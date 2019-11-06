#include "module_dns.h"

#include <unordered_map>
#include <string>
#include "module_dns_spcdns.h"
#include "module_dns_spcdns_mappings.h"

struct module_dns_conf {
    bd_cb_set *callbacks;
    int timeout_request;
    int timeout_check;
    bool enabled;
};
static struct module_dns_conf *config;

struct module_dns_req {
    double start_ts;
    double end_ts;
    char *src_ip;
    char *dst_ip;
};
struct module_dns_local {
    std::unordered_map<uint16_t, struct module_dns_req *> *reqs;
};

int module_dns_answer_to_result_set(bd_result_set_t *result_set, dns_answer_t *ans,
    const char *type, int num);
void *module_dns_starting(void *tls);
int module_dns_packet(libtrace_t *trace, libtrace_thread_t *thread,
    Flow *flow, libtrace_packet_t *packet, void *tls, void *mls);
int module_dns_ending(void *tls, void *mls);

void *module_dns_starting(void *tls) {

    // create module storage
    struct module_dns_local *storage = (struct module_dns_local *)
        malloc(sizeof(struct module_dns_local));
    if (storage == NULL) {
        fprintf(stderr, "Unable to allocate memory for module_dns storage\n");
        return NULL;
    }
    // create request map
    storage->reqs = new std::unordered_map<uint16_t, struct module_dns_req *>;

    return storage;
}

int module_dns_packet(bd_bigdata_t *bigdata, void *mls) {

    libtrace_t *trace = bigdata->trace;
    libtrace_thread_t *thread = bigdata->thread;
    libtrace_packet_t *packet = bigdata->packet;
    Flow *flow = bigdata->flow;
    void *tls = bigdata->tls;

    // Gain access to module local storage and thread local storage
    struct module_dns_local *m_local = (struct module_dns_local *)mls;
    bd_thread_local_t *t_local = (bd_thread_local_t *)tls;

    libtrace_udp_t *udp;
    libtrace_tcp_t *tcp;
    bool is_udp;
    uint32_t remaining;
    uint16_t ethertype;
    void *payload;
    int i;
    char buf[30];

    payload = trace_get_layer3(packet, &ethertype, &remaining);

    // no layer3 header
    if (payload == NULL) { return 1; }
    // no remaining packet
    if (remaining == 0) { return 1; }

    if ((udp = trace_get_udp(packet)) == NULL) {
        if ((tcp = trace_get_tcp(packet)) == NULL) {
            return 1;
        }
        is_udp = 0;
        payload = trace_get_payload_from_tcp(tcp, &remaining);
    } else {
        is_udp = 1;
        payload = trace_get_payload_from_udp(udp, &remaining);
    }
    // no payload
    if (payload == NULL) { return -1; }

    // decode the dns packet
    dns_decoded_t bufresult[DNS_DECODEBUF_8K];
    size_t bufsize = sizeof(bufresult);
    int ret;
    ret = dns_decode(bufresult, &bufsize, (dns_packet_t *)payload, remaining);
    if (ret != RCODE_OKAY) {
        return 1;
    }

    // get the identifier for this packet
    uint16_t identifier = (uint16_t)*bufresult;

    std::unordered_map<uint16_t, struct module_dns_req *> *map = m_local->reqs;
    auto search = map->find(identifier);

    // check if the identifier is in the hashmap
    if (search == map->end()) {
        dns_query_t *req = (dns_query_t *)bufresult;

        // Ensure the request is a query before inserting into the map
        if (req->query) {

            // create request structure
            struct module_dns_req *req_stor = (struct module_dns_req *)malloc(
                sizeof(struct module_dns_req));
            if (req_stor == NULL) {
                fprintf(stderr, "Unable to allocate memory\n");
                return 1;
            }
            req_stor->start_ts = trace_get_seconds(packet);

            /*if (DEBUG) {
                fprintf(stderr, "got query %s thread id %lu\n",
                    dns_type_text(req->questions[0].type), pthread_self());
            }*/

            // insert request into the map
            map->insert({identifier, req_stor});
        } else {
            /*if (DEBUG) {
                // is a result without query
                fprintf(stderr, "Got response with no corresponding query type %s thread %lu\n",
                dns_type_text(req->questions[0].type), pthread_self());
            }*/
        }

    } else {

        // retrieve the original request
        struct module_dns_req *req = (struct module_dns_req *)search->second;

        // finish populating the result structure
        req->end_ts = trace_get_seconds(packet);

        // retrieve the response
        dns_query_t *resp = (dns_query_t *)bufresult;

        req->src_ip = (char *)malloc(INET6_ADDRSTRLEN);
        req->dst_ip = (char *)malloc(INET6_ADDRSTRLEN);
        if (req->src_ip == NULL || req->dst_ip == NULL) {
            fprintf(stderr, "Unable to allocate memory. func. module_dns_packet()\n");
            return 1;
        }
        req->src_ip = trace_get_source_address_string(packet, req->src_ip,
            INET6_ADDRSTRLEN);
        req->dst_ip = trace_get_destination_address_string(packet, req->dst_ip,
            INET6_ADDRSTRLEN);

        // create the result set
        bd_result_set_t *result_set = bd_result_set_create("dns");

        /* flip source/dst IPs because this is the response packet, want them to match
         * the request packet */
        bd_result_set_insert_string(result_set, "src_ip", req->dst_ip);
        bd_result_set_insert_string(result_set, "dst_ip", req->src_ip);
        bd_result_set_insert_tag(result_set, "protocol", is_udp ? "udp" : "tcp");

        bd_result_set_insert_uint(result_set, "question_count", (uint64_t)resp->qdcount);
        bd_result_set_insert_uint(result_set, "answer_count", (uint64_t)resp->ancount);
        bd_result_set_insert_uint(result_set, "nameserver_count", (uint64_t)resp->nscount);
        bd_result_set_insert_uint(result_set, "additional_count", (uint64_t)resp->arcount);
        bd_result_set_insert_double(result_set, "rtt", req->end_ts - req->start_ts);

        // add tags
        bd_result_set_insert_tag(result_set, "authoritive_result", resp->aa ? "true" : "false");
        bd_result_set_insert_tag(result_set, "truncated_result", resp->tc ? "true" : "false");
        bd_result_set_insert_tag(result_set, "recursion_desired", resp->rd ? "true" : "false");
        bd_result_set_insert_tag(result_set, "recursion_available", resp->ra ? "true" : "false");
        snprintf(buf, sizeof(buf), "%d", resp->rcode);
        bd_result_set_insert_tag(result_set, "response_code", buf);
        snprintf(buf, sizeof(buf), "%d", resp->opcode);
        bd_result_set_insert_tag(result_set, "opcode", buf);

        // for each question
        for (i=0; i<resp->qdcount; i++) {
            snprintf(buf, sizeof(buf), "%s%d", "question", i);
            bd_result_set_insert_string(result_set, buf, resp->questions[i].name);

            snprintf(buf, sizeof(buf), "%s%d%s", "question", i, "_type");
            bd_result_set_insert_tag(result_set, buf,
                dns_type_text(resp->questions[i].type));
        }

        // for each answer
        for (i=0; i<resp->ancount; i++) {
            module_dns_answer_to_result_set(result_set, &resp->answers[i], "answer", i);
        }
        // for each nameserver
        for (i=0; i<resp->nscount; i++) {
            module_dns_answer_to_result_set(result_set, &resp->nameservers[i], "nameserver", i);
        }
        // for each additional
        for (i=0; i<resp->arcount; i++) {
            module_dns_answer_to_result_set(result_set, &resp->additional[i], "additional", i);
        }

        // set the timestamp for the result
        struct timeval tv = trace_get_timeval(packet);
        bd_result_set_insert_timestamp(result_set, tv.tv_sec);

        // send resultset to reporter thread
        bd_result_set_publish(bigdata, result_set, tv.tv_sec);

        // remove request from map and free memory for request and response
        map->erase(identifier);
        free(req->src_ip);
        free(req->dst_ip);
        free(req);

    }

    return 0;
}

// Used to remove timed out requests that not have received a response packet from
// the map of requests
int module_dns_tick(bd_bigdata_t *bigdata, void *mls, uint64_t tick) {

    libtrace_t *trace = bigdata->trace;
    libtrace_thread_t *thread = bigdata->thread;
    void *tls = bigdata->tls;

    // Gain access to module local storage and thread local storage
    struct module_dns_local *m_local = (struct module_dns_local *)mls;

    // Gain access to the map
    std::unordered_map<uint16_t, struct module_dns_req *> *map = m_local->reqs;

    // create iterator
    std::unordered_map<uint16_t, struct module_dns_req *>::iterator itr = map->begin();
    for (itr = map->begin(); itr != map->end(); ) {
        struct module_dns_req *cur = (struct module_dns_req *)itr->second;

        // remove from hashmap if timeout has been reached
        if (tick >= (cur->start_ts + config->timeout_request)) {
            map->erase(itr++);
            // should not be allocated for only a request so should not need to free
            // keeping here to make it clear
            //free(cur->src_ip);
            //free(cur->dst_ip);
            free(cur);
        // else move on to next element
        } else {
            ++itr;
        }
    }
}

int module_dns_ending(void *tls, void *mls) {
    module_dns_local *storage = (module_dns_local *)mls;

    return 0;
}

int module_dns_answer_to_result_set(bd_result_set_t *result_set, dns_answer_t *ans,
    const char *type, int num) {

    char buf[100];
    char buf2[30];
    char buf3[30];

    snprintf(buf2, sizeof(buf2), "%s%d", type, num);
    snprintf(buf3, sizeof(buf3), "%s%d%s", type, num, "_type");

    switch(ans->generic.type) {
        case RR_NS:
            bd_result_set_insert_string(result_set, buf2, ans->ns.nsdname);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->ns.type));
            break;
        case RR_A:
            inet_ntop(AF_INET, &ans->a.address, buf, sizeof(buf));
            bd_result_set_insert_string(result_set, buf2, buf);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->a.type));
            break;
        case RR_AAAA:
            inet_ntop(AF_INET6, &ans->aaaa.address, buf, sizeof(buf));
            bd_result_set_insert_string(result_set, buf2, buf);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->aaaa.type));
            break;
        case RR_CNAME:
            bd_result_set_insert_string(result_set, buf2, ans->cname.cname);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->cname.type));
            break;
        case RR_MX:
            snprintf(buf, sizeof(buf), "%d %s",
                ans->mx.preference,
                ans->mx.exchange);
            bd_result_set_insert_string(result_set, buf2, buf);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->mx.type));
            break;
        case RR_PTR:
            bd_result_set_insert_string(result_set, buf2, ans->ptr.ptr);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->ptr.type));
            break;
        case RR_HINFO:
            snprintf(buf, sizeof(buf), "%s %s",
                ans->hinfo.cpu,
                ans->hinfo.os);
            bd_result_set_insert_string(result_set, buf2, buf);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->hinfo.type));
            break;
        case RR_MINFO:
            snprintf(buf, sizeof(buf), "%s %s",
                ans->minfo.rmailbx,
                ans->minfo.emailbx);
            bd_result_set_insert_string(result_set, buf2, buf);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->minfo.type));
            break;
        case RR_SPF:
        case RR_TXT:
            bd_result_set_insert_string(result_set, buf2, ans->txt.text);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->txt.type));
            break;
        case RR_SOA:
            snprintf(buf, sizeof(buf), "%u %u %u %u %u",
                ans->soa.serial,
                ans->soa.refresh,
                ans->soa.retry,
                ans->soa.expire,
                ans->soa.minimum);
            bd_result_set_insert_string(result_set, buf2, buf);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->soa.type));
            break;
        case RR_LOC:
            break;
        case RR_SRV:
            snprintf(buf, sizeof(buf), "%5d %5d %5d %s",
                ans->srv.priority,
                ans->srv.weight,
                ans->srv.port,
                ans->srv.target);
            bd_result_set_insert_string(result_set, buf2, buf);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->srv.type));
            break;
        case RR_OPT:
            snprintf(buf, sizeof(buf), "%lu %s %lu",
                (unsigned long)ans->opt.udp_payload,
                ans->opt.fdo ? "true" : "false",
                (unsigned long)ans->opt.numopts);
            bd_result_set_insert_string(result_set, buf2, buf);
            bd_result_set_insert_tag(result_set, buf3, dns_type_text(ans->opt.type));
            break;
        default:
            break;
    }
}

int module_dns_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {
    int enter_level = *level;
    bool first_pass = 1;

    while (enter_level != *level || first_pass) {
        first_pass = 0;
        switch(event->type) {
            case YAML_SCALAR_EVENT:
                if (strcmp((char *)event->data.scalar.value, "enabled") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "t") == 0) {

                        config->enabled = 1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "timeout_request") == 0) {
                    consume_event(parser, event, level);
                    config->timeout_request = atoi((char *)event->data.scalar.value);
                    if (config->timeout_request == 0) {
                        fprintf(stderr, "Invalid timeout_request value. "
                            "module_dns. setting to default 20 seconds\n");
                        config->timeout_request = 20;
                    }
                }
                if (strcmp((char *)event->data.scalar.value, "timeout_check") == 0) {
                    consume_event(parser, event, level);
                    config->timeout_check = atoi((char *)event->data.scalar.value);
                    if (config->timeout_check == 0) {
                        fprintf(stderr, "Invalid timeout_check value. "
                            "module_dns. setting to default 20 seconds\n");
                        config->timeout_check = 20;
                    }
                }
            default:
                consume_event(parser, event, level);
                break;
        }
    }

    if (config->enabled) {
        config->callbacks->config_cb = (cb_config)module_dns_config;
        config->callbacks->start_cb = (cb_start)module_dns_starting;
        config->callbacks->packet_cb = (cb_packet)module_dns_packet;

        // set tick event to check for timed out requests
        config->callbacks->tick_cb = (cb_tick)module_dns_tick;
        // set timeout check interval
        bd_add_tickrate_to_cb_set(config->callbacks, config->timeout_check);

        config->callbacks->stop_cb = (cb_stop)module_dns_ending;
        bd_add_filter_to_cb_set(config->callbacks, "port 53");

        fprintf(stdout, "DNS Plugin Enabled\n");
    }
}

int module_dns_init(bd_bigdata_t *bigdata) {
    // allocate memory for config structure
    config = (struct module_dns_conf *)malloc(
        sizeof(struct module_dns_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_dns_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    // initialise the config structure
    config->enabled = 0;

    config->timeout_request = 20;
    config->timeout_check = 20;

    config->callbacks = bd_create_cb_set("dns");
    config->callbacks->config_cb = (cb_config)module_dns_config;

    /* register the callback set */
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}

