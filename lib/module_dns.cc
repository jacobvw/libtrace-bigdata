#include <unordered_map>
#include <string>
#include "module_dns_spcdns.h"

struct module_dns_req {
    double start_ts;
    double end_ts;
    char *src_ip;
    char *dst_ip;
};
struct module_dns_local {
    std::unordered_map<uint16_t, struct module_dns_req *> *reqs;
};

bd_result_set module_dns_create_bd_result() {

}

int module_dns_free_bd_result(bd_result_set_t *result) {

}

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

int module_dns_packet(libtrace_t *trace, libtrace_packet_t *packet, Flow *flow, void *tls, void *mls) {

    // Gain access to module local storage and thread local storage
    struct module_dns_local *m_local = (struct module_dns_local *)mls;
    bd_thread_local_t *t_local = (bd_thread_local_t *)tls;

    libtrace_udp_t *udp;
    libtrace_tcp_t *tcp;
    uint32_t remaining;
    uint16_t ethertype;
    void *payload;

    payload = trace_get_layer3(packet, &ethertype, &remaining);

    // no layer3 header
    if (payload == NULL) { return 1; }
    // no remaining packet
    if (remaining == 0) { return 1; }

    if ((udp = trace_get_udp(packet)) == NULL) {
        if ((tcp = trace_get_tcp(packet)) == NULL) {
            return 1;
        }
        payload = trace_get_payload_from_tcp(tcp, &remaining);
    } else {
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

            // insert request into the map
            map->insert({identifier, req_stor});
        }
    } else {

        // retrieve the original request
        struct module_dns_req *req = (struct module_dns_req *)search->second;
        // retrieve the response
        dns_query_t *resp = (dns_query_t *)bufresult;

        dns_question_t *question = (dns_question_t *)resp->questions;
        dns_answer_t *ans = (dns_answer_t *)resp->answers;
        dns_answer_t *ns = (dns_answer_t *)resp->nameservers;
        dns_answer_t *addi = (dns_answer_t *)resp->additional;

        // finish populating the result structure
        req->end_ts = trace_get_seconds(packet);
        req->src_ip = (char *)malloc(sizeof(INET6_ADDRSTRLEN));
        req->dst_ip = (char *)malloc(sizeof(INET6_ADDRSTRLEN));
        if (req->src_ip == NULL || req->dst_ip == NULL) {
            fprintf(stderr, "Unable to allocate memory. func. module_dns_packet()\n");
            return 1;
        }
        req->src_ip = trace_get_source_address_string(packet, req->src_ip, INET6_ADDRSTRLEN);
        req->dst_ip = trace_get_destination_address_string(packet, req->dst_ip, INET6_ADDRSTRLEN);


        // output the result -- need to make generic record format??
        // create result set
        bd_result_set_t *result_set = bd_result_set_create("dns");
        bd_result_set_insert_string(result_set, "test", "data");

        bd_result_set_output(result_set);
        bd_result_set_free(result_set);
        fprintf(stderr, "print dns result\n");

        // remove request from map and free memory for request and response
        map->erase(identifier);
        free(req);

        // remove requests that have not received a response??
    }

    return 0;
}

int module_dns_ending(void *tls, void *mls) {
    module_dns_local *storage = (module_dns_local *)mls;

    return 0;
}

int module_dns_init() {

    bd_cb_set *callbacks = bd_create_cb_set();

    callbacks->start_cb = (cb_start)module_dns_starting;
    callbacks->packet_cb = (cb_packet)module_dns_packet;
    callbacks->stop_cb = (cb_stop)module_dns_ending;

    bd_add_filter_to_cb_set(callbacks, "port 53");

    bd_register_cb_set(callbacks);

    return 0;
}
