#include "module_flow_statistics.h"
#include "bigdata.h"
#include <unordered_map>
#include <set>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

struct module_flow_statistics_conf {
    bd_cb_set *callbacks;
    bool enabled;
    int output_interval;
    bool byte_count;
    bool packet_count;
    bool flow_count;
    bool ip_count;
};
static struct module_flow_statistics_conf *config;

typedef struct module_flow_statistics_proto mod_flow_stats_proto_t;

typedef struct module_flow_statistics {
    // map containing stats for each flow
    std::unordered_map<lpi_protocol_t, mod_flow_stats_proto_t *> *proto_stats;
} mod_flow_stats_t;

typedef struct module_flow_statistics_proto {
    lpi_module *module;

    // byte_counters
    uint64_t in_bytes;
    uint64_t out_bytes;

    // packet_counters
    uint64_t in_packets;
    uint64_t out_packets;

    std::set<uint32_t> *src_ips;
    std::set<uint32_t> *dst_ips;

    std::set<uint32_t> *local_ips;
    std::set<uint32_t> *remote_ips;

    // keep track of all the flow ids - used as a way to count number of flows
    std::set<uint64_t> *flow_ids;
} mod_flow_stats_proto_t;

int mod_statistics_is_local_ip(uint32_t address) {
    //bd_get_local_ips();
    return 0;
}

void *module_flow_statistics_starting(void *tls) {
    /* Allocate memory for module storage */
    mod_flow_stats_t *stats = (mod_flow_stats_t *)malloc(sizeof(mod_flow_stats_t));
    if (stats == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_flow_statistics_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    // create protocol list
    stats->proto_stats = new std::unordered_map<lpi_protocol_t, mod_flow_stats_proto_t *>;

    return stats;
}

int module_flow_statistics_packet(libtrace_t *trace, libtrace_thread_t *thread,
    Flow *flow, libtrace_packet_t *packet, void *tls, void *mls) {

    // get the module local storage
    mod_flow_stats_t *stats = (mod_flow_stats_t *)mls;
    // get the flow record
    bd_flow_record_t *flow_rec = (bd_flow_record_t *)flow->extension;
    // get packet direction
    int dir = bd_get_packet_direction(packet);
    struct sockaddr_storage src_addr, dst_addr;
    struct sockaddr *src_ip, *dst_ip;

    // search proto_stats map for this protocol
    auto search = stats->proto_stats->find(flow_rec->lpi_module->protocol);
    mod_flow_stats_proto_t *proto;

    // If protocol was not found create it and insert it
    if (search == stats->proto_stats->end()) {
        proto = (mod_flow_stats_proto_t *)
            malloc(sizeof(mod_flow_stats_proto_t));
        if (proto == NULL) {
            fprintf(stderr, "Unable to allocate memory. func. "
                "module_flow_statistics_packet()\n");
            exit(BD_OUTOFMEMORY);
        }

        // initialise the new module
        proto->module = flow_rec->lpi_module;
        proto->in_bytes = 0;
        proto->out_bytes = 0;
        proto->in_packets = 0;
        proto->out_packets = 0;
        proto->src_ips = new std::set<uint32_t>;
        proto->dst_ips = new std::set<uint32_t>;
        proto->local_ips = new std::set<uint32_t>;
        proto->remote_ips = new std::set<uint32_t>;
        proto->flow_ids = new std::set<uint64_t>;

        stats->proto_stats->insert({flow_rec->lpi_module->protocol, proto});
    } else {
        proto = (mod_flow_stats_proto_t *)search->second;
    }

    // if the protocol has changed for this flow
    if (proto->module != flow_rec->lpi_module) {
        // find a way to move recorded stats over to correct proto??
        proto->module = flow_rec->lpi_module;
    }

    // update counters for the protocol
    if (dir) {
        if (config->byte_count) { proto->in_bytes += trace_get_payload_length(packet); }
        if (config->packet_count) { proto->in_packets += 1; }
    } else {
        if (config->byte_count) { proto->out_bytes += trace_get_payload_length(packet); }
        if (config->packet_count) { proto->out_packets += 1; }
    }

    if (config->ip_count) {
        src_ip = trace_get_source_address(packet, (struct sockaddr *)&src_addr);
        dst_ip = trace_get_destination_address(packet, (struct sockaddr *)&dst_addr);
        if (src_ip != NULL && dst_ip != NULL) {
            // IPv4
            if (src_ip->sa_family == AF_INET && dst_ip->sa_family == AF_INET) {
                // get source ip address
                struct sockaddr_in *v4 = (struct sockaddr_in *)src_ip;
                struct in_addr ipv4 = (struct in_addr)v4->sin_addr;
                uint32_t address = htonl(ipv4.s_addr);
                // insert into source ip set
                proto->src_ips->insert(address);
                // check if the ip is local or remote
                if (mod_statistics_is_local_ip(address)) {
                    proto->local_ips->insert(address);
                } else {
                    proto->remote_ips->insert(address);
                }

                // get destination ip address
                v4 = (struct sockaddr_in *)dst_ip;
                ipv4 = (struct in_addr)v4->sin_addr;
                address = htonl(ipv4.s_addr);
                // insert into destination ip list
                proto->dst_ips->insert(address);
                // check if the ip is local or remote
                if (mod_statistics_is_local_ip(address)) {
                    proto->local_ips->insert(address);
                } else {
                    proto->remote_ips->insert(address);
                }
            }
            // IPv6. TODO
            if (src_ip->sa_family == AF_INET6 && dst_ip->sa_family == AF_INET6) {
                struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)src_ip;
                struct in6_addr ipv6 = (struct in6_addr)v6->sin6_addr;
                //unsigned char address[16] = ipv6.s6_addr;

                // insert into set

                v6 = (struct sockaddr_in6 *)dst_ip;
                ipv6 = (struct in6_addr)v6->sin6_addr;
                //address[16] = ipv6.s6_addr;

                // insert into set
            }
        }
    }

    // insert the flow id
    if (config->flow_count) { proto->flow_ids->insert(flow->id.get_id_num()); }
}

int module_flow_statistics_stopping(void *tls, void *mls) {
    mod_flow_stats_t *stats = (mod_flow_stats_t *)mls;

    // free allocated structures within the map
    for (std::unordered_map<lpi_protocol_t, mod_flow_stats_proto_t *>::iterator
        it=stats->proto_stats->begin(); it!=stats->proto_stats->end(); ++it) {

        mod_flow_stats_proto_t *proto = (mod_flow_stats_proto_t *)it->second;

        delete(proto->src_ips);
        delete(proto->dst_ips);
        delete(proto->local_ips);
        delete(proto->remote_ips);
        delete(proto->flow_ids);
        free(proto);
    }

    // delete the map
    delete(stats->proto_stats);

    /* release stats memory */
    free(stats);
}

int module_flow_statistics_tick(libtrace_t *trace, libtrace_thread_t *thread,
    void *tls, void *mls, uint64_t tick) {

    // gain access to the stats
    mod_flow_stats_t *stats = (mod_flow_stats_t *)mls;

    // output protocol counters
    for (std::unordered_map<lpi_protocol_t, mod_flow_stats_proto_t *>::iterator
        it=stats->proto_stats->begin(); it!=stats->proto_stats->end(); ++it) {

        mod_flow_stats_proto_t *proto = (mod_flow_stats_proto_t *)it->second;

        bd_result_set_t *result_set = bd_result_set_create("flow_stats");
        bd_result_set_insert_tag(result_set, "protocol", proto->module->name);

        if (config->packet_count) {
            bd_result_set_insert_uint(result_set, "in_packets", proto->in_packets);
            bd_result_set_insert_uint(result_set, "out_packets", proto->out_packets);
        }

        if (config->byte_count) {
            bd_result_set_insert_uint(result_set, "in_bytes", proto->in_bytes);
            bd_result_set_insert_uint(result_set, "out_bytes", proto->out_bytes);
        }
        if (config->ip_count) {
            bd_result_set_insert_uint(result_set, "unique_src_ips", proto->src_ips->size());
            bd_result_set_insert_uint(result_set, "unique_dst_ips", proto->dst_ips->size());
        }
        /*std::set<uint32_t>::iterator ite;
        for (ite=proto->src_ips->begin(); ite != proto->src_ips->end(); ++ite) {
            fprintf(stderr, "\tsrc ip: %d.%d.%d.%d\n", (*ite & 0xff000000) >> 24,
                                                       (*ite & 0x00ff0000) >> 16,
                                                       (*ite & 0x0000ff00) >> 8,
                                                       (*ite & 0x000000ff));
        }
        for (ite=proto->dst_ips->begin(); ite != proto->dst_ips->end(); ++ite) {
            fprintf(stderr, "\tdst ip: %d.%d.%d.%d\n", (*ite & 0xff000000) >> 24,
                                                       (*ite & 0x00ff0000) >> 16,
                                                       (*ite & 0x0000ff00) >> 8,
                                                       (*ite & 0x000000ff));
        }*/
        if (config->flow_count) {
            bd_result_set_insert_uint(result_set, "unique_flows", proto->flow_ids->size());
        }

        // publish the result
        bd_result_set_publish(trace, thread, result_set);

        delete(proto->src_ips);
        delete(proto->dst_ips);
        delete(proto->local_ips);
        delete(proto->remote_ips);
        delete(proto->flow_ids);
        free(proto);
    }

    // clear the protocol list
    stats->proto_stats->clear();
}

int module_flow_statistics_combiner(bd_result_t *result) {

}

int module_flow_statistics_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {
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
                if (strcmp((char *)event->data.scalar.value, "output_interval") == 0) {
                    consume_event(parser, event, level);
                    config->output_interval = atoi((char *)event->data.scalar.value);
                    // atoi returns 0 on error so ensure return value was not 0
                    if (config->output_interval != 0 &&
                            (config->output_interval % BIGDATA_TICKRATE) == 0) {

                        bd_add_tickrate_to_cb_set(config->callbacks, config->output_interval);
                    } else {
                        fprintf(stderr, "Invalid output_interval, must be devisible by 1000. "
                            "module flow_statistics\n");
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "byte_count") == 0) {
                    consume_event(parser, event, level);
                    config->byte_count = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "packet_count") == 0) {
                    consume_event(parser, event, level);
                    config->packet_count = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "flow_count") == 0) {
                    consume_event(parser, event, level);
                    config->flow_count = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "ip_count") == 0) {
                    consume_event(parser, event, level);
                    config->ip_count = 1;
                    break;
                }
            default:
                consume_event(parser, event, level);
                break;

        }
    }

    if (config->enabled) {
        fprintf(stderr, "enabling\n");
        config->callbacks->start_cb = (cb_start)module_flow_statistics_starting;
        config->callbacks->packet_cb = (cb_packet)module_flow_statistics_packet;
        config->callbacks->stop_cb = (cb_stop)module_flow_statistics_stopping;
        config->callbacks->tick_cb = (cb_tick)module_flow_statistics_tick;
    }
}

int module_flow_statistics_init() {
    // allocate memory for config structure
    config = (struct module_flow_statistics_conf *)malloc(
        sizeof(struct module_flow_statistics_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_flow_statistics_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    // initialise the config structure
    config->enabled = 0;
    config->output_interval = 10000;
    config->byte_count = 0;
    config->packet_count = 0;
    config->flow_count = 0;

    config->callbacks = bd_create_cb_set("flow_statistics");

    config->callbacks->config_cb = (cb_config)module_flow_statistics_config;

    bd_register_cb_set(config->callbacks);

    return 0;
}
