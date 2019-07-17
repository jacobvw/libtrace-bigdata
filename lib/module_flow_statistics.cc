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

struct module_flow_statistics_ip_compare {
    bool operator()(const sockaddr_storage& x, const sockaddr_storage& y) const {
        if (x.ss_family != y.ss_family) {
            return 1;
        }

        if (x.ss_family == AF_INET) {
            struct sockaddr_in *xx = (struct sockaddr_in *)&x;
            struct sockaddr_in *yy = (struct sockaddr_in *)&y;
            return xx->sin_addr.s_addr < yy->sin_addr.s_addr;
        }

        if (x.ss_family == AF_INET6) {
            struct sockaddr_in6 *xx = (struct sockaddr_in6 *)&x;
            struct sockaddr_in6 *yy = (struct sockaddr_in6 *)&y;
            for (int i = 0; i < 16; i++) {
                if (xx->sin6_addr.s6_addr[i] != yy->sin6_addr.s6_addr[i]) {
                    return xx->sin6_addr.s6_addr[i] < yy->sin6_addr.s6_addr[i];
                }
            }
            // ips must match
            return 0;
        }
    }
};

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

    std::set<struct sockaddr_storage, module_flow_statistics_ip_compare> *src_ips;
    std::set<struct sockaddr_storage, module_flow_statistics_ip_compare> *dst_ips;

    std::set<struct sockaddr_storage, module_flow_statistics_ip_compare> *local_ips;
    std::set<struct sockaddr_storage, module_flow_statistics_ip_compare> *remote_ips;

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
        proto->src_ips = new std::set<struct sockaddr_storage, module_flow_statistics_ip_compare>;
        proto->dst_ips = new std::set<struct sockaddr_storage, module_flow_statistics_ip_compare>;
        proto->local_ips = new std::set<struct sockaddr_storage, module_flow_statistics_ip_compare>;
        proto->remote_ips = new std::set<struct sockaddr_storage, module_flow_statistics_ip_compare>;
        proto->flow_ids = new std::set<uint64_t>;

        stats->proto_stats->insert({flow_rec->lpi_module->protocol, proto});
    } else {
        proto = (mod_flow_stats_proto_t *)search->second;
    }

    // if the protocol has changed for this flow
    if (proto->module->protocol != flow_rec->lpi_module->protocol) {
        // search for the old protocol
        auto search_old = stats->proto_stats->find(proto->module->protocol);
        if (search_old == stats->proto_stats->end()) {
            // protocol not found. this should not happen
        } else {
            // get the old protocol
            mod_flow_stats_proto_t *proto_old = (mod_flow_stats_proto_t *)
                search_old->second;;
            // remove counters from the previous protocol
            proto_old->in_bytes -= bd_flow_get_in_bytes(flow);
            proto_old->out_bytes -= bd_flow_get_out_bytes(flow);
            proto_old->in_packets -= bd_flow_get_in_packets(flow);
            proto_old->out_packets -= bd_flow_get_out_packets(flow);
            // need a way to remove ip sets from old protocol but only if it only
            // occurred for a single flow. Could iterate over flow_ids somehow?
        }

        // add counters to the newly identified protocol
        proto->in_bytes += bd_flow_get_in_bytes(flow);
        proto->out_bytes += bd_flow_get_out_bytes(flow);
        proto->in_packets += bd_flow_get_in_packets(flow);
        proto->out_packets += bd_flow_get_out_packets(flow);
        // note: this iteration should add src/dst ips to the set
        proto->module = flow_rec->lpi_module;
    }

    // dir = 1 is inbound packets
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
            // insert into source and destination ips into the set
            proto->src_ips->insert(src_addr);
            proto->dst_ips->insert(dst_addr);
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
        it=stats->proto_stats->begin(); it != stats->proto_stats->end(); ++it) {

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

        /*std::set<struct sockaddr_storage>::iterator ite;
        for (ite=proto->src_ips->begin(); ite != proto->src_ips->end(); ++ite) {

            struct sockaddr_storage tt = *ite;
            if (tt.ss_family == AF_INET) {
                  struct sockaddr_in *ttt = (struct sockaddr_in *)&tt;
                  char asd[INET_ADDRSTRLEN];
                  inet_ntop(AF_INET, &(ttt->sin_addr), asd, INET_ADDRSTRLEN);
                  fprintf(stderr, "src ip address %s\n", asd);
            }
            if (tt.ss_family == AF_INET6) {
                  struct sockaddr_in6 *ttt = (struct sockaddr_in6 *)&tt;
                  char asd[INET6_ADDRSTRLEN];
                  inet_ntop(AF_INET6, &(ttt->sin6_addr), asd, INET6_ADDRSTRLEN);
                  fprintf(stderr, "src ip address %s\n", asd);
            }
        }

        for (ite=proto->dst_ips->begin(); ite != proto->dst_ips->end(); ++ite) {

            struct sockaddr_storage tt = *ite;
            if (tt.ss_family == AF_INET) {
                  struct sockaddr_in *ttt = (struct sockaddr_in *)&tt;
                  char asd[INET_ADDRSTRLEN];
                  inet_ntop(AF_INET, &(ttt->sin_addr), asd, INET_ADDRSTRLEN);
                  fprintf(stderr, "dst ip address %s\n", asd);
            }
            if (tt.ss_family == AF_INET6) {
                  struct sockaddr_in6 *ttt = (struct sockaddr_in6 *)&tt;
                  char asd[INET6_ADDRSTRLEN];
                  inet_ntop(AF_INET6, &(ttt->sin6_addr), asd, INET6_ADDRSTRLEN);
                  fprintf(stderr, "dst ip address %s\n", asd);
            }
        }*/

        if (config->flow_count) {
            bd_result_set_insert_uint(result_set, "unique_flows", proto->flow_ids->size());
        }

        // set the timestamp for the result
        bd_result_set_insert_timestamp(result_set, tick);
        // add interval
        bd_result_set_insert_int(result_set, "interval", config->output_interval);

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

inline bool operator<(struct sockaddr_storage &lh, struct sockaddr_storage &rh) {

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
                    if (config->output_interval != 0) {
                        bd_add_tickrate_to_cb_set(config->callbacks, config->output_interval);
                    } else {
                        fprintf(stderr, "Invalid output_interval value. "
                            "module_flow_statistics. Disabling module\n");
                        config->enabled = 0;
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
        config->callbacks->start_cb = (cb_start)module_flow_statistics_starting;
        config->callbacks->packet_cb = (cb_packet)module_flow_statistics_packet;
        config->callbacks->stop_cb = (cb_stop)module_flow_statistics_stopping;
        config->callbacks->tick_cb = (cb_tick)module_flow_statistics_tick;
    }

    return 0;
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
    config->output_interval = 60;
    config->byte_count = 0;
    config->packet_count = 0;
    config->flow_count = 0;

    config->callbacks = bd_create_cb_set("flow_statistics");
    config->callbacks->config_cb = (cb_config)module_flow_statistics_config;
    bd_register_cb_set(config->callbacks);

    return 0;
}
