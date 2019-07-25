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
    bool output_all_protocols;
    bool byte_count;
    bool packet_count;
    bool flow_count;
    bool ip_count;
};
static struct module_flow_statistics_conf *config;

// comparator for set of ips
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

typedef struct module_flow_statistics_proto {
    // byte_counters
    uint64_t in_bytes;
    uint64_t out_bytes;

    // packet_counters
    uint64_t in_packets;
    uint64_t out_packets;

    // external ip sets
    std::set<struct sockaddr_storage, module_flow_statistics_ip_compare> *esrc_ips;
    std::set<struct sockaddr_storage, module_flow_statistics_ip_compare> *edst_ips;
    // internal ip sets
    std::set<struct sockaddr_storage, module_flow_statistics_ip_compare> *isrc_ips;
    std::set<struct sockaddr_storage, module_flow_statistics_ip_compare> *idst_ips;

    // keep track of all the flow ids - used as a way to count number of flows
    std::set<uint64_t> *flow_ids;
} mod_flow_stats_proto_t;

typedef struct module_flow_statistics {
    mod_flow_stats_proto_t proto_stats[LPI_PROTO_LAST];
    uint64_t lastkey;
} mod_flow_stats_t;

static void module_flow_statistics_init_proto_stats(mod_flow_stats_proto_t *proto) {

    // initialise the new protocol
    proto->in_bytes = 0;
    proto->out_bytes = 0;
    proto->in_packets = 0;
    proto->out_packets = 0;
    proto->esrc_ips = new std::set<struct sockaddr_storage,
        module_flow_statistics_ip_compare>;
    proto->edst_ips = new std::set<struct sockaddr_storage,
        module_flow_statistics_ip_compare>;
    proto->isrc_ips = new std::set<struct sockaddr_storage,
        module_flow_statistics_ip_compare>;
    proto->idst_ips = new std::set<struct sockaddr_storage,
        module_flow_statistics_ip_compare>;
    proto->flow_ids = new std::set<uint64_t>;
}

static void module_flow_statistics_clear_proto_stats(mod_flow_stats_proto_t *proto) {
    proto->in_bytes = 0;
    proto->out_bytes = 0;
    proto->in_packets = 0;
    proto->out_packets = 0;
    proto->esrc_ips->clear();
    proto->edst_ips->clear();
    proto->isrc_ips->clear();
    proto->idst_ips->clear();
    proto->flow_ids->clear();
}

static void module_flow_statistics_delete_proto_stats(mod_flow_stats_proto_t *proto) {
    delete(proto->esrc_ips);
    delete(proto->edst_ips);
    delete(proto->isrc_ips);
    delete(proto->idst_ips);
    delete(proto->flow_ids);
}

void *module_flow_statistics_starting(void *tls) {
    /* Allocate memory for module storage */
    mod_flow_stats_t *stats = (mod_flow_stats_t *)malloc(sizeof(mod_flow_stats_t));
    if (stats == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_flow_statistics_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    // init proto stats
    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        module_flow_statistics_init_proto_stats(&(stats->proto_stats[i]));
    }

    return stats;
}

int module_flow_statistics_packet(libtrace_t *trace, libtrace_thread_t *thread,
    Flow *flow, libtrace_packet_t *packet, void *tls, void *mls) {

    // get the module local storage
    mod_flow_stats_t *stats = (mod_flow_stats_t *)mls;
    // get the flow record
    bd_flow_record_t *flow_rec = (bd_flow_record_t *)flow->extension;

    // get the flow direction and current direction
    int flow_dir = bd_flow_get_direction(flow);
    int dir = bd_get_packet_direction(packet);

    // get pointer to protocol for this packet
    mod_flow_stats_proto_t *proto = &(stats->proto_stats[flow_rec->lpi_module->protocol]);

    // dir = 1 is inbound packets
    if (dir) {
        if (config->byte_count) { proto->in_bytes += trace_get_payload_length(packet); }
        if (config->packet_count) { proto->in_packets += 1; }
    } else {
        if (config->byte_count) { proto->out_bytes += trace_get_payload_length(packet); }
        if (config->packet_count) { proto->out_packets += 1; }
    }

    if (config->ip_count) {
        struct sockaddr_storage src_addr, dst_addr;

        // get the initial source and destination address for the flow
        bd_flow_get_source_ip(flow, &src_addr);
        bd_flow_get_destination_ip(flow, &dst_addr);

        // check if source ip is local/internal or external
        if (bd_local_ip((struct sockaddr *)&src_addr)) {
            proto->isrc_ips->insert(src_addr);
        } else {
            proto->esrc_ips->insert(src_addr);
        }

        // check if destination ip is local/internal or external
        if (bd_local_ip((struct sockaddr *)&dst_addr)) {
            proto->idst_ips->insert(dst_addr);
        } else {
            proto->edst_ips->insert(dst_addr);
        }
    }

    // insert the flow id
    if (config->flow_count) {
        proto->flow_ids->insert(flow->id.get_id_num());
    }
}

int module_flow_statistics_stopping(void *tls, void *mls) {
    mod_flow_stats_t *stats = (mod_flow_stats_t *)mls;

    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        module_flow_statistics_delete_proto_stats(&(stats->proto_stats[i]));
    }

    /* release stats memory */
    free(stats);
}

int module_flow_statistics_tick(libtrace_t *trace, libtrace_thread_t *thread,
    void *tls, void *mls, uint64_t tick) {

    // gain access to the stats
    mod_flow_stats_t *stats = (mod_flow_stats_t *)mls;

    // create result to send to combiner
    mod_flow_stats_t *combine = (mod_flow_stats_t *)
        malloc(sizeof(mod_flow_stats_t));
    if (combine == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_flow_statistics_tick()\n");
        exit(BD_OUTOFMEMORY);
    }

    // copy over protocol stats
    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        // copy over packet/byte counts
        combine->proto_stats[i].in_bytes = stats->proto_stats[i].in_bytes;
        combine->proto_stats[i].out_bytes = stats->proto_stats[i].out_bytes;
        combine->proto_stats[i].in_packets = stats->proto_stats[i].in_packets;
        combine->proto_stats[i].out_packets = stats->proto_stats[i].out_packets;
        // copy over src/dst ips
        combine->proto_stats[i].esrc_ips = stats->proto_stats[i].esrc_ips;
        combine->proto_stats[i].edst_ips = stats->proto_stats[i].edst_ips;
        // copy over internal src/dst ips
        combine->proto_stats[i].isrc_ips = stats->proto_stats[i].isrc_ips;
        combine->proto_stats[i].idst_ips = stats->proto_stats[i].idst_ips;
        // copy over flow ids
        combine->proto_stats[i].flow_ids = stats->proto_stats[i].flow_ids;

        // clear stats for current protocol
        module_flow_statistics_clear_proto_stats(&(stats->proto_stats[i]));
    }

    // send result to the combiner function
    bd_result_combine(trace, thread, combine, tick, config->callbacks->id);

    return 0;
}

void *module_flow_statistics_reporter_start(void *tls) {
    // create structure to hold tallies
    mod_flow_stats_t *tally = (mod_flow_stats_t *)
        malloc(sizeof(mod_flow_stats_t));
    if (tally == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_flow_statistics_reporter_start()\n");
        exit(BD_OUTOFMEMORY);
    }

    tally->lastkey = 0;

    // init all proto stats counters
    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        module_flow_statistics_init_proto_stats(&(tally->proto_stats[i]));
    }

    return tally;
}

int module_flow_statistics_combiner(bd_bigdata_t *bigdata, void *mls,
    uint64_t tick, void *result) {

    mod_flow_stats_t *tally = (mod_flow_stats_t *)mls;
    mod_flow_stats_t *res = (mod_flow_stats_t *)result;

    if (tally->lastkey == 0) {
        tally->lastkey = tick;
    }

    // if the incoming result is for a new time period (key) flush current tally
    // and clear it
    if (tally->lastkey < tick) {
        for (int i = 0; i < LPI_PROTO_LAST; i++) {
            // get pointer to current protocol
            mod_flow_stats_proto_t *proto = &(tally->proto_stats[i]);

            // create and populate the result set
            bd_result_set_t *result_set = bd_result_set_create("flow_stats");
            bd_result_set_insert_tag(result_set, "protocol",
                lpi_print((lpi_protocol_t)i));
            if (config->packet_count) {
                bd_result_set_insert_uint(result_set, "in_packets", proto->in_packets);
                bd_result_set_insert_uint(result_set, "out_packets", proto->out_packets);
            }
            if (config->byte_count) {
                bd_result_set_insert_uint(result_set, "in_bytes", proto->in_bytes);
                bd_result_set_insert_uint(result_set, "out_bytes", proto->out_bytes);
            }
            if (config->ip_count) {
                bd_result_set_insert_uint(result_set, "count_esrc_ips",
                    proto->esrc_ips->size());
                bd_result_set_insert_uint(result_set, "count_edst_ips",
                    proto->edst_ips->size());
                bd_result_set_insert_uint(result_set, "count_isrc_ips",
                    proto->isrc_ips->size());
                bd_result_set_insert_uint(result_set, "count_idst_ips",
                    proto->idst_ips->size());
            }
            if (config->flow_count) {
                bd_result_set_insert_uint(result_set, "count_flows",
                    proto->flow_ids->size());
            }
            // set the timestamp for the result
            bd_result_set_insert_timestamp(result_set, tick);
            // add interval
            bd_result_set_insert_int(result_set, "interval", config->output_interval);

            // send the result to any registered output modules
            bd_callback_trigger_output(bigdata, result_set);

            // free the result set
            bd_result_set_free(result_set);

            // clear the tally for this protocol
            module_flow_statistics_clear_proto_stats(proto);
        }

        // update the last key
        tally->lastkey = tick;
    }

    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        tally->proto_stats[i].in_bytes += res->proto_stats[i].in_bytes;
        tally->proto_stats[i].out_bytes += res->proto_stats[i].out_bytes;
        tally->proto_stats[i].in_packets += res->proto_stats[i].in_packets;
        tally->proto_stats[i].out_packets += res->proto_stats[i].out_packets;

        // merge src/dst ip sets
        tally->proto_stats[i].esrc_ips->insert(res->proto_stats[i].esrc_ips->begin(),
            res->proto_stats[i].esrc_ips->end());
        tally->proto_stats[i].edst_ips->insert(res->proto_stats[i].edst_ips->begin(),
            res->proto_stats[i].edst_ips->end());
        // merge local src/dst ip sets
        tally->proto_stats[i].isrc_ips->insert(res->proto_stats[i].isrc_ips->begin(),
            res->proto_stats[i].isrc_ips->end());
        tally->proto_stats[i].idst_ips->insert(res->proto_stats[i].idst_ips->begin(),
            res->proto_stats[i].idst_ips->end());
        // merge flow id set
        tally->proto_stats[i].flow_ids->insert(res->proto_stats[i].flow_ids->begin(),
            res->proto_stats[i].flow_ids->end());
    }

    // free the result passed to combiner
    free(result);
}

int module_flow_statistics_reporter_stop(void *tls, void *mls) {
    mod_flow_stats_t *tally = (mod_flow_stats_t *)mls;

    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        module_flow_statistics_delete_proto_stats(&(tally->proto_stats[i]));
    }

    free(tally);
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
                if (strcmp((char *)event->data.scalar.value, "output_all_protocols") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "t") == 0) {

                        config->output_all_protocols = 1;
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

        config->callbacks->reporter_start_cb = (cb_reporter_start)
            module_flow_statistics_reporter_start;
        config->callbacks->reporter_combiner_cb = (cb_reporter_combiner)
            module_flow_statistics_combiner;
        config->callbacks->reporter_stop_cb = (cb_reporter_stop)
            module_flow_statistics_reporter_stop;
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
    config->output_all_protocols = 0;
    config->byte_count = 0;
    config->packet_count = 0;
    config->flow_count = 0;

    config->callbacks = bd_create_cb_set("flow_statistics");
    config->callbacks->config_cb = (cb_config)module_flow_statistics_config;
    bd_register_cb_set(config->callbacks);

    return 0;
}
