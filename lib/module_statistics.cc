#include "module_statistics.h"

#include <set>

struct module_statistics_conf {
    bd_cb_set *callbacks;
    bool enabled;
    int output_interval;
    bool byte_count;
    bool packet_count;
    bool ip4_packet_count;
    bool ip6_packet_count;
    bool tcp_packet_count;
    bool udp_packet_count;
};
static struct module_statistics_conf *config;

typedef struct module_statistics {
    double start_ts;                          // start time for the statistics
    double end_ts;                            // end time for the statistics
    std::set<uint8_t> *u_tcp_ops;             // all tcp options found
    uint64_t c_in_packets;                    // count of inbound packets
    uint64_t c_out_packets;                   // count of outbound packets
    uint64_t c_in_bytes;                      // number of inbound bytes
    uint64_t c_out_bytes;                     // number of outbound bytes
    uint64_t lastkey;                         // lastkey used for each output interval

    uint64_t tcp_pkts;
    uint64_t udp_pkts;
    uint64_t ip4_pkts;
    uint64_t ip6_pkts;
} mod_stats_t;

void module_statistics_init_stor(mod_stats_t *stats) {
    stats->start_ts = 0;
    stats->end_ts = 0;
    stats->u_tcp_ops = new std::set<uint8_t>;
    stats->c_in_packets = 0;
    stats->c_out_packets = 0;
    stats->c_in_bytes = 0;
    stats->c_out_bytes = 0;
    stats->tcp_pkts = 0;
    stats->udp_pkts = 0;
    stats->ip4_pkts = 0;
    stats->ip6_pkts = 0;
}

void module_statistics_clear_stor(mod_stats_t *stats) {
    stats->u_tcp_ops->clear();
    stats->c_in_packets = 0;
    stats->c_out_packets = 0;
    stats->c_in_bytes = 0;
    stats->c_out_bytes = 0;
    stats->tcp_pkts = 0;
    stats->udp_pkts = 0;
    stats->ip4_pkts = 0;
    stats->ip6_pkts = 0;
}

void module_statistics_delete_stor(mod_stats_t *stats) {
    delete(stats->u_tcp_ops);
}

void *module_statistics_starting(void *tls) {
    /* Allocate memory for module storage */
    mod_stats_t *stats = (mod_stats_t *)malloc(sizeof(mod_stats_t));
    if (stats == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_statistics_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    // initialise storage
    module_statistics_init_stor(stats);

    return stats;
}

int module_statistics_packet(bd_bigdata_t *bigdata, void *mls) {

    libtrace_t *trace = bigdata->trace;
    libtrace_thread_t *thread = bigdata->thread;
    libtrace_packet_t *packet = bigdata->packet;
    Flow *flow = bigdata->flow;
    void *tls = bigdata->tls;

    // get the module local storage
    mod_stats_t *stats = (mod_stats_t *)mls;
    // get the packet direction
    int dir = bd_get_packet_direction(packet);

    // check if the packet contains a TCP header
    libtrace_tcp_t *tcp_h = trace_get_tcp(packet);
    if (tcp_h) {
        stats->tcp_pkts += 1;
    }

    // check if the packet contains a UDP header
    libtrace_udp_t *udp_h = trace_get_udp(packet);
    if (udp_h) {
        stats->udp_pkts += 1;
    }

    libtrace_ip_t *ip4 = trace_get_ip(packet);
    if (ip4) {
        stats->ip4_pkts += 1;
    }

    libtrace_ip6_t *ip6 = trace_get_ip6(packet);
    if (ip6) {
        stats->ip6_pkts += 1;
    }

    // update all the counters
    if (dir) {
        if (config->packet_count) { stats->c_in_packets += 1; }
        if (config->byte_count) { stats->c_in_bytes += trace_get_payload_length(packet); }
    } else {
        if (config->packet_count) { stats->c_out_packets += 1; }
        if (config->byte_count) { stats->c_out_bytes += trace_get_payload_length(packet); }
    }

    // update timestamps
    if (stats->start_ts = 0) { trace_get_seconds(packet); }
    stats->end_ts = trace_get_seconds(packet);
}

int module_statistics_stopping(void *tls, void *mls) {
    mod_stats_t *stats = (mod_stats_t *)mls;

    module_statistics_delete_stor(stats);

    /* release stats memory */
    free(stats);
}

int module_statistics_tick(bd_bigdata_t *bigdata, void *mls, uint64_t tick) {

    libtrace_t *trace = bigdata->trace;
    libtrace_thread_t *thread = bigdata->thread;
    void *tls = bigdata->tls;

    // gain access to the stats
    mod_stats_t *stats = (mod_stats_t *)mls;

    // create result for the combiner
    mod_stats_t *combine = (mod_stats_t *)malloc(sizeof(mod_stats_t));
    if (combine == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_statistics_tick()\n");
        exit(BD_OUTOFMEMORY);
    }

    // copy over results
    combine->c_in_packets = stats->c_in_packets;
    combine->c_out_packets = stats->c_out_packets;
    combine->c_in_bytes = stats->c_in_bytes;
    combine->c_out_bytes = stats->c_out_bytes;
    combine->ip4_pkts = stats->ip4_pkts;
    combine->ip6_pkts = stats->ip6_pkts;
    combine->tcp_pkts = stats->tcp_pkts;
    combine->udp_pkts = stats->udp_pkts;

    // clear current stats
    module_statistics_clear_stor(stats);

    // send results to the combiner function
    bd_result_combine(bigdata, combine, tick, config->callbacks->id);

    return 0;
}

void *module_statistics_reporter_start(void *tls) {
    /* Allocate memory for tally storage */
    mod_stats_t *tally = (mod_stats_t *)malloc(sizeof(mod_stats_t));
    if (tally == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_statistics_reporter_start()\n");
        exit(BD_OUTOFMEMORY);
    }

    tally->lastkey = 0;

    // initialise storage
    module_statistics_init_stor(tally);

    return tally;
}

int module_statistics_combiner(bd_bigdata_t *bigdata, void *mls,
    uint64_t tick, void *result) {

    mod_stats_t *tally = (mod_stats_t *)mls;
    mod_stats_t *res = (mod_stats_t *)result;

    if (tally->lastkey == 0) {
        tally->lastkey = tick;
    }

    // if a new result is due
    if (tally->lastkey <  tick) {
        bd_result_set_t *result_set = bd_result_set_create("statistics");
        bd_result_set_insert_uint(result_set, "in_bytes", tally->c_in_bytes);
        bd_result_set_insert_uint(result_set, "out_bytes", tally->c_out_bytes);
        bd_result_set_insert_uint(result_set, "in_packets", tally->c_in_packets);
        bd_result_set_insert_uint(result_set, "out_packets", tally->c_out_packets);
        // output ip4 packet count if enabled
        if (config->ip4_packet_count) {
            bd_result_set_insert_uint(result_set, "ip4_packets", tally->ip4_pkts);
        }
        // output ip6 packet count if enabled
        if (config->ip6_packet_count) {
            bd_result_set_insert_uint(result_set, "ip6_packets", tally->ip6_pkts);
        }
        // output tcp packet count if enabled
        if (config->tcp_packet_count) {
            bd_result_set_insert_uint(result_set, "tcp_packets", tally->tcp_pkts);
        }
        // output udp packet count if enabled
        if (config->udp_packet_count) {
            bd_result_set_insert_uint(result_set, "udp_packets", tally->udp_pkts);
        }

        // insert timestamp into result
        bd_result_set_insert_timestamp(result_set, tick);
        // insert time interval
        bd_result_set_insert_int(result_set, "interval", config->output_interval);

        // post the result
        bd_result_set_publish(bigdata, result_set, tick);

        // clear the tally
        module_statistics_clear_stor(tally);

        // update the last key
        tally->lastkey = tick;
    }

    // increment the tally
    tally->c_in_packets += res->c_in_packets;
    tally->c_out_packets += res->c_out_packets;
    tally->c_in_bytes += res->c_in_bytes;
    tally->c_out_bytes += res->c_out_bytes;
    tally->ip4_pkts += res->ip4_pkts;
    tally->ip6_pkts += res->ip6_pkts;
    tally->tcp_pkts += res->tcp_pkts;
    tally->udp_pkts += res->udp_pkts;

    // free the result
    free(res);
}

int module_statistics_clear(void *mls) {
    mod_stats_t *stats = (mod_stats_t *)mls;

    module_statistics_clear_stor(stats);
}

int module_statistics_reporter_stop(void *tls, void *mls) {
    mod_stats_t *tally = (mod_stats_t *)mls;

    module_statistics_delete_stor(tally);

    free(tally);
}

int module_statistics_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {
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
                            "module_statistics. Disabling module\n");
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
                if (strcmp((char *)event->data.scalar.value, "ip4_packet_count") == 0) {
                    consume_event(parser, event, level);
                    config->ip4_packet_count = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "ip6_packet_count") == 0) {
                    consume_event(parser, event, level);
                    config->ip6_packet_count = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "tcp_packet_count") == 0) {
                    consume_event(parser, event, level);
                    config->tcp_packet_count = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "udp_packet_count") == 0) {
                    consume_event(parser, event, level);
                    config->udp_packet_count = 1;
                    break;
                }
            default:
                consume_event(parser, event, level);
                break;
        }
    }

    if (config->enabled) {
        config->callbacks->start_cb = (cb_start)module_statistics_starting;
        config->callbacks->packet_cb = (cb_packet)module_statistics_packet;
        config->callbacks->stop_cb = (cb_stop)module_statistics_stopping;

        config->callbacks->tick_cb = (cb_tick)module_statistics_tick;

        config->callbacks->reporter_start_cb = (cb_reporter_start)
            module_statistics_reporter_start;
        config->callbacks->reporter_combiner_cb = (cb_reporter_combiner)
            module_statistics_combiner;
        config->callbacks->reporter_stop_cb = (cb_reporter_stop)
            module_statistics_reporter_stop;

        config->callbacks->clear_cb = (cb_clear)module_statistics_clear;

        fprintf(stderr, "Statistics Plugin Enabled\n");
    }

    return 0;
}

int module_statistics_init() {
    // allocate memory for config structure
    config = (struct module_statistics_conf *)malloc(
        sizeof(struct module_statistics_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_statistics_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    // initialise the config structure
    config->enabled = 0;
    config->output_interval = 10000;
    config->byte_count = 0;
    config->packet_count = 0;
    config->ip4_packet_count = 0;
    config->ip6_packet_count = 0;
    config->tcp_packet_count = 0;
    config->udp_packet_count = 0;

    config->callbacks = bd_create_cb_set("statistics");
    config->callbacks->config_cb = (cb_config)module_statistics_config;
    bd_register_cb_set(config->callbacks);

    return 0;
}
