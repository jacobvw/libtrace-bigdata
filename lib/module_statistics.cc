#include "module_statistics.h"
#include "bigdata.h"

struct module_statistics_conf {
    bd_cb_set *callbacks;
    bool enabled;
    int output_interval;
    bool byte_count;
    bool packet_count;
    bool duration;
};
static struct module_statistics_conf *config;

typedef struct module_statistics {
    double start_ts;                          // start time for the statistics
    double end_ts;                            // end time for the statistics
    uint64_t u_tcp_ops;                       // number of unique TCP options
    uint64_t c_in_packets;                    // count of inbound packets
    uint64_t c_out_packets;                   // count of outbound packets
    uint64_t c_in_bytes;                      // number of inbound bytes
    uint64_t c_out_bytes;                     // number of outbound bytes
} mod_stats_t;

void module_statistics_init_stor(mod_stats_t *stats) {

    stats->start_ts = 0;
    stats->end_ts = 0;
    stats->u_tcp_ops = 0;
    stats->c_in_packets = 0;
    stats->c_out_packets = 0;
    stats->c_in_bytes = 0;
    stats->c_out_bytes = 0;
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

int module_statistics_packet(libtrace_t *trace, libtrace_thread_t *thread,
    Flow *flow, libtrace_packet_t *packet, void *tls, void *mls) {

    // get the module local storage
    mod_stats_t *stats = (mod_stats_t *)mls;
    // get the packet direction
    int dir = bd_get_packet_direction(packet);

    // update all the counters
    if (dir) {
        if (config->packet_count) { stats->c_in_packets += 1; }
        if (config->byte_count) { stats->c_in_bytes += trace_get_payload_length(packet); }
    } else {
        if (config->packet_count) { stats->c_out_packets += 1; }
        if (config->byte_count) { stats->c_out_bytes += trace_get_payload_length(packet); }
    }

    // update timestamps
    if (config->duration) {
        if (stats->start_ts = 0) { trace_get_seconds(packet); }
        stats->end_ts = trace_get_seconds(packet);
    }
}

int module_statistics_stopping(void *tls, void *mls) {
    mod_stats_t *stats = (mod_stats_t *)mls;

    /* release stats memory */
    free(stats);
}

int module_statistics_tick(libtrace_t *trace, libtrace_thread_t *thread,
    void *tls, void *mls, uint64_t tick) {

    // gain access to the stats
    mod_stats_t *stats = (mod_stats_t *)mls;

    // create result set
    bd_result_set_t *result_set = bd_result_set_create("stats");
    if (config->duration) {
        bd_result_set_insert_uint(result_set, "start_ts", stats->start_ts);
        bd_result_set_insert_uint(result_set, "end_ts" , stats->end_ts);
        bd_result_set_insert_uint(result_set, "duration", stats->end_ts - stats->start_ts);
    }
    //bd_result_set_insert_uint(result_set, "unique_tcp_ops", stats->u_tcp_ops);
    if (config->packet_count) {
        bd_result_set_insert_uint(result_set, "in_packets", stats->c_in_packets);
        bd_result_set_insert_uint(result_set, "out_packets", stats->c_out_packets);
    }
    if (config->byte_count) {
        bd_result_set_insert_uint(result_set, "in_bytes", stats->c_in_bytes);
        bd_result_set_insert_uint(result_set, "out_bytes", stats->c_out_bytes);
    }
    bd_result_set_publish(trace, thread, result_set, tick);

    // clear stats counters
    module_statistics_init_stor(stats);

}

int module_statistics_combiner(bd_result_t *result) {

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
                if (strcmp((char *)event->data.scalar.value, "duration") == 0) {
                    consume_event(parser, event, level);
                    config->duration = 1;
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
    config->duration = 0;

    config->callbacks = bd_create_cb_set("statistics");
    config->callbacks->config_cb = (cb_config)module_statistics_config;
    bd_register_cb_set(config->callbacks);

    return 0;
}
