#include "module_statistics.h"
#include "bigdata.h"

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
    // get the flow record
    bd_flow_record_t *flow_rec = (bd_flow_record_t *)flow->extension;

    uint64_t tcp_ops = 0;
    int dir = bd_get_packet_direction(packet);

    // update all the counters
    if (dir) {
        stats->c_in_packets += 1;
        stats->c_in_bytes += trace_get_payload_length(packet);
    } else {
        stats->c_out_packets += 1;
        stats->c_out_bytes += trace_get_payload_length(packet);
    }

    // update timestamps
    if (stats->start_ts = 0) { trace_get_seconds(packet); }
    stats->end_ts = trace_get_seconds(packet);
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
    bd_result_set_insert_uint(result_set, "start_ts", stats->start_ts);
    bd_result_set_insert_uint(result_set, "end_ts" , stats->end_ts);
    bd_result_set_insert_uint(result_set, "unique_tcp_ops", stats->u_tcp_ops);
    bd_result_set_insert_uint(result_set, "in_packets", stats->c_in_packets);
    bd_result_set_insert_uint(result_set, "out_packets", stats->c_out_packets);
    bd_result_set_insert_uint(result_set, "in_bytes", stats->c_in_bytes);
    bd_result_set_insert_uint(result_set, "out_bytes", stats->c_out_bytes);
    bd_result_set_publish(trace, thread, result_set);

    // clear stats counters
    module_statistics_init_stor(stats);

}

int module_statistics_combiner(bd_result_t *result) {

}

int module_statistics_init() {
    bd_cb_set *callbacks = bd_create_cb_set();

    callbacks->start_cb = (cb_start)module_statistics_starting;
    callbacks->packet_cb = (cb_packet)module_statistics_packet;
    callbacks->stop_cb = (cb_stop)module_statistics_stopping;
    callbacks->tick_cb = (cb_tick)module_statistics_tick;

    // output results every minute
    bd_add_tickrate_to_cb_set(callbacks, 5000);
    bd_register_cb_set(callbacks);

    return 0;
}
