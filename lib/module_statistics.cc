#include "module_statistics.h"
#include "bigdata.h"

typedef struct module_statistics {
    double start_ts;                // start time for the statistics
    double end_ts;                  // end time for the statistics
    uint64_t u_tcp_ops;             // number of unique TCP options
    uint64_t c_in_packets;          // count of inbound packets
    uint64_t c_out_packets;         // count of outbound packets
    uint64_t c_in_bytes;            // number of inbound bytes
    uint64_t c_out_bytes;           // number of outbound bytes
} mod_stats_t;

void *module_statistics_starting(void *tls) {
    mod_stats_t *stats = (mod_stats_t *)malloc(sizeof(mod_stats_t));
    if (stats == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_statistics_starting()\n");
        return NULL;
    }
}

int module_statistics_packet(libtrace_t *trace, libtrace_thread_t *thread,
    Flow *flow, libtrace_packet_t *packet, void *tls, void *mls) {

    
}

int module_statistics_stopping(void *tls, void *mls) {

}

int module_statistics_tick() {
    fprintf(stderr, "tick stats\n");
}

int module_statistics_combiner() {

}

int module_statistics_init() {
    bd_cb_set *callbacks = bd_create_cb_set();

    callbacks->start_cb = (cb_start)module_statistics_starting;
    callbacks->packet_cb = (cb_packet)module_statistics_packet;
    callbacks->stop_cb = (cb_stop)module_statistics_stopping;
    callbacks->tick_cb = (cb_tick)module_statistics_tick;
    callbacks->combiner_cb = (cb_combiner)module_statistics_combiner;

    bd_add_tickrate_to_cb_set(callbacks, 5000);
    bd_register_cb_set(callbacks);

    return 0;
}
