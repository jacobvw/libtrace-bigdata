#include "module_statistics.h"
#include "bigdata.h"
#include <unordered_map>
#include <set>

typedef struct module_statistics_proto mod_stats_proto_t;

typedef struct module_statistics {
    double start_ts;                          // start time for the statistics
    double end_ts;                            // end time for the statistics
    uint64_t u_tcp_ops;                       // number of unique TCP options
    uint64_t c_in_packets;                    // count of inbound packets
    uint64_t c_out_packets;                   // count of outbound packets
    uint64_t c_in_bytes;                      // number of inbound bytes
    uint64_t c_out_bytes;                     // number of outbound bytes

    // map containing stats for each flow
    std::unordered_map<lpi_protocol_t, mod_stats_proto_t *> *proto_stats;
} mod_stats_t;

typedef struct module_statistics_proto {
    lpi_module *module;

    uint64_t in_bytes;
    uint64_t out_bytes;

    uint64_t in_packets;
    uint64_t out_packets;

    std::set<uint32_t> local_ips;
    std::set<uint32_t> remote_ips;

    // posibly have a list of flows? could help count number of unique ones
    
} mod_stats_proto_t;

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

    // create protocol list
    stats->proto_stats = new std::unordered_map<lpi_protocol_t, mod_stats_proto_t *>;

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

    // update all the counters
    if (bd_get_packet_direction(packet)) {
        stats->c_in_packets += 1;
        stats->c_in_bytes += trace_get_payload_length(packet);
    } else {
        stats->c_out_packets += 1;
        stats->c_out_bytes += trace_get_payload_length(packet);
    }

    // update timestamps
    if (stats->start_ts = 0) { trace_get_seconds(packet); }
    stats->end_ts = trace_get_seconds(packet);



    // search proto_stats map for this protocol
    auto search = stats->proto_stats->find(flow_rec->lpi_module->protocol);
    mod_stats_proto_t *proto;

    // If protocol was not found create it and insert it
    if (search == stats->proto_stats->end()) {
        proto = (mod_stats_proto_t *)
            malloc(sizeof(mod_stats_proto_t));
        if (proto == NULL) {
            fprintf(stderr, "Unable to allocate memory. func. "
                "module_statistics_packet()\n");
            exit(BD_OUTOFMEMORY);
        }

        proto->module = flow_rec->lpi_module;
        proto->in_bytes = 0;
        proto->out_bytes = 0;
        proto->in_packets = 0;
        proto->out_packets = 0;

        stats->proto_stats->insert({flow_rec->lpi_module->protocol, proto});
    } else {
        proto = (mod_stats_proto_t *)search->second;
    }

    // update counters for the protocol
    if (bd_get_packet_direction(packet)) {
        proto->in_bytes += trace_get_payload_length(packet);
        proto->in_packets += 1;
    } else {
        proto->out_bytes += trace_get_payload_length(packet);
        proto->out_packets += 1;
    }
}

int module_statistics_stopping(void *tls, void *mls) {
    mod_stats_t *stats = (mod_stats_t *)mls;

    /* delete protocol stats list. Need to empty the list first */
    delete(stats->proto_stats);

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

    // clear stats counters
    module_statistics_init_stor(stats);

    // publish the result
    bd_result_set_publish(trace, thread, result_set);

    // output protocol counters
    for (std::unordered_map<lpi_protocol_t, mod_stats_proto_t *>::iterator
        it=stats->proto_stats->begin(); it!=stats->proto_stats->end(); ++it) {

        mod_stats_proto_t *proto = (mod_stats_proto_t *)it->second;

        fprintf(stderr, "Protocol: %s\n", proto->module->name);
        fprintf(stderr, "\tIn packets: %lu\n", proto->in_packets);
        fprintf(stderr, "\tOut packets: %lu\n", proto->out_packets);
    }
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
