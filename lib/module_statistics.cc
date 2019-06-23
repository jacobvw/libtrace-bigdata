#include "module_statistics.h"
#include "bigdata.h"
#include <unordered_map>
#include <set>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

    std::set<uint32_t> *src_ips;
    std::set<uint32_t> *dst_ips;

    std::set<uint32_t> *local_ips;
    std::set<uint32_t> *remote_ips;

    // keep track of all the flow ids - used as a way to count number of flows
    std::set<uint64_t> *flow_ids;
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

int mod_statistics_is_local_ip(uint32_t address) {
    //bd_get_local_ips();
    return 0;
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
    int dir = bd_get_packet_direction(packet);
    struct sockaddr_storage src_addr, dst_addr;
    struct sockaddr *src_ip, *dst_ip;

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

        proto->src_ips = new std::set<uint32_t>;
        proto->dst_ips = new std::set<uint32_t>;

        proto->local_ips = new std::set<uint32_t>;
        proto->remote_ips = new std::set<uint32_t>;

        proto->flow_ids = new std::set<uint64_t>;

        stats->proto_stats->insert({flow_rec->lpi_module->protocol, proto});
    } else {
        proto = (mod_stats_proto_t *)search->second;
    }

    // if the protocol has changed for this flow
    if (proto->module != flow_rec->lpi_module) {
        // find a way to move recorded stats over to correct proto??
        proto->module = flow_rec->lpi_module;
    }
    // update counters for the protocol
    if (dir) {
        proto->in_bytes += trace_get_payload_length(packet);
        proto->in_packets += 1;
    } else {
        proto->out_bytes += trace_get_payload_length(packet);
        proto->out_packets += 1;
    }

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

    // insert the flow id
    proto->flow_ids->insert(flow->id.get_id_num());
}

int module_statistics_stopping(void *tls, void *mls) {
    mod_stats_t *stats = (mod_stats_t *)mls;

    // free allocated structures within the map
    for (std::unordered_map<lpi_protocol_t, mod_stats_proto_t *>::iterator
        it=stats->proto_stats->begin(); it!=stats->proto_stats->end(); ++it) {

        mod_stats_proto_t *proto = (mod_stats_proto_t *)it->second;

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

int module_statistics_tick(libtrace_t *trace, libtrace_thread_t *thread,
    void *tls, void *mls, uint64_t tick) {

    // gain access to the stats
    mod_stats_t *stats = (mod_stats_t *)mls;

    // create result set
    //bd_result_set_t *result_set = bd_result_set_create("stats");
    //bd_result_set_insert_uint(result_set, "start_ts", stats->start_ts);
    //bd_result_set_insert_uint(result_set, "end_ts" , stats->end_ts);
    //bd_result_set_insert_uint(result_set, "unique_tcp_ops", stats->u_tcp_ops);
    //bd_result_set_insert_uint(result_set, "in_packets", stats->c_in_packets);
    //bd_result_set_insert_uint(result_set, "out_packets", stats->c_out_packets);
    //bd_result_set_insert_uint(result_set, "in_bytes", stats->c_in_bytes);
    //bd_result_set_insert_uint(result_set, "out_bytes", stats->c_out_bytes);

    // clear stats counters
    //module_statistics_init_stor(stats);

    // publish the result
    //bd_result_set_publish(trace, thread, result_set);

    // output protocol counters
    for (std::unordered_map<lpi_protocol_t, mod_stats_proto_t *>::iterator
        it=stats->proto_stats->begin(); it!=stats->proto_stats->end(); ++it) {

        mod_stats_proto_t *proto = (mod_stats_proto_t *)it->second;

        bd_result_set_t *result_set = bd_result_set_create("stats");
        bd_result_set_insert_tag(result_set, "protocol", proto->module->name);
        bd_result_set_insert_uint(result_set, "in_packets", proto->in_packets);
        bd_result_set_insert_uint(result_set, "out_packets", proto->out_packets);
        bd_result_set_insert_uint(result_set, "in_bytes", proto->in_bytes);
        bd_result_set_insert_uint(result_set, "out_bytes", proto->out_bytes);
        bd_result_set_insert_uint(result_set, "unique_src_ips", proto->src_ips->size());
        bd_result_set_insert_uint(result_set, "unique_dst_ips", proto->dst_ips->size());
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
        bd_result_set_insert_uint(result_set, "unique_flows", proto->flow_ids->size());

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
    fprintf(stderr, "\n");
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
