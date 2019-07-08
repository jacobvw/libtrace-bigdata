#ifndef BIGDATA_FLOW_H
#define BIGDATA_FLOW_H

#include "bigdata.h"

typedef struct bigdata_flow_record {
    double start_ts;
    double end_ts;
    char *proto;
    char *src_ip;
    char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t in_packets;
    uint64_t out_packets;
    uint64_t in_bytes;
    uint64_t out_bytes;
    uint8_t init_dir;
    lpi_data_t lpi;
    lpi_module_t *lpi_module;
} bd_flow_record_t;

Flow *flow_per_packet(libtrace_t *trace, libtrace_thread_t *thread,
    libtrace_packet_t *packet, void *global, void *tls);

int flow_expire(libtrace_t *trace, libtrace_thread_t *thread,libtrace_packet_t *packet,
    void *global, void *tls);

uint64_t bd_flow_get_in_packets(Flow *flow);
uint64_t bd_flow_get_out_packets(Flow *flow);
uint64_t bd_flow_get_in_bytes(Flow *flow);
uint64_t bd_flow_get_out_bytes(Flow *flow);
#endif
