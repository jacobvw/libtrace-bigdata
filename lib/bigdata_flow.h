
#ifndef BIGDATA_FLOW_H
#define BIGDATA_FLOW_H

#include "bigdata.h"

typedef struct bigdata_flow_record {
    double start_ts;
    double end_ts;
    struct sockaddr_storage src_ip;
    struct sockaddr_storage dst_ip;
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

int flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts);

int flow_process_metrics(libtrace_packet_t *packet, Flow *flow, double dir, double ts);

int flow_expire(libtrace_t *trace, libtrace_thread_t *thread,libtrace_packet_t *packet,
    void *global, void *tls);

uint64_t bd_flow_get_in_packets(Flow *flow);
uint64_t bd_flow_get_out_packets(Flow *flow);
uint64_t bd_flow_get_in_bytes(Flow *flow);
uint64_t bd_flow_get_out_bytes(Flow *flow);
int bd_flow_get_direction(Flow *flow);
struct sockaddr_storage *bd_flow_get_source_ip(Flow *flow, struct sockaddr_storage *src);
struct sockaddr_storage *bd_flow_get_destination_ip(Flow *flow, struct sockaddr_storage *dst);

lpi_protocol_t bd_flow_get_protocol(bd_bigdata_t *bigdata);
FlowManager *bd_flow_get_flowmanager(bd_bigdata_t *bigdata);
Flow *bd_flow_get(bd_bigdata_t *bigdata);
bd_flow_record_t *bd_flow_get_record(bd_bigdata_t *bigdata);
double bd_flow_get_duration(bd_bigdata_t *bigdata);
uint64_t bd_flow_get_id(bd_bigdata_t *bigdata);

#endif
