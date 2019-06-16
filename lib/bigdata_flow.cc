#include "bigdata_flow.h"
#include "bigdata.h"
#include <netinet/in.h>

/* private prototypes */
int flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts);
int flow_process_metrics(libtrace_packet_t *packet, Flow *flow, double dir, double ts);

Flow *flow_per_packet(libtrace_t *trace, libtrace_thread_t *thread,
    libtrace_packet_t *packet, void *global, void *tls) {

    // Get thread local storage
    bd_global_t *global_data = (bd_global_t *)global;
    bd_thread_local_t *local_data = (bd_thread_local_t *)tls;

    Flow *flow;
    double ts = trace_get_seconds(packet);
    uint8_t dir;
    bool is_new = false;
    libtrace_tcp_t *tcp = NULL;
    libtrace_ip_t *ip = NULL;

    uint16_t l3_type;
    /* Libflowmanager only deals with IP traffic, so ignore anything
     * that does not have an IP header */
    ip = (libtrace_ip_t *)trace_get_layer3(packet, &l3_type, NULL);
    if (l3_type != 0x0800) { return NULL; }
    if (ip == NULL) { return NULL; }

    /* Get the direction of the trace, this could be improved */
    //dir = trace_get_direction(packet);
    if (ip->ip_src.s_addr < ip->ip_dst.s_addr) {
        dir = 0;
    } else {
        dir = 1;
    }

    /* Ignore packets where the IP addresses are the same - something is
     * probably screwy and it's REALLY hard to determine direction */
    if (ip->ip_src.s_addr == ip->ip_dst.s_addr)
        return NULL;

    /* Match the packet to a Flow - this will create a new flow if
     * there is no matching flow already in the Flow map and set the
     * is_new flag to true. */
    flow = local_data->flow_manager->matchPacketToFlow(packet, dir, &is_new);

    /* Libflowmanager did not like something about that packet - best to
     * just ignore it and carry on */
    if (flow == NULL)
        return NULL;

    /* If this is a new flow, metrics need to be allocated for it */
    if (is_new) {
        flow_init_metrics(packet, flow, dir, ts);

        bd_cb_set *cbs = global_data->callbacks;
        for (; cbs != NULL; cbs = cbs->next) {
            if (cbs->flowstart_cb != NULL) {
                cbs->flowstart_cb();
            }
        }
    }

    /* update metrics for the flow */
    flow_process_metrics(packet, flow, dir, ts);

    /* Tell libflowmanager to update the expiry time for this flow */
    local_data->flow_manager->updateFlowExpiry(flow, packet, dir, ts);

    return flow;
}

int flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts) {
    // create flow record for the flow
    bd_flow_record_t *flow_record = (bd_flow_record_t *)malloc(sizeof(bd_flow_record_t));


    flow_record->src_ip = (char *)malloc(sizeof(INET6_ADDRSTRLEN));
    flow_record->dst_ip = (char *)malloc(sizeof(INET6_ADDRSTRLEN));
    if (flow_record->src_ip == NULL || flow_record->dst_ip == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. flow_init_metrics()\n");
        return 1;
    }
    flow_record->src_ip = trace_get_source_address_string(packet,
    flow_record->src_ip, INET6_ADDRSTRLEN);
    flow_record->dst_ip = trace_get_destination_address_string(packet,
    flow_record->dst_ip, INET6_ADDRSTRLEN);
    flow_record->src_port = trace_get_source_port(packet);
    flow_record->dst_port = trace_get_destination_port(packet);
    flow_record->start_ts = ts;
    flow_record->end_ts = ts;
    flow_record->init_dir = dir;
    flow_record->in_packets = 0;
    flow_record->out_packets = 0;
    flow_record->in_bytes = 0;
    flow_record->out_bytes = 0;
    lpi_init_data(&flow_record->lpi);
    flow_record->lpi_module = NULL;

    // link flow record to the flow
    flow->extension = flow_record;

    return 0;
}

int flow_process_metrics(libtrace_packet_t *packet, Flow *flow, double dir, double ts) {
    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;

    flow_record->end_ts = ts;
    int lpi_updated;

    if (dir == 0) {
        flow_record->out_packets += 1;
        flow_record->out_bytes += trace_get_payload_length(packet);
    } else {
        flow_record->in_packets += 1;
        flow_record->in_bytes += trace_get_payload_length(packet);
    }

    /* update libprotoident */
    lpi_updated = lpi_update_data(packet, &flow_record->lpi, flow_record->init_dir);
    /* guess the protocol if its not known or was updated */
    if (flow_record->lpi_module == NULL || lpi_updated) {
        flow_record->lpi_module = lpi_guess_protocol(&flow_record->lpi);
    }

    return 0;
}

int flow_expire(libtrace_t *trace, libtrace_thread_t *thread,
    libtrace_packet_t *packet, void *global, void *tls) {

    bd_global_t *global_data = (bd_global_t *)global;
    bd_thread_local_t *local_data = (bd_thread_local_t *)tls;
    FlowManager *fm = local_data->flow_manager;
    bd_cb_set *cbs = global_data->callbacks;

    Flow *expired_flow;

    while ((expired_flow = fm->expireNextFlow(trace_get_seconds(packet), false)) != NULL) {
        /* Gain access to the flow metrics */
        bd_flow_record_t *flow_record = (bd_flow_record_t *)expired_flow->extension;

        /* Get the protocol name */
        flow_record->proto = strdup(flow_record->lpi_module->name);

        // create resultset for flow record and output
        bd_result_set_t *result_set = bd_result_set_create("flow");
        bd_result_set_insert_double(result_set, "start_ts", flow_record->start_ts);
        bd_result_set_insert_double(result_set, "end_ts", flow_record->end_ts);
        bd_result_set_insert_tag(result_set, "protocol", flow_record->proto);
        bd_result_set_insert_string(result_set, "src_ip", flow_record->src_ip);
        bd_result_set_insert_string(result_set, "dst_ip", flow_record->dst_ip);
        bd_result_set_insert_uint(result_set, "src_port", (uint64_t)flow_record->src_port);
        bd_result_set_insert_uint(result_set, "dst_port", (uint64_t)flow_record->dst_port);
        bd_result_set_insert_uint(result_set, "in_packets", flow_record->in_packets);
        bd_result_set_insert_uint(result_set, "out_packets", flow_record->out_packets);
        bd_result_set_insert_uint(result_set, "in_bytes", flow_record->in_bytes);
        bd_result_set_insert_uint(result_set, "out_bytes", flow_record->out_bytes);
        // output the result set
        bd_result_set_publish(trace, thread, result_set);

        // call all callbacks registered to flowend events
        for (; cbs != NULL; cbs = cbs->next) {
            if (cbs->flowend_cb != NULL) {
                cbs->flowend_cb();
            }
        }

        /* Free the metrics structure and release the flow to libflowmanager */
        free(flow_record->src_ip);
        free(flow_record->dst_ip);
        free(flow_record->proto);
        free(flow_record);
        fm->releaseFlow(expired_flow);
    }

    return 0;
}

