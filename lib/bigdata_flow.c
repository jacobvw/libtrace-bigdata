#include <libtrace_parallel.h>
#include <libflowmanager.h>
#include <libprotoident.h>
#include <netinet/in.h>

void flow_per_packet(libtrace_t *trace, libtrace_packet_t *packet, void *global, void *local) {
    // Get thread local storage
    bigdata_global_t *global_data = (bigdata_global_t *)global;
    bigdata_local_t *local_data = (bigdata_local_t *)local;
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
    if (l3_type != 0x0800) { return; }
    if (ip == NULL) { return; }

    /* Get the direction of the trace, this could be improved */
    dir = trace_get_direction(packet);

    /* Ignore packets where the IP addresses are the same - something is
     * probably screwy and it's REALLY hard to determine direction */
    if (ip->ip_src.s_addr == ip->ip_dst.s_addr)
        return;

    /* Match the packet to a Flow - this will create a new flow if
     * there is no matching flow already in the Flow map and set the
     * is_new flag to true. */
    flow = local_data->flow_manager->matchPacketToFlow(packet, dir, &is_new);

    /* Libflowmanager did not like something about that packet - best to
     * just ignore it and carry on */
    if (flow == NULL)
        return;

    /* If this is a new flow, metrics need to be allocated for it */
    if (is_new) {
        flow_init_metrics(packet, flow, dir, ts);

        // Call flow start callbacks
        ltbigdata_event_handlers *handler = global_data->listeners[FLOW_START];
        /* Call callbacks registered to the start of a flow */
        for (; handler != NULL; handler = handler->next) {
            handler->cb(trace, packet, local_data);
        }
    }

    /* update metrics for the flow */
    flow_process_metrics(packet, flow, dir, ts);

    /* Tell libflowmanager to update the expiry time for this flow */
    local_data->flow_manager->updateFlowExpiry(flow, packet, dir, ts);
}

void flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts) {
    bd_record_t *flow_record;
    flow_record = (bd_record_t *)malloc(sizeof(bd_record_t));

    // allocate memory for source/destination ips, allow for space to store v6 addresses
    flow_record->src_ip = (char *)malloc(INET6_ADDRSTRLEN);
    flow_record->dst_ip = (char *)malloc(INET6_ADDRSTRLEN);
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

    fprintf(stderr, "created new flow\n");

    flow->extension = flow_record;
}

void flow_process_metrics(libtrace_packet_t *packet, Flow *flow, double dir, double ts) {
    bd_record_t *flow_record = (bd_record_t *)flow->extension;

    flow_record->end_ts = ts;

    if (dir == 0) {
        flow_record->out_packets += 1;
        flow_record->out_bytes += trace_get_payload_length(packet);
    } else {
        flow_record->in_packets += 1;
        flow_record->in_bytes += trace_get_payload_length(packet);
    }

    /* update libprotoident */
    lpi_update_data(packet, &flow_record->lpi, flow_record->init_dir);
}

void flow_expire(libtrace_t *trace, libtrace_packet_t *packet, void *global, void *local) {

    bigdata_global_t *global_data = (bigdata_global_t *)global;
    bigdata_local_t *local_data = (bigdata_local_t *)local;
    FlowManager *fm = local_data->flow_manager;
    ltbigdata_event_handlers *handler = global_data->listeners[FLOW_END];

    Flow *expired;

    while ((expired = fm->expireNextFlow(trace_get_seconds(packet), false)) != NULL) {
        /* Gain access to the flow metrics */
        bd_record_t *flow_record = (bd_record_t *)expired->extension;

        /* Guess the protocol */
        lpi_module_t *proto = lpi_guess_protocol(&flow_record->lpi);
        flow_record->proto = (char *)malloc(sizeof(proto->name));
        flow_record->proto = strdup(proto->name);

        /* Export the metrics */
        bd_output_record(flow_record);

        /* Call callbacks registered to the end of a flow */
        for (; handler != NULL; handler = handler->next) {
            handler->cb(trace, packet, local_data);
        }

        /* Free the metrics structure and release the flow to libflowmanager */
        free(flow_record->src_ip);
        free(flow_record->dst_ip);
        free(flow_record->proto);
        free(flow_record);
        fm->releaseFlow(expired);
    }
}
