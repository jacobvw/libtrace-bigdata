#include "bigdata_flow.h"
#include "bigdata.h"
#include <netinet/in.h>
#include <arpa/inet.h>

/* private prototypes */
int flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts);
int flow_process_metrics(libtrace_t *trace, libtrace_thread_t *thread, libtrace_packet_t *packet,
    Flow *flow, void *global, void *tls, double dir, double ts);

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

    /* Get the direction of the packet */
    dir = bd_get_packet_direction(packet);

    /* Ignore packets where the IP addresses are the same - something is
     * probably screwy and it's REALLY hard to determine direction */
    if (ip->ip_src.s_addr == ip->ip_dst.s_addr) {
        return NULL;
    }

    /* Match the packet to a Flow - this will create a new flow if
     * there is no matching flow already in the Flow map and set the
     * is_new flag to true. */
    flow = local_data->flow_manager->matchPacketToFlow(packet, dir, &is_new);

    /* Libflowmanager did not like something about that packet - best to
     * just ignore it and carry on */
    if (flow == NULL) {
        return NULL;
    }

    /* If this is a new flow, metrics need to be allocated for it */
    if (is_new) {
        flow_init_metrics(packet, flow, dir, ts);

    }

    // update metrics for the flow
    flow_process_metrics(trace, thread, packet, flow, global, tls, dir, ts);

    // update expiry time for this flow
    local_data->flow_manager->updateFlowExpiry(flow, packet, dir, ts);

    return flow;
}

int flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts) {
    // create flow record for the flow
    bd_flow_record_t *flow_record = (bd_flow_record_t *)malloc(sizeof(bd_flow_record_t));
    if (flow_record == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. flow_init_metrics()\n");
        exit(BD_OUTOFMEMORY);
    }

    // Make sure to set the ss_family if no source or destination address was found
    if (trace_get_source_address(packet, (struct sockaddr *)
        &(flow_record->src_ip)) == NULL) {

        flow_record->src_ip.ss_family = AF_UNSPEC;
    }
    if (trace_get_destination_address(packet, (struct sockaddr *)
        &(flow_record->dst_ip)) == NULL) {

        flow_record->dst_ip.ss_family = AF_UNSPEC;
    }

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

int flow_process_metrics(libtrace_t *trace, libtrace_thread_t *thread, libtrace_packet_t *packet,
    Flow *flow, void *global, void *tls, double dir, double ts) {

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

    /* the lpi_module is only NULL when this is a new flow */
    if (flow_record->lpi_module == NULL) {
        /* try guess the protocol for the flow */
        flow_record->lpi_module = lpi_guess_protocol(&flow_record->lpi);

        /* create bigdata structure for the flowstart event */
        bd_bigdata_t bigdata;
        bigdata.trace = trace;
        bigdata.thread = thread;
        bigdata.packet = packet;
        bigdata.flow = flow;
        bigdata.global = (bd_global_t *)global;
        bigdata.tls = tls;

        /* Trigger the flowstart event */
        bd_callback_trigger_flowstart(&bigdata);

    /* Otherwise if this is not a new flow but lpi has updated */
    } else if (lpi_updated) {

        /* keep track of the old protocol */
        lpi_protocol_t oldproto = flow_record->lpi_module->protocol;

        /* Now guess the new protocol with the newly supplied information */
        flow_record->lpi_module = lpi_guess_protocol(&flow_record->lpi);

        /* If the protocol has changed generate a protocol updated event */
        if (oldproto != flow_record->lpi_module->protocol) {

            /* Create bigdata structure for the protocol updated event */
            bd_bigdata_t bigdata;
            bigdata.trace = trace;
            bigdata.thread = thread;
            bigdata.packet = packet;
            bigdata.flow = flow;
            bigdata.global = (bd_global_t *)global;
            bigdata.tls = tls;

            /* Trigger the event */
            bd_callback_trigger_protocol_updated(&bigdata, oldproto,
                flow_record->lpi_module->protocol);

        }
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

    /* create bigdata structure for expired flow event */
    bd_bigdata_t bigdata;
    bigdata.trace = trace;
    bigdata.thread = thread;
    bigdata.packet = NULL;
    bigdata.flow = NULL;
    bigdata.global = (bd_global_t *)global;
    bigdata.tls = tls;

    while ((expired_flow = fm->expireNextFlow(trace_get_seconds(packet), false)) != NULL) {
        // Gain access to the flow metrics
        bd_flow_record_t *flow_record = (bd_flow_record_t *)expired_flow->extension;

        /* update the flow in the bigdata structure for the current flow */
        bigdata.flow = expired_flow;

        /* trigger the flowend event */
        bd_callback_trigger_flowend(&bigdata);

        // Free the metrics structure and release the flow to libflowmanager
        free(flow_record);
        fm->releaseFlow(expired_flow);
    }

    return 0;
}

uint64_t bd_flow_get_in_packets(Flow *flow) {
    // gain access to flow metrics
    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;
    return flow_record->in_packets;
}

uint64_t bd_flow_get_out_packets(Flow *flow) {
    // gain access to flow metrics
    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;
    return flow_record->out_packets;
}

uint64_t bd_flow_get_in_bytes(Flow *flow) {
    // gain access to flow metrics
    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;
    return flow_record->in_bytes;
}

uint64_t bd_flow_get_out_bytes(Flow *flow) {
    // gain access to flow metrics
    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;
    return flow_record->out_bytes;
}

int bd_flow_get_direction(Flow *flow) {
    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;
    return flow_record->init_dir;
}

struct sockaddr_storage *bd_flow_get_source_ip(Flow *flow,
    struct sockaddr_storage *src) {

    if (src == NULL) {
        return NULL;
    }

    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;
    memcpy(src, &(flow_record->src_ip), sizeof(struct sockaddr_storage));

    return src;
}

struct sockaddr_storage *bd_flow_get_destination_ip(Flow *flow,
    struct sockaddr_storage *dst) {

    if (dst == NULL) {
        return NULL;
    }

    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;
    memcpy(dst, &(flow_record->dst_ip), sizeof(struct sockaddr_storage));

    return dst;
}

lpi_protocol_t bd_flow_get_protocol(bd_bigdata_t *bigdata) {

    if (bigdata == NULL) {
        return LPI_PROTO_UNKNOWN;
    }

    if (bigdata->flow == NULL) {
        return LPI_PROTO_UNKNOWN;
    }

    if (bigdata->flow->extension == NULL) {
        return LPI_PROTO_UNKNOWN;
    }

    /* If flow is not null we should have a flow record */
    bd_flow_record_t *flow_rec = (bd_flow_record_t *)
        (bigdata->flow->extension);

    return flow_rec->lpi_module->protocol;
}

FlowManager *bd_flow_get_flowmanager(bd_bigdata_t *bigdata) {

    if (bigdata == NULL) {
        fprintf(stderr, "NULL bigdata structure passed into. func "
            "bd_get_flowmanager()\n");
        return NULL;
    }

    /* first ensure this is a processing thread. The flowmanager is not
     *  available from the reporting thread.
     */
    if (trace_get_perpkt_thread_id(bigdata->thread) == -1) {
        fprintf(stderr, "Flowmanager is only available from the "
            "processing threads\n");
        return NULL;
    }

    // get thread local storage
    bd_thread_local_t *local = (bd_thread_local_t *)bigdata->tls;

    return local->flow_manager;
}

Flow *bd_flow_get(bd_bigdata_t *bigdata) {
     return bigdata->flow;
}

bd_flow_record_t *bd_flow_get_record(bd_bigdata_t *bigdata) {

    if (bigdata == NULL) {
        fprintf(stderr, "NULL bigdata structure passed into. func "
            "bd_get_flow_record()\n");
        return NULL;
    }

    Flow *f;
    if ((f = bd_flow_get(bigdata)) != NULL) {
        return (bd_flow_record_t *)f->extension;
    }

    return NULL;
}

double bd_flow_get_duration(bd_bigdata_t *bigdata) {

    bd_flow_record_t *rec;
    if ((bd_flow_get_record(bigdata)) != NULL) {
        return rec->end_ts - rec->start_ts;
    }

    return 0;
}
