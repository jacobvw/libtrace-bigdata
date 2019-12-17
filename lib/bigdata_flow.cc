#include "bigdata_flow.h"
#include <netinet/in.h>
#include <arpa/inet.h>

static int flow_init_metrics(bd_bigdata_t *bigdata, uint8_t dir, double ts);
static int flow_process_metrics(bd_bigdata_t *bigdata, double dir, double ts);

static char *sockaddr_storage_to_string(struct sockaddr_storage *ptr, char *space,
    int spacelen);

Flow *flow_per_packet(bd_bigdata_t *bigdata) {

    /* get the thread local data */
    bd_thread_local_t *local_data = (bd_thread_local_t *)bigdata->tls;

    double ts = trace_get_seconds(bigdata->packet);
    uint8_t dir;
    bool is_new = false;
    libtrace_ip_t *ip = NULL;
    uint16_t l3_type;

    /* Libflowmanager only deals with IP traffic, so ignore anything
     * that is not ipv4 or ipv6 */
    ip = (libtrace_ip_t *)trace_get_layer3(bigdata->packet, &l3_type, NULL);
    if (l3_type != TRACE_ETHERTYPE_IP && l3_type != TRACE_ETHERTYPE_IPV6) {
        return NULL;
    }
    /* ignore packets with no ip header */
    if (ip == NULL) {
        return NULL;
    }

    /* Get the direction of the packet */
    dir = bd_get_packet_direction(bigdata);
    /* Ignore packets with a invalid direction */
    if (dir != 0 && dir != 1) {
        return NULL;
    }

    /* Match the packet to a Flow - this will create a new flow if
     * there is no matching flow already in the Flow map and set the
     * is_new flag to true. */
    bigdata->flow = local_data->flow_manager->matchPacketToFlow(bigdata->packet,
        dir, &is_new);

    /* Libflowmanager did not like something about that packet - best to
     * just ignore it and carry on */
    if (bigdata->flow == NULL) {
        return NULL;
    }

    /* If this is a new flow, metrics need to be allocated for it */
    if (is_new) {
        flow_init_metrics(bigdata, dir, ts);
    }

    /* update metrics for the flow */
    flow_process_metrics(bigdata, dir, ts);

    /* update expiry time for this flow */
    local_data->flow_manager->updateFlowExpiry(bigdata->flow, bigdata->packet,
        dir, ts);

    return bigdata->flow;
}

static int flow_init_metrics(bd_bigdata_t *bigdata, uint8_t dir, double ts) {

    // create flow record for the flow
    bd_flow_record_t *flow_record = (bd_flow_record_t *)malloc(sizeof(bd_flow_record_t));
    if (flow_record == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. flow_init_metrics()\n");
        exit(BD_OUTOFMEMORY);
    }

    // Make sure to set the ss_family if no source or destination address was found
    if (trace_get_source_address(bigdata->packet, (struct sockaddr *)
        &(flow_record->src_ip)) == NULL) {

        flow_record->src_ip.ss_family = AF_UNSPEC;
    }
    if (trace_get_destination_address(bigdata->packet, (struct sockaddr *)
        &(flow_record->dst_ip)) == NULL) {

        flow_record->dst_ip.ss_family = AF_UNSPEC;
    }

    flow_record->src_port = trace_get_source_port(bigdata->packet);
    flow_record->dst_port = trace_get_destination_port(bigdata->packet);
    flow_record->start_ts = ts;
    flow_record->ttfb = 0;
    flow_record->end_ts = ts;
    flow_record->init_dir = dir;
    flow_record->in_packets = 0;
    flow_record->out_packets = 0;
    flow_record->in_bytes = 0;
    flow_record->out_bytes = 0;
    lpi_init_data(&flow_record->lpi);
    flow_record->lpi_module = NULL;

    // link flow record to the flow
    bigdata->flow->extension = flow_record;

    return 0;
}

static int flow_process_metrics(bd_bigdata_t *bigdata, double dir, double ts) {

    // get the flow record
    bd_flow_record_t *flow_record = (bd_flow_record_t *)bigdata->flow->extension;

    flow_record->end_ts = ts;
    int lpi_updated;

    if (dir == 0) {
        flow_record->out_packets += 1;
        flow_record->out_bytes += trace_get_payload_length(bigdata->packet);
    } else {
        flow_record->in_packets += 1;
        flow_record->in_bytes += trace_get_payload_length(bigdata->packet);
    }

    /* update libprotoident */
    lpi_updated = lpi_update_data(bigdata->packet, &flow_record->lpi,
        flow_record->init_dir);

    /* the lpi_module is only NULL when this is a new flow */
    if (flow_record->lpi_module == NULL) {
        /* try guess the protocol for the flow */
        flow_record->lpi_module = lpi_guess_protocol(&flow_record->lpi);

        /* Trigger the flowstart event */
        bd_callback_trigger_flowstart(bigdata);

    /* Otherwise if this is not a new flow but lpi has updated */
    } else if (lpi_updated) {

        /* can we assume when libprotoident updates we can calculate
         * the time to first byte?? */
        flow_record->ttfb = flow_record->end_ts - flow_record->start_ts;

        /* keep track of the old protocol */
        lpi_protocol_t oldproto = flow_record->lpi_module->protocol;

        /* Now guess the new protocol with the newly supplied information */
        flow_record->lpi_module = lpi_guess_protocol(&flow_record->lpi);

        /* If the protocol has changed generate a protocol updated event */
        if (oldproto != flow_record->lpi_module->protocol) {

            /* Trigger the event */
            bd_callback_trigger_protocol_updated(bigdata, oldproto,
                flow_record->lpi_module->protocol);

        }
    }

    return 0;
}

int flow_expire(bd_bigdata_t *bigdata) {

    // get needed information from the bigdata structure
    bd_thread_local_t *local = (bd_thread_local_t *)bigdata->tls;

    FlowManager *fm = local->flow_manager;
    Flow *expired_flow;

    // keep track of the current flow
    Flow *flow = bigdata->flow;

    while ((expired_flow = fm->expireNextFlow(trace_get_seconds(bigdata->packet),
        false)) != NULL) {

        // Gain access to the flow metrics
        bd_flow_record_t *flow_record = (bd_flow_record_t *)expired_flow->extension;

        /* update the flow in the bigdata structure for the current flow */
        bigdata->flow = expired_flow;

        /* trigger the flowend event */
        bd_callback_trigger_flowend(bigdata);

        // Free the metrics structure and release the flow to libflowmanager
        free(flow_record);
        fm->releaseFlow(expired_flow);
    }

    // restore the current flow
    bigdata->flow = flow;

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

    if (flow == NULL) {
        return NULL;
    }

    if (dst == NULL) {
        return NULL;
    }

    if (flow->extension == NULL) {
        return NULL;
    }

    bd_flow_record_t *flow_record = (bd_flow_record_t *)flow->extension;
    memcpy(dst, &(flow_record->dst_ip), sizeof(struct sockaddr_storage));

    return dst;
}

char *bd_flow_get_destination_ip_string(Flow *flow, char *space, int spacelen) {

    if (flow == NULL) {
        return NULL;
    }

    struct sockaddr_storage dst_ip;

    if (bd_flow_get_destination_ip(flow, &dst_ip) == NULL) {
        return NULL;
    }

    sockaddr_storage_to_string(&dst_ip, space, spacelen);

    return space;


}

char *bd_flow_get_source_ip_string(Flow *flow, char *space, int spacelen) {

    if (flow == NULL) {
        return NULL;
    }

    struct sockaddr_storage src_ip;

    if (bd_flow_get_source_ip(flow, &src_ip) == NULL) {
        return NULL;
    }

    sockaddr_storage_to_string(&src_ip, space, spacelen);

    return space;

}

lpi_protocol_t bd_flow_get_protocol(Flow *flow) {

    if (flow == NULL) {
        fprintf(stderr, "NULL flow. func. bd_flow_get_protocol()\n");
        return LPI_PROTO_UNKNOWN;
    }

    bd_flow_record_t *flow_rec = (bd_flow_record_t *)flow->extension;

    return flow_rec->lpi_module->protocol;
}

lpi_category_t bd_flow_get_category(Flow *flow) {

    if (flow == NULL) {
        fprintf(stderr, "NULL flow. func. bd_flow_get_category()\n");
        return LPI_CATEGORY_UNKNOWN;
    }

    bd_flow_record_t *flow_rec = (bd_flow_record_t *)flow->extension;

    return flow_rec->lpi_module->category;
}

lpi_module_t *bd_flow_get_lpi_module(Flow *flow) {

    if (flow == NULL) {
        fprintf(stderr, "NULL flow. func. bd_flow_get_lpi_module()\n");
        return NULL;
    }

    bd_flow_record_t *flow_rec = (bd_flow_record_t *)flow->extension;

    return flow_rec->lpi_module;
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

/* Returns the flow for the current packet */
Flow *bd_flow_get(bd_bigdata_t *bigdata) {
     return bigdata->flow;
}

bd_flow_record_t *bd_flow_get_record(Flow *flow) {

    if (flow == NULL) {
        fprintf(stderr, "NULL flow. func. bd_flow_get_record()\n");
        return NULL;
    }

    return (bd_flow_record_t *)flow->extension;
}

double bd_flow_get_duration(Flow *flow) {

    bd_flow_record_t *rec = NULL;

    if ((bd_flow_get_record(flow)) != NULL) {
        return rec->end_ts - rec->start_ts;
    }

    return 0;
}

uint64_t bd_flow_get_id(Flow *flow) {

    if (flow == NULL) {
        return 0;
    }

    return flow->id.get_id_num();
}

struct timeval bd_flow_get_start_timeval(Flow *flow) {

    struct timeval tv;
    bd_flow_record_t *flow_rec;

    tv.tv_sec = -1;
    tv.tv_usec = -1;

    if (flow == NULL) {
        fprintf(stderr, "NULL flow. func. bd_flow_get_start_timeval()\n");
        return tv;
    }

    if ((flow_rec = bd_flow_get_record(flow)) != NULL) {
        tv.tv_sec = (uint32_t)flow_rec->start_ts;
        tv.tv_usec = (uint32_t)(((flow_rec->start_ts - tv.tv_sec) * 1000000)/UINT_MAX);
    }

    return tv;
}

uint64_t bd_flow_get_start_time_milliseconds(Flow *flow) {

    if (flow == NULL) {
        fprintf(stderr, "NULL flow. func. bd_flow_get_end_time_milliseconds()\n");
        return 0;
    }

    struct timeval tv = bd_flow_get_start_timeval(flow);

    return (tv.tv_sec * (uint64_t)1000) + (tv.tv_usec / 1000);
}

struct timeval bd_flow_get_end_timeval(Flow *flow) {

    struct timeval tv;
    bd_flow_record_t *flow_rec;

    tv.tv_sec = -1;
    tv.tv_usec = -1;

    if (flow == NULL) {
        fprintf(stderr, "NULL flow. func. bd_flow_get_end_timeval()\n");
        return tv;
    }

    if ((flow_rec = bd_flow_get_record(flow)) != NULL) {
        tv.tv_sec = (uint32_t)flow_rec->end_ts;
        tv.tv_usec = (uint32_t)(((flow_rec->end_ts - tv.tv_sec) * 1000000)/UINT_MAX);
    }

    return tv;
}

uint64_t bd_flow_get_end_time_milliseconds(Flow *flow) {

    if (flow == NULL) {
        fprintf(stderr, "NULL flow. func. bd_flow_get_end_time_milliseconds()\n");
        return 0;
    }

    struct timeval tv = bd_flow_get_end_timeval(flow);

    return (tv.tv_sec * (uint64_t)1000) + (tv.tv_usec / 1000);
}

double bd_flow_get_time_to_first_byte(Flow *flow) {

    bd_flow_record_t *flow_record = bd_flow_get_record(flow);

    /* invalid flow just return 0? */
    if (flow_record == NULL) {
        return 0;
    }

    return flow_record->ttfb;
}

/* PRIVATE FUNCTIONS */
static char *sockaddr_storage_to_string(struct sockaddr_storage *ptr, char *space,
    int spacelen) {

    if (!ptr) { return NULL; }
    if (!space) { return NULL; }
    if (spacelen <= 0) { return NULL; }


    if (ptr->ss_family == AF_INET) {

        struct sockaddr_in *v4 = (struct sockaddr_in *)ptr;
        inet_ntop(AF_INET, &(v4->sin_addr), space, spacelen);

    } else if (ptr->ss_family == AF_INET6) {

        struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ptr;
        inet_ntop(AF_INET6, &(v6->sin6_addr), space, spacelen);

    } else {

        space[0] = '\0';

    }

    return space;
}
