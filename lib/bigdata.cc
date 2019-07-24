#include "bigdata.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

bd_global_t *global_data;

void init_modules() {
    module_statistics_init();
    module_flow_statistics_init();
    module_dns_init();
    module_influxdb_init();
}

void libtrace_cleanup(libtrace_t *trace, libtrace_callback_set_t *processing,
    libtrace_callback_set_t *reporter) {

    if (trace != NULL) {
        trace_destroy(trace);
    }

    if (processing != NULL) {
        trace_destroy_callback_set(processing);
    }

    if (reporter != NULL) {
        trace_destroy_callback_set(reporter);
    }
}

/* Called when a processing thread is started before any packets are read
 * return a pointer to the threads local storage */
static void *start_processing(libtrace_t *trace, libtrace_thread_t *thread,
    void *global) {

    int cb_counter = 0;
    // gain access to global data
    bd_global_t *g_data = (bd_global_t *)global;

    // create thread local storage
    bd_thread_local_t *local = (bd_thread_local_t *)malloc(sizeof(bd_thread_local_t));
    if (local == NULL) {
        fprintf(stderr, "Unable to allocate memory. func start_processing()\n");
        exit(BD_OUTOFMEMORY);
    }

    // create module local storage pointer space
    local->mls = (void **)malloc(sizeof(void *) * g_data->callback_count);
    if (local->mls == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. start_processing()\n");
        exit(BD_OUTOFMEMORY);
    }

    // Setup the flow manager for this thread
    local->flow_manager = new FlowManager();
    bool opt_false = 0;
    lfm_plugin_id_t plugid = LFM_PLUGIN_STANDARD;
    if (local->flow_manager->setConfigOption(LFM_CONFIG_TCP_TIMEWAIT, &opt_false) == 0) {
        fprintf(stderr, "Unable to apply flow config\n");
        return NULL;
    }
    if (local->flow_manager->setConfigOption(LFM_CONFIG_EXPIRY_PLUGIN, &plugid) == 0) {
        fprintf(stderr, "Unable to apply flow config\n");
        return NULL;
    }

    // call handlers to modules that need initialise some event local data
    bd_cb_set *cbs = g_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->start_cb != NULL) {
            local->mls[cb_counter] = cbs->start_cb(local);
        }
        cb_counter += 1;
    }

    // create storage space for each modules countdown tickrate
    local->c_tickrate = (uint64_t *)calloc(1, sizeof(uint64_t) * g_data->callback_count);
    if (local->c_tickrate == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. start_processing()\n");
        exit(BD_OUTOFMEMORY);
    }

    return local;
}

libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *thread,
    void *global, void *tls, libtrace_packet_t *packet) {

    Flow *flow = NULL;
    int ret = 0;
    int cb_counter = 0;

    // Get global and thread local data
    bd_global_t *g_data = (bd_global_t *)global;
    bd_thread_local_t *l_data = (bd_thread_local_t *)tls;

    // pass packet into the flow manager
    flow = flow_per_packet(trace, thread, packet, global, tls);

    // if a flow was not found something has gone wrong
    if (flow) {
        bd_cb_set *cbs = g_data->callbacks;
        for (; cbs != NULL; cbs = cbs->next) {
            if (cbs->packet_cb != NULL) {
                if (cbs->filter != NULL) {
                    if (trace_apply_filter(cbs->filter, packet)) {
                        cbs->packet_cb(trace, thread, flow, packet, tls, l_data->mls[cb_counter]);
                    }
                } else {
                    cbs->packet_cb(trace, thread, flow, packet, tls, l_data->mls[cb_counter]);
                }
            }
            cb_counter += 1;
        }
    }

    // Expire all suitably idle flows.
    flow_expire(trace, thread, packet, global, tls);

    return packet;
}

static void stop_processing(libtrace_t *trace, libtrace_thread_t *thread, void *global,
    void *tls) {

    int cb_counter = 0;
    // get global and thread local storage
    bd_global_t *g_data = (bd_global_t *)global;
    bd_thread_local_t *l_data = (bd_thread_local_t *)tls;

    bd_cb_set *cbs = g_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->stop_cb != NULL) {
            cbs->stop_cb(tls, l_data->mls[cb_counter]);
        }
        cb_counter += 1;
    }

    // cleanup thread local storage, flow managers, etc.
    if (l_data->mls != NULL) { free(l_data->mls); }
    if (l_data->flow_manager != NULL) { delete(l_data->flow_manager); }
    if (l_data != NULL) { free(l_data); }
}




static void per_tick(libtrace_t *trace, libtrace_thread_t *thread, void *global,
    void *tls, uint64_t tick) {

    int cb_counter = 0;
    // get the global data
    bd_global_t *g_data = (bd_global_t *)global;
    // get global configuration
    bd_conf_t *config = g_data->config;
    // get the thread local data
    bd_thread_local_t *l_data = (bd_thread_local_t *)tls;

    // convert ERF timestamp to seconds
    uint64_t timestamp_seconds = tick >> 32;

    bd_cb_set *cbs = g_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->tick_cb != NULL) {

            // c_tickrate will be 0 on the first pass.
            if (l_data->c_tickrate[cb_counter] == 0) {
                // Align the output to nearest boundary.
                // E.G. output interval of 60 seconds will be on the minute boundary:
                // 12:00, 12:01, 12:02 etc.
                if ((timestamp_seconds % cbs->tickrate) == 0) {
                    l_data->c_tickrate[cb_counter] = timestamp_seconds + cbs->tickrate;
                }
            }

            // if the current module is due a tick
            // note: modules receive tick time in seconds
            if (l_data->c_tickrate[cb_counter] <= timestamp_seconds) {
                cbs->tick_cb(trace, thread, tls, l_data->mls[cb_counter], timestamp_seconds);
                l_data->c_tickrate[cb_counter] = timestamp_seconds + cbs->tickrate;
            }
        }
        cb_counter += 1;
    }

    // output some libtrace stats if debug is enabled
    if (config->debug) {
        libtrace_stat_t *stats = trace_create_statistics();
        trace_get_statistics(trace, stats);
        fprintf(stderr, "Accepted %lu packets, Dropped %lu packets\n",
            stats->accepted, stats->dropped);
        free(stats);
    }
}




static void *reporter_starting(libtrace_t *trace, libtrace_thread_t *thread,
    void *global) {

    int cb_counter = 0;
    // gain access to global data
    bd_global_t *g_data = (bd_global_t *)global;

    // create report thread local storage
    bd_rthread_local_t *local = (bd_rthread_local_t *)malloc(sizeof(bd_rthread_local_t));
    if (local == NULL) {
        fprintf(stderr, "Unable to allocate memory. func reporter_starting()\n");
        exit(BD_OUTOFMEMORY);
    }
    // create module local storage pointer space
    local->mls = (void **)malloc(sizeof(void *) * g_data->callback_count);
    if (local->mls == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. reporter_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    // call handlers to modules that need initialise some report module
    // local storage
    bd_cb_set *cbs = g_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->reporter_start_cb != NULL) {
            local->mls[cb_counter] = (void *)cbs->reporter_start_cb(local);
        }
        cb_counter += 1;
    }

    return local;
}

static void reporter_result(libtrace_t *trace, libtrace_thread_t *thread,
    void *global, void *tls, libtrace_result_t *res) {

    int ret;
    int cb_counter = 0;

    // get the generic structure holding the result
    libtrace_generic_t gen = res->value;
    // cast back to a result wrapper
    bd_result_set_wrap_t *result = (bd_result_set_wrap_t *)gen.ptr;

    // create bigdata structure for callbacks
    bd_bigdata_t bigdata;
    bigdata.trace = trace;
    bigdata.thread = thread;
    bigdata.packet = NULL;
    bigdata.flow = NULL;
    bigdata.global = (bd_global_t *)global;
    bigdata.tls = tls;

    // if the result needs to be sent to the modules combiner do that
    if (result->type == BD_RESULT_COMBINE) {
       // trigger combiner callback
       fprintf(stderr, "calling combiner\n");
       bd_callback_trigger_combiner(&bigdata, (bd_result_set_wrap_t *)result);
       fprintf(stderr, "end combiner\n");
    } else if (result->type == BD_RESULT_PUBLISH) {
       // trigger output callback
       bd_callback_trigger_output(&bigdata, (bd_result_set_t *)result->value);
    }

    // cleanup the resultset
    bd_result_set_wrap_free(result);
}

static void reporter_stopping(libtrace_t *trace, libtrace_thread_t *thread,
    void *global, void *tls) {

    int cb_counter = 0;
    // get global and thread local storage
    bd_global_t *g_data = (bd_global_t *)global;
    bd_thread_local_t *l_data = (bd_thread_local_t *)tls;

    // call all reporter stopping callbacks, each module is required to free any
    // module local storage
    bd_cb_set *cbs = g_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->reporter_stop_cb != NULL) {
            cbs->reporter_stop_cb(tls, l_data->mls[cb_counter]);
        }
        cb_counter += 1;
    }

    // cleanup thread local storage, flow managers, etc.
    if (l_data->mls != NULL) { free(l_data->mls); }
    if (l_data != NULL) { free(l_data); }
}


int main(int argc, char *argv[]) {

    /* Initialise libprotoident */
    if (lpi_init_library() == -1) {
        fprintf(stderr, "Unable to initialise libprotoident\n");
        return -1;
    }

    /* Create global data */
    global_data = (bd_global_t *)malloc(sizeof(bd_global_t));
    if (global_data == NULL) {
        fprintf(stderr, "Unable to allocate memory for global data\n");
        exit(BD_OUTOFMEMORY);
    }
    if (pthread_mutex_init(&global_data->lock, NULL) != 0) {
        printf("\n mutex init failed\n");
        return -1;
    }
    global_data->callbacks = NULL;
    global_data->callback_count = 0;

    // initialise modules
    init_modules();

    // parse configuration
    global_data->config = parse_config(argv[1], global_data);

    libtrace_t *trace = NULL;
    libtrace_callback_set_t *processing = NULL;
    libtrace_callback_set_t *reporter = NULL;

    trace = trace_create(global_data->config->interface);
    if (trace_is_err(trace)) {
        trace_perror(trace, "Unable to open capture point");
        libtrace_cleanup(trace, processing, reporter);
        return 1;
    }

    trace_set_reporter_thold(trace, 1);
    // Send tick message once per second
    trace_set_tick_interval(trace, 1000);

    trace_set_combiner(trace, &combiner_unordered, (libtrace_generic_t){0});
    // Setup number of processing threads
    trace_set_perpkt_threads(trace, global_data->config->processing_threads);

    // Enable the bidirectional hasher if specified by the user.
    if (global_data->config->enable_bidirectional_hasher) {
        // Using this hasher will keep all packets related to a flow on the same thread
        trace_set_hasher(trace, HASHER_BIDIRECTIONAL, NULL, NULL);
        fprintf(stdout, "Bidirectional hasher enabled\n");
    }

    // setup processing callbacks
    processing = trace_create_callback_set();
    trace_set_starting_cb(processing, start_processing);
    trace_set_packet_cb(processing, per_packet);
    trace_set_stopping_cb(processing, stop_processing);
    trace_set_tick_interval_cb(processing, per_tick);

    // setup report thread
    reporter = trace_create_callback_set();
    trace_set_starting_cb(reporter, reporter_starting);
    trace_set_result_cb(reporter, reporter_result);
    trace_set_stopping_cb(reporter, reporter_stopping);
    // process reports as soon as they are received
    trace_set_reporter_thold(trace, 1);


    // start the trace
    if (trace_pstart(trace, global_data, processing, reporter) == -1) {
        trace_perror(trace, "Unable to start packet capture");
        libtrace_cleanup(trace, processing, reporter);
        return 1;
    }

    trace_join(trace);
    if (trace_is_err(trace)) {
        trace_perror(trace, "Unable to read packets");
        libtrace_cleanup(trace, processing, reporter);
        return -1;
    }

    libtrace_cleanup(trace, processing, reporter);

    return 0;
}

bd_cb_set *bd_create_cb_set(const char *module_name) {
    bd_cb_set *cbset = (bd_cb_set *)calloc(1, sizeof(bd_cb_set));
    if (cbset == NULL) {
        fprintf(stderr, "Unable to create callback set. func. bd_create_cb_set()\n");
        exit(BD_OUTOFMEMORY);
    }

    // assign the module name
    cbset->name = strdup(module_name);

    // assign default tickrate.
    cbset->tickrate = BIGDATA_TICKRATE;
    cbset->c_tickrate = BIGDATA_TICKRATE;

    return cbset;
}

/* Registers a modules callback functions against libtrace-bigdata
 * params:
 *     bd_cb_set - modules callback set
 * returns:
 *     assigned module ID
 */
int bd_register_cb_set(bd_cb_set *cbset) {
    // obtain lock for global data
    pthread_mutex_lock(&global_data->lock);

    bd_cb_set *tmp = global_data->callbacks;

    if (tmp == NULL) {
       global_data->callbacks = cbset;
    } else {
        while (tmp->next != NULL) {
             tmp = tmp->next;
        }
        tmp->next = cbset;
    }

    // increment callback count
    global_data->callback_count += 1;
    // set modules ID
    cbset->id = global_data->callback_count;

    pthread_mutex_unlock(&global_data->lock);

    return cbset->id;
}
int bd_add_filter_to_cb_set(bd_cb_set *cbset, const char *filter) {
    cbset->filter = trace_create_filter(filter);
    return 0;
}
int bd_add_tickrate_to_cb_set(bd_cb_set *cbset, size_t tickrate) {
    cbset->tickrate = tickrate;
    cbset->c_tickrate = 0;
    return 0;
}

int bd_get_packet_direction(libtrace_packet_t *packet) {

    if (packet == NULL) {
        fprintf(stderr, "NULL packet. func. bd_get_packet_direction()\n");
        return -1;
    }

    if (global_data->config->local_networks_as_direction) {
        struct sockaddr_storage src_addr, dst_addr;
        struct sockaddr *src_ip, *dst_ip;

        src_ip = trace_get_source_address(packet, (struct sockaddr *)&src_addr);
        dst_ip = trace_get_destination_address(packet, (struct sockaddr *)&dst_addr);

        for (int i=0; i<global_data->config->local_subnets_count; i++) {
            bd_network_t *network = global_data->config->local_subnets[i];

            struct sockaddr *address = (struct sockaddr *)&(network->address);
            struct sockaddr *mask = (struct sockaddr *)&(network->mask);

            // ensure both addresses are of the same family
            if (address->sa_family == src_ip->sa_family) {

                if (src_ip->sa_family == AF_INET) {
                    // IPv4
                    struct sockaddr_in *packet_in = (struct sockaddr_in *)src_ip;
                    struct sockaddr_in *network_in = (struct sockaddr_in *)address;
                    struct sockaddr_in *mask_in = (struct sockaddr_in *)mask;

                    struct in_addr *packet_addr = (struct in_addr *)&(packet_in->sin_addr);
                    struct in_addr *network_addr = (struct in_addr *)&(network_in->sin_addr);
                    struct in_addr *mask_addr = (struct in_addr *)&(mask_in->sin_addr);

                    // check source
                    if ((packet_addr->s_addr & mask_addr->s_addr) == network_addr->s_addr) {
                        return 0;
                    }

                    packet_in = (struct sockaddr_in *)dst_ip;
                    packet_addr = (struct in_addr *)&(packet_in->sin_addr);

                    // check destination
                    if ((packet_addr->s_addr & mask_addr->s_addr) == network_addr->s_addr) {
                        return 1;
                    }
                }

                if (src_ip->sa_family == AF_INET6) {
                    // IPv6
                    struct sockaddr_in6 *packet_in = (struct sockaddr_in6 *)src_ip;
                    struct sockaddr_in6 *network_in = (struct sockaddr_in6 *)address;
                    struct sockaddr_in6 *mask_in = (struct sockaddr_in6 *)mask;

                    struct in6_addr *packet_addr = (struct in6_addr *)&(packet_in->sin6_addr);
                    struct in6_addr *network_addr = (struct in6_addr *)&(network_in->sin6_addr);
                    struct in6_addr *mask_addr = (struct in6_addr *)&(mask_in->sin6_addr);

                    uint8_t tmp[16];
                    bool match = 1;

                    // check source
                    for (int i = 0; i < 16; i++) {
                        tmp[i] = packet_addr->s6_addr[i] & mask_addr->s6_addr[i];
                        if (tmp[i] != network_addr->s6_addr[i]) {
                            match = 0;
                        }
                    }
                    if (match) { return 0; }

                    packet_in = (struct sockaddr_in6 *)dst_ip;
                    packet_addr = (struct in6_addr *)&(packet_in->sin6_addr);
                    match = 1;

                    // check destination
                    for (int i = 0; i < 16; i++) {
                        tmp[i] = packet_addr->s6_addr[i] & mask_addr->s6_addr[i];
                        if (tmp[i] != network_addr->s6_addr[i]) {
                            match = 0;
                        }
                    }
                    if (match) { return 1; }

                }
            }
        }
    }

    return trace_get_direction(packet);

}
