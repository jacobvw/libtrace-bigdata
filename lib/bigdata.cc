#include "bigdata.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static void init_modules(bd_bigdata_t *bigdata) {
    module_statistics_init(bigdata);
    module_protocol_statistics_init(bigdata);
    module_dns_init(bigdata);
    module_http_init(bigdata);
    module_influxdb_init(bigdata);
    module_elasticsearch_init(bigdata);
    module_bgp_init(bigdata);
#ifdef HAVE_LIBRDKAFKA
    module_kafka_init(bigdata);
#endif
    module_flow_statistics_init(bigdata);
#ifdef HAVE_LIBMAXMINDDB
    module_maxmind_init(bigdata);
#endif
}

static void libtrace_cleanup(libtrace_t *trace, libtrace_callback_set_t *processing,
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

static bd_bigdata_t *init_bigdata(bd_bigdata_t *bigdata, libtrace_t *trace, libtrace_thread_t *thread,
    libtrace_packet_t *packet, Flow *flow, bd_global_t *global, void *tls) {

    bigdata->trace = trace;
    bigdata->thread = thread;
    bigdata->packet = packet;
    bigdata->flow = flow;
    bigdata->global = global;
    bigdata->tls = tls;

    /* initialize cached fields */
    bigdata->cache.packet_direction = -1;
    bigdata->cache.ip_local = -1;

    return bigdata;
}

/* Called when a processing thread is started before any packets are read
 * return a pointer to the threads local storage */
static void *start_processing(libtrace_t *trace, libtrace_thread_t *thread,
    void *global) {

    // create the bigdata structure
    bd_bigdata_t bigdata;

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

    // create storage space for each modules countdown tickrate
    local->c_tickrate = (uint64_t *)malloc(sizeof(uint64_t) * g_data->callback_count);
    if (local->c_tickrate == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. start_processing()\n");
        exit(BD_OUTOFMEMORY);
    }
    // initialise the current tickrates
    for (int i = 0; i < g_data->callback_count; i++) {
        local->c_tickrate[i] = 0;
    }

    // init bigdata structure
    init_bigdata(&bigdata, trace, thread, NULL, NULL, (bd_global_t *)global,
        (void *)local);

    /* trigger packet processing thread starting event for input plugins to init
     * some local storage
     */
    bd_callback_trigger_starting(&bigdata);

    return local;
}

static libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *thread,
    void *global, void *tls, libtrace_packet_t *packet) {

    // create bigdata structure
    bd_bigdata_t bigdata;
    init_bigdata(&bigdata, trace, thread, packet, NULL, (bd_global_t *)global, tls);

    // update the bigdata structure with flow information and trigger protocol &
    // category events
    if (flow_per_packet(&bigdata) != NULL) {
        bd_flow_record_t *flow_record = (bd_flow_record_t *)bigdata.flow->extension;
        bd_callback_trigger_protocol(&bigdata, flow_record->lpi_module->protocol);
        bd_callback_trigger_category(&bigdata, flow_record->lpi_module->category);
    }

    // trigger packet event
    bd_callback_trigger_packet(&bigdata);

    // Expire all suitably idle flows.
    flow_expire(&bigdata);

    return packet;
}

static void stop_processing(libtrace_t *trace, libtrace_thread_t *thread, void *global,
    void *tls) {

    bd_bigdata_t bigdata;
    bd_thread_local_t *l_data;

    // init the bigdata structure
    init_bigdata(&bigdata, trace, thread, NULL, NULL, (bd_global_t *)global,
        (bd_thread_local_t *)tls);

    /* trigger packet processing thread stopping event */
    bd_callback_trigger_stopping(&bigdata);

    // cast the thread local storage
    l_data = (bd_thread_local_t *)tls;

    // cleanup thread local storage, flow managers, etc.
    if (l_data->mls != NULL) { free(l_data->mls); }
    if (l_data->flow_manager != NULL) { delete(l_data->flow_manager); }
    if (l_data != NULL) { free(l_data); }
}

static void per_tick(libtrace_t *trace, libtrace_thread_t *thread, void *global,
    void *tls, uint64_t tick) {

    // create bigdata structure
    bd_bigdata_t bigdata;
    init_bigdata(&bigdata, trace, thread, NULL, NULL, (bd_global_t *)global, tls);

    // trigger the tick events
    bd_callback_trigger_tick(&bigdata, tick);

}

static void *reporter_starting(libtrace_t *trace, libtrace_thread_t *thread,
    void *global) {

    bd_bigdata_t bigdata;

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

    init_bigdata(&bigdata, trace, thread, NULL, NULL, (bd_global_t *)global,
        (void *)local);

    /* Trigger reporter starting event */
    bd_callback_trigger_reporter_starting(&bigdata);

    return local;
}

static void reporter_result(libtrace_t *trace, libtrace_thread_t *thread,
    void *global, void *tls, libtrace_result_t *res) {

    // get the generic structure holding the result
    libtrace_generic_t gen = res->value;
    // cast back to a result wrapper
    bd_result_set_wrap_t *result = (bd_result_set_wrap_t *)gen.ptr;

    // create bigdata structure for callbacks
    bd_bigdata_t bigdata;
    init_bigdata(&bigdata, trace, thread, NULL, NULL, (bd_global_t *)global, tls);

    // if the result needs to be sent to the modules combiner do that
    if (result->type == BD_RESULT_COMBINE) {
       // trigger combiner callback
       bd_callback_trigger_combiner(&bigdata, result);
    } else if (result->type == BD_RESULT_PUBLISH) {
       // trigger output filter callback
       bd_callback_trigger_reporter_filter(&bigdata, (bd_result_set_t *)result->value);

       // trigger output callback
       bd_callback_trigger_output(&bigdata, (bd_result_set_t *)result->value);
    }

    // cleanup the result wrapper
    bd_result_set_wrap_free(result);
}

static void reporter_stopping(libtrace_t *trace, libtrace_thread_t *thread,
    void *global, void *tls) {

    bd_bigdata_t bigdata;

    // get thread local storage
    bd_thread_local_t *l_data = (bd_thread_local_t *)tls;

    // init bigdata structure
    init_bigdata(&bigdata, trace, thread, NULL, NULL, (bd_global_t *)global,
        (void *)tls);

    // trigger reporter stopping event
    bd_callback_trigger_reporter_stopping(&bigdata);

    // cleanup thread local storage, flow managers, etc.
    if (l_data->mls != NULL) { free(l_data->mls); }
    if (l_data != NULL) { free(l_data); }
}

int main(int argc, char *argv[]) {

    bd_bigdata_t bigdata;
    bd_global_t global;

    /* ensure only 2 args, app name and config file */
    if (argc != 2) {
        fprintf(stderr, "Usage: %s configFile\n", argv[0]);
        exit(BD_INVALID_PARAMS);
    }

    /* Initialise libprotoident */
    if (lpi_init_library() == -1) {
        fprintf(stderr, "Unable to initialise libprotoident\n");
        exit(BD_STARTUP_ERROR);
    }

    /* init global data */
    if (pthread_mutex_init(&(global.lock), NULL) != 0) {
        printf("\n mutex init failed\n");
        exit(BD_STARTUP_ERROR);
    }
    global.callbacks = NULL;
    global.callback_count = 0;

    /* init bigdata structure */
    init_bigdata(&bigdata, NULL, NULL, NULL, NULL, &global, NULL);

    // initialise modules
    init_modules(&bigdata);

    // parse configuration
    global.config = parse_config(argv[1], &global);
    if (global.config == NULL) {
        exit(BD_INVALID_CONFIG);
    }

    libtrace_t *trace = NULL;
    libtrace_callback_set_t *processing = NULL;
    libtrace_callback_set_t *reporter = NULL;

    trace = trace_create(global.config->interface);
    if (trace_is_err(trace)) {
        trace_perror(trace, "Unable to open capture point");
        libtrace_cleanup(trace, processing, reporter);
        exit(BD_INVALID_INTERFACE);
    }

    trace_set_reporter_thold(trace, 1);
    // Send tick message once per second
    trace_set_tick_interval(trace, 1000);

    trace_set_combiner(trace, &combiner_unordered, (libtrace_generic_t){0});
    // Setup number of processing threads
    trace_set_perpkt_threads(trace, global.config->processing_threads);

    // Enable the bidirectional hasher if specified by the user.
    if (global.config->enable_bidirectional_hasher) {
        // Using this hasher will keep all packets related to a flow on the same thread
        trace_set_hasher(trace, HASHER_BIDIRECTIONAL, NULL, NULL);
        fprintf(stdout, "Bidirectional Hasher Enabled\n");
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
    if (trace_pstart(trace, &global, processing, reporter) == -1) {
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
