#include "bigdata.h"

#include <libtrace_parallel.h>

#include <yaml.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "bigdata_flow.c"

// Capture modules
#include "module_dns.c"
#include "module_http.c"

// database modules
#include "influxdb.h"

// this is only here for register_event. Can i remove it somehow??
bigdata_global_t *global_data;

void libtrace_cleanup(libtrace_t *trace, libtrace_callback_set_t *processing,
    libtrace_callback_set_t *reporter) {

}

/* Called when a processing thread is started before any packets are read
 * return a pointer to the threads local storage */
static void *start_processing(libtrace_t *trace, libtrace_thread_t *thread,
    void *global) {

    // create thread local storage
    bigdata_local_t *local = (bigdata_local_t *)malloc(sizeof(bigdata_local_t));
    if (local == NULL) {
        fprintf(stderr, "Unable to allocate memory\n");
        return NULL;
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

    return local;
}

libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *thread,
    void *global, void *tls, libtrace_packet_t *packet) {

    ltbigdata_event_handlers *handler = NULL;

    // Get global and thread local data
    bigdata_global_t *global_data = (bigdata_global_t *)global;
    bigdata_local_t *local_data = (bigdata_local_t *)tls;

    double ts = trace_get_seconds(packet);

    // Pull out some common fields within the packet
    int src_port = trace_get_source_port(packet);
    int dst_port = trace_get_destination_port(packet);

    // pass packet into the flow manager
    flow_per_packet(trace, packet, global_data, local_data);

    // call handlers that want every packet
    handler = global_data->listeners[ALL];
    for (; handler != NULL; handler = handler->next) {
        handler->cb(trace, packet, local_data);
    }

    // Apply BPF filters to packets passing matched packets to handlers
    handler = global_data->listeners[FILTER];
    for (; handler != NULL; handler = handler->next) {
        // Apply the filter
        if (trace_apply_filter(handler->filter, packet)) {
            handler->cb(trace, packet, local_data);
        }
    }

    /* Expire all suitably idle flows. Note: this will export expired flow metrics */
    flow_expire(trace, packet, global_data, local_data);

    return packet;
}

int parse_config(char *filename) {
    FILE *fd;
    yaml_parser_t parser;
    yaml_event_t event;;

    // try open the config file
    if ((fd = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "Failed to open config file %s\n", filename);
	return errno;
    }

    // create the parser object
    yaml_parser_initialize(&parser);

    yaml_parser_set_input_file(&parser, fd);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "Failed to parse config file %d\n", parser.error);
            exit(EXIT_FAILURE);
        }

        switch (event.type) {
            case YAML_NO_EVENT: puts("No event!"); break;
            /* Stream start/end */
            case YAML_STREAM_START_EVENT: puts("STREAM START"); break;
            case YAML_STREAM_END_EVENT:   puts("STREAM END");   break;
            /* Block delimeters */
            case YAML_DOCUMENT_START_EVENT: puts("<b>Start Document</b>"); break;
            case YAML_DOCUMENT_END_EVENT:   puts("<b>End Document</b>");   break;
            case YAML_SEQUENCE_START_EVENT: puts("<b>Start Sequence</b>"); break;
            case YAML_SEQUENCE_END_EVENT:   puts("<b>End Sequence</b>");   break;
            case YAML_MAPPING_START_EVENT:  puts("<b>Start Mapping</b>");  break;
            case YAML_MAPPING_END_EVENT:    puts("<b>End Mapping</b>");    break;
            /* Data */
            case YAML_ALIAS_EVENT:  printf("Got alias (anchor %s)\n", event.data.alias.anchor); break;
            case YAML_SCALAR_EVENT: printf("Got scalar (value %s)\n", event.data.scalar.value); break;
        }

        if (event.type != YAML_STREAM_END_EVENT) {
            yaml_event_delete(&event);
        }

    } while (event.type != YAML_STREAM_END_EVENT);

    yaml_event_delete(&event);
    yaml_parser_delete(&parser);
    fclose(fd);
    return 0;
}

int main(int argc, char *argv[]) {

    /* Initialise libprotoident */
    if (lpi_init_library() == -1) {
        fprintf(stderr, "Unable to initialise libprotoident\n");
        return 1;
    }

    /* Create thread global data */
    global_data = (bigdata_global_t *)
        malloc(sizeof(bigdata_global_t));
    if (global_data == NULL) {
        fprintf(stderr, "Unable to allocate memory for global data\n");
        return 1;
    }
    global_data->listeners = (ltbigdata_event_handlers**)
        malloc(sizeof(ltbigdata_event_handlers)*NUM_EVENTS);
    if (global_data->listeners == NULL) {
        fprintf(stderr, "Unable to allocate memory for event listeners\n");
        return 1;
    }
    if (pthread_mutex_init(&global_data->lock, NULL) != 0) {
        printf("\n mutex init failed\n");
        return 1;
    }

    //format_dns_init();
    //format_http_init();

    libtrace_t *trace = NULL;
    libtrace_callback_set_t *processing = NULL;
    libtrace_callback_set_t *reporter = NULL;

    trace = trace_create(argv[1]);
    if (trace_is_err(trace)) {
        trace_perror(trace, "Unable to open capture point");
        libtrace_cleanup(trace, processing, reporter);
        return 1;
    }

    trace_set_reporter_thold(trace, 1);
    // Send tick message once per second
    trace_set_tick_interval(trace, 1000);

    trace_set_combiner(trace, &combiner_ordered, (libtrace_generic_t){0});
    // Setup a single thread
    trace_set_perpkt_threads(trace, 4);
    // Using this hasher will keep all packets related to a flow on the same thread
    trace_set_hasher(trace, HASHER_BIDIRECTIONAL, NULL, NULL);

    // setup processing callbacks
    processing = trace_create_callback_set();
    trace_set_starting_cb(processing, start_processing);
    //trace_set_first_packet_cb(processing, first_packet);
    //trace_set_stopping_cb(processing, fin_local);
    trace_set_packet_cb(processing, per_packet);
    //trace_set_tick_interval_cb(processing, per_tick);

    // setup report thread
    reporter = trace_create_callback_set();
    //trace_set_starting_callback(reporter, init_reporter);
    //trace_set_result_callback(reporter, report_results);
    //trace_set_stopping_cb(reporter, end_reporter);

    // start the trace
    if (trace_pstart(trace, global_data, processing, reporter) == -1) {
        trace_perror(trace, "Unable to start packet capture");
        libtrace_cleanup(trace, processing, reporter);
        return 1;
    }

    trace_join(trace);
    /*if (trace_is_err(trace)) {
        trace_perror(trace, "Unable to read packets");
        libtrace_cleanup(trace, processing, reporter);
        return 1;
    }

    libtrace_cleanup(trace, processing, reporter);*/
    return 0;
}

int ltbigdata_register_event(bigdata_event event, callback cb, const char *filter) {
    ltbigdata_event_handlers *handlers = global_data->listeners[event];

    /* obtain lock for global data */
    pthread_mutex_lock(&global_data->lock);

    // No handlers exist for this event
    if (handlers == NULL) {
        if (!(handlers = (ltbigdata_event_handlers*)
            malloc(sizeof(ltbigdata_event_handlers)))) {
            fprintf(stderr, "Unable to allocate memory");
            pthread_mutex_unlock(&global_data->lock);
            return 1;
        }

        handlers->cb = cb;
        handlers->filter = NULL;
        if (filter != NULL) { handlers->filter = trace_create_filter(filter); }
        handlers->next = NULL;
        global_data->listeners[event] = handlers;

    } else {
        while (handlers->next != NULL) {
            handlers = handlers->next;

            // Check this handler is not allready registered
            if (handlers->cb == cb) {
                pthread_mutex_unlock(&global_data->lock);
                return 0;
            }
        }

        ltbigdata_event_handlers *t;
        if (!(t = (ltbigdata_event_handlers*)
            malloc(sizeof(ltbigdata_event_handlers)))) {
            fprintf(stderr, "Unable to allocate memory");
            pthread_mutex_unlock(&global_data->lock);
            return 1;
        }

        t->cb = cb;
        t->filter = NULL;
        if (filter != NULL) { t->filter = trace_create_filter(filter); }
        t->next = NULL;

        handlers->next = t;
    }

    pthread_mutex_unlock(&global_data->lock);

    return 0;
}
