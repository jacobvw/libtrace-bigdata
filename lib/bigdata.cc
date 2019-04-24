#include "bigdata.h"

#include <libtrace_parallel.h>

#include <yaml.h>

#include <iostream>
#include <list>
#include <iterator>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "bigdata_flow.c"

// Capture modules
#include "module_dns.cc"
#include "module_http.c"
#include "module_influxdb.c"
#include "module_port.cc"

#define RESULT_SET_INIT_SIZE 20
#define RESULT_SET_INC_SIZE 10

// this is only here for register_event. Can i remove it somehow??
bd_global_t *global_data;


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

    // gain access to global data
    bd_global_t *global_data = (bd_global_t *)global;

    // create thread local storage
    bd_thread_local_t *local = (bd_thread_local_t *)malloc(sizeof(bd_thread_local_t));
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

    // call handlers to modules that need initialise some event local data
    bd_cb_set *cbs = global_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->start_cb != NULL) {
            cbs->mls = cbs->start_cb(local);
        }
    }


    return local;
}

libtrace_packet_t *per_packet(libtrace_t *trace, libtrace_thread_t *thread,
    void *global, void *tls, libtrace_packet_t *packet) {

    Flow *flow = NULL;
    int ret = 0;

    // Get global and thread local data
    bd_global_t *global_data = (bd_global_t *)global;

    // pass packet into the flow manager
    flow = flow_per_packet(trace, packet, global, tls);

    bd_cb_set *cbs = global_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->packet_cb != NULL) {
            if (cbs->filter != NULL) {
                if (trace_apply_filter(cbs->filter, packet)) {
                    cbs->packet_cb(trace, packet, flow, tls, cbs->mls);
                }
            } else {
                cbs->packet_cb(trace, packet, flow, tls, cbs->mls);
            }
        }
    }

    /* Expire all suitably idle flows. Note: this will export expired flow metrics */
    flow_expire(trace, packet, global, tls);

    return packet;
}

static void stop_processing(libtrace_t *trace, libtrace_thread_t *thread, void *global,
    void *tls) {

    bd_cb_set *cbs = global_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->stop_cb != NULL) {
            cbs->stop_cb(tls, cbs->mls);
        }
    }


    // cleanup thread local storage, flow managers etc..
}

bd_result_set_t *bd_result_set_create(const char *mod) {
    // create result set structure
    bd_result_set_t *res = (bd_result_set_t *)malloc(sizeof(bd_result_set_t));
    if (res == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_create_output_result_set()\n");
        return NULL;
    }
    // allocate space for results
    res->results = (bd_result_t *)malloc(sizeof(bd_result_t)*RESULT_SET_INIT_SIZE);
    if (res->results == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_create_output_result_set()\n");
        return NULL;
    }
    res->module = mod;
    res->num_results = 0;
    res->allocated_results = RESULT_SET_INIT_SIZE;
    res->timestamp = 0;

    return res;
}
int bd_result_set_insert(bd_result_set_t *result_set, const char *key, bd_record_type dtype,
    bd_record_value value) {

    if (result_set == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_insert()\n");
        return 1;
    }

    // re-allocated more result structures if needed
    if (result_set->num_results >= result_set->allocated_results) {
        result_set->allocated_results += RESULT_SET_INC_SIZE;
        result_set->results = (bd_result_t *)realloc(result_set->results,
            sizeof(bd_result_t)*result_set->allocated_results);
        if (result_set->results == NULL) {
            fprintf(stderr, "Unable to allocate memory. func. bd_result_set_insert()\n");
            return 1;
        }
    }

    result_set->results[result_set->num_results].key = key;
    result_set->results[result_set->num_results].type = dtype;
    result_set->results[result_set->num_results].value = value;

    result_set->num_results += 1;

    return 0;

}
int bd_result_set_insert_string(bd_result_set_t *result_set, const char *key,
    const char *value) {

    union bd_record_value val;
    val.data_string = strdup(value);
    if (val.data_string == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_result_set_insert_string()\n");
        return 1;
    }

    bd_result_set_insert(result_set, key, BD_TYPE_STRING, val);

    return 0;
}
int bd_result_set_insert_float(bd_result_set_t *result_set, const char *key,
    float value) {

    union bd_record_value val;
    val.data_float = value;
    bd_result_set_insert(result_set, key, BD_TYPE_FLOAT, val);

    return 0;
}
int bd_result_set_insert_double(bd_result_set_t *result_set, const char *key,
    double value) {

    union bd_record_value val;
    val.data_double = value;
    bd_result_set_insert(result_set, key, BD_TYPE_DOUBLE, val);

    return 0;
}
int bd_result_set_insert_int(bd_result_set_t *result_set, const char *key,
    int64_t value) {

    union bd_record_value val;
    val.data_int = value;
    bd_result_set_insert(result_set, key, BD_TYPE_INT, val);

    return 0;
}
int bd_result_set_insert_uint(bd_result_set_t *result_set, const char *key,
    uint64_t value) {

    union bd_record_value val;
    val.data_uint = value;
    bd_result_set_insert(result_set, key, BD_TYPE_UINT, val);

    return 0;
}
int bd_result_set_insert_bool(bd_result_set_t *result_set, const char *key,
    bool value) {

    union bd_record_value val;
    val.data_bool = value;
    bd_result_set_insert(result_set, key, BD_TYPE_BOOL, val);

    return 0;
}
int bd_result_set_set_timestamp(bd_result_set_t *result_set, double timestamp) {
    result_set->timestamp = timestamp;
    return 0;
}
int bd_result_set_output(bd_result_set_t *result) {

    int ret;

    if (result == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_output()\n");
        return 1;
    }

    bd_cb_set *cbs = global_data->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->output_cb != NULL) {
            ret = cbs->output_cb(cbs->mls, result);
            // if ret isnt 0 output failed so store and output and try again later??
        }
    }

    return 0;
}
int bd_result_set_free(bd_result_set_t *result_set) {

    int i;

    if (result_set == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_free()\n");
        return 1;
    }

    if (result_set->results != NULL) {
        // iterate over each clearing any strings
        for (i=0; i<result_set->num_results; i++) {
            if (result_set->results[i].type == BD_TYPE_STRING) {
                if (result_set->results[i].value.data_string != NULL) {
                    free(result_set->results[i].value.data_string);
                }
            }
        }
        free(result_set->results);
    }

    free(result_set);

    return 0;
}

int parse_config(char *filename) {
    FILE *fd;
    yaml_parser_t parser;
    yaml_event_t event;
    yaml_document_t document;

    // try open the config file
    if ((fd = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "Failed to open config file %s\n", filename);
	return -1;
    }

    // create the parser object
    yaml_parser_initialize(&parser);
    yaml_parser_set_input_file(&parser, fd);

    if (!yaml_parser_load(&parser, &document)) {
        fprintf(stderr, "Invalid config file %s\n", filename);
        return -1;
    }

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            fprintf(stderr, "Failed to parse config file %d\n", parser.error);
            exit(EXIT_FAILURE);
        }

        switch (event.type) {
            case YAML_NO_EVENT: puts("No event!"); break;
            // Stream start/end
            case YAML_STREAM_START_EVENT: puts("STREAM START"); break;
            case YAML_STREAM_END_EVENT:   puts("STREAM END");   break;
            // Block delimeters
            case YAML_DOCUMENT_START_EVENT: puts("<b>Start Document</b>"); break;
            case YAML_DOCUMENT_END_EVENT:   puts("<b>End Document</b>");   break;
            case YAML_SEQUENCE_START_EVENT: puts("<b>Start Sequence</b>"); break;
            case YAML_SEQUENCE_END_EVENT:   puts("<b>End Sequence</b>");   break;
            case YAML_MAPPING_START_EVENT:  puts("<b>Start Mapping</b>");  break;
            case YAML_MAPPING_END_EVENT:    puts("<b>End Mapping</b>");    break;
            // Data
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

    parse_config(argv[2]);

    /* Initialise libprotoident */
    if (lpi_init_library() == -1) {
        fprintf(stderr, "Unable to initialise libprotoident\n");
        return -1;
    }

    /* Create global data */
    global_data = (bd_global_t *)malloc(sizeof(bd_global_t));
    if (global_data == NULL) {
        fprintf(stderr, "Unable to allocate memory for global data\n");
        return -1;
    }
    if (pthread_mutex_init(&global_data->lock, NULL) != 0) {
        printf("\n mutex init failed\n");
        return -1;
    }
    global_data->callbacks = NULL;

    module_influxdb_init();
    module_dns_init();
    //module_port_init();
    //module_http_init();

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
    // Setup number of processing threads
    trace_set_perpkt_threads(trace, 4);
    // Using this hasher will keep all packets related to a flow on the same thread
    trace_set_hasher(trace, HASHER_BIDIRECTIONAL, NULL, NULL);

    // setup processing callbacks
    processing = trace_create_callback_set();
    trace_set_starting_cb(processing, start_processing);
    //trace_set_first_packet_cb(processing, first_packet);
    trace_set_packet_cb(processing, per_packet);
    trace_set_stopping_cb(processing, stop_processing);
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
    if (trace_is_err(trace)) {
        trace_perror(trace, "Unable to read packets");
        libtrace_cleanup(trace, processing, reporter);
        return -1;
    }

    libtrace_cleanup(trace, processing, reporter);

    return 0;
}

bd_cb_set *bd_create_cb_set() {
    bd_cb_set *cbset = (bd_cb_set *)calloc(1, sizeof(bd_cb_set));
    if (cbset == NULL) {
        fprintf(stderr, "Unable to create callback set. func. bd_create_cb_set()\n");
        return NULL;
    }
    return cbset;
}
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

    pthread_mutex_unlock(&global_data->lock);
    return 0;
}
int bd_add_filter_to_cb_set(bd_cb_set *cbset, const char *filter) {
    cbset->filter = trace_create_filter(filter);
    return 0;
}
