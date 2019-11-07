#include "bigdata.h"

/* configuration structure for the plugin */
struct module_MODULENAME_config {
    bd_cb_set *callbacks;
    bool enabled;
};
/* global varible used to read from module configuration */
static struct module_MODULENAME_config *config;

struct module_MODULENAME_storage {
    uint64_t bytes;
    uint64_t http_packets;
    /* create any varibles needed for the analytics here */
    uint64_t last_tick; /* used for reporting results */
};

/* define packet processing threads starting function. This function is used
 * to initialise any storage required for the plugin
 */
void *module_MODULENAME_starting(void *tls) {

    /* create the modules storage */
    struct module_MODULENAME_storage *stor = (struct module_MODULENAME_storage *)
        malloc(sizeof(struct module_MODULENAME_storage));

    /* initialise the module storage */
    stor->bytes = 0;
    stor->http_packets = 0;

    /* return the module storage to the application core. This will now be
     * passed into other callback function as the mls (module local storage)
     * parameter.
     */
    return stor;
}

/* define a function to receive all packets */
int module_MODULENAME_packet(bd_bigdata_t *bigdata, void *tls, void *mls) {

    /* get access to the packet */
    libtrace_packet_t *packet = bd_get_packet(bigdata);

    /* regain access to the module storage defined in the starting function */
    struct module_MODULENAME_storage *stor = (struct module_MODULENAME_storage *)mls;


    /* perform any packet analysis or measurements here,
     * all Libtrace API functions are supported here.
     */
    stor->bytes += trace_get_payload_length(packet)

    return 0;
}

/* define a function to receive only HTTP packets */
int module_MODULENAME_http_packet(bd_bigdata_t *bigdata, void *tls, void *mls) {

    /* regain access to the module storage defined in the starting function */
    struct module_MODULENAME_storage *stor = (struct module_MODULENAME_storage *)mls;

    /* perform any HTTP analysis or measurements here */
    stor->http_packets += 1;

    return 0;
}

/* define a tick function to output the results for each processing thread.
 * Note: each processing thread calls this independantly. */
int module_MODULENAME_tick(bd_bigdata_t *bigdata, void *mls, uint64_t tick) {

    /* regain access to the module storage defined in the starting function */
    struct module_MODULENAME_storage *stor = (struct module_MODULENAME_storage *)mls;

    /* the result can now be combined with results from other processing threads */
    /* first create a structure to copy the result to */
    struct module_MODULENAME_storage *res = (struct module_MODULENAME_storage *)
        malloc(sizeof(struct module_MODULENAME_storage));
    /* now copy the results from stor to res */
    res->bytes = stor->bytes;
    res->http_packets = stor->http_packets;
    /* now post the result to be combined */
    bd_result_combine(trace, thread, res, tick, config->callbacks->id);

    /* clear the module storage for the next round */
    stor->bytes = 0;
    stor->http_packets = 0;

    return 0;
}


/* Because the combining function runs on the reporting thread, callbacks need to be
 * setup for the reporting thread starting and ending functions to initialise storage
 * to hold the combined total for each partial results.

/* define reporting thread starting function */
void module_MODULENAME_reporter_starting(void *tls) {

    /* create storage to hold the combined results */
    struct module_MODULENAME_storage *totals = (struct module_MODULENAME_storage *)
        malloc(sizeof(struct module_MODULENAME_storage));

    /* init the storage */
    totals->bytes = 0;
    totals->http_count = 0;
    totals->last_tick = 0;

    /* return the totals storage, this will be passed to all callbacks running within
     * the reporting thread as mls.
     */
    return totals;
}

/* define a combining function which will receive the results posted by the tick
 * function
 */
int module_MODULENAME_reporter_combiner(bigdata_t *bigdata, void *mls, uint64_t tick,
    void *result) {

    /* gain access to the totals structure create in the reporter starting function */
    struct module_MODULENAME_storage *totals = (struct module_MODULENAME_storage *)mls;

    /* gain access to the partial result sent from the tick function to be combined */
    struct module_MODULENAME_storage *res = (struct module_MODULENAME_storage *)result;

    /* tick contains the timestamp for the period the result was created for.
     * When a tick is seen greater than the previous all partial results for that
     * period have been received and the result can be output.
     */

    /* last_tick will only be 0 on the first pass so assign to the current tick */
    if (totals->last_tick == 0) {
        totals->last_tick = tick;
    }

    /* if the current tick is greater than last_tick its time to output a result */
    if (totals->last_tick < tick) {

        /* create a result set */
        bd_result_set_t *resultset = bd_result_set_create("MODULENAME");
        /* insert the counters into the result */
        bd_result_set_insert_uint(resultset, "bytes", totals->bytes);
        bd_result_set_insert_uint(resultset, "http_count", totals->http_count);
        /* insert the timestamp into the result set */
        bd_result_set_insert_timestamp(resultset, tick);

        /* send result set to be published */
        bd_result_set_publish(bigdata, resultset, tick);

        /* clear totals for next round of results */
        totals->bytes = 0;
        totals->http_count = 0;

    /* otherwise increment the totals with the current partial result */
    } else {
        totals->bytes += res->bytes;
        totals->http_count += totals->http_count;
    }

    /* free the result created from the tick function and passed into the combiner */
    free(res);
}

/* define a stopping function for the reporting thread */
int module_MODULENAME_reporter_stopping(void *tls, void *mls) {

    /* gain access to the totals structure created in the reporting starting function */
    struct module_MODULENAME_storage *totals = (struct module_MODULENAME_storage *)mls;

    /* free the totals structure */
    free(totals);
}

/* define the configuration function */
int module_MODULENAME_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

    /* parse the plugins configuration from the configuration file. Currently this
     * plugin only supports the enabled parameter
     */
    int enter_level = *level;
    bool first_pass = 1;

    while (enter_level != *level || first_pass) {
        first_pass = 0;
        switch(event->type) {
            case YAML_SCALAR_EVENT:
                if (strcmp((char *)event->data.scalar.value, "enabled") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "t") == 0) {

                        config->enabled = 1;
                    }
                    break;
                }
            default:
                consume_event(parser, event, level);
                break;
        }
    }

    /* if the plugin was enabled define its callback functions for each event */
    if (config->enabled) {
        /* define the packet processing thread callback functions */
        config->callbacks->start_cb = (cb_start)module_MODULENAME_starting;
        config->callbacks->packet_cb = (cb_packet)module_MODULENAME_packet;
        /* define callback for HTTP packets */
        bd_register_protocol_event(config->callbacks, module_MODULENAME_http_packet,
            LPI_PROTO_HTTP);
        config->callbacks->stop_cb = (cb_stop)module_MODULENAME_stopping;
        config->callbacks->tick_cb = (cb_tick)module_MODULENAME_tick;
        /* set the tick interval to 60 seconds */
        bd_add_tickrate_to_cb_set(config->callbacks, 60);

        /* define the reporting thread callback functions */
        config->callbacks->reporter_start_cb = (cb_reporter_start)
            module_MODULENAME_reporter_start;
        config->callbacks->reporter_combiner_cb = (cb_reporter_combiner)
            module_MODULENAME_reporter_combiner;
        config->callbacks->reporter_stop_cb = (cb_reporter_stop)
            module_MODULENAME_reporter_stopping;

        fprintf(stdout, "MODULENAME Plugin Enabled\n");
    }
}


/* define the initialisation function for the plugin, This is called by the application
 * core on startup */
int module_MODULENAME_init(bd_bigdata_t *bigdata) {

    /* create storage for the plugins conf structure */
    config = (struct module_MODULENAME_config *)malloc(sizeof(struct
        module_MODULENAME_config));

    /* init the config structure */
    config->enabled = 0;

    /* create callback set used to map callback functions to each event */
    config->callbacks = bd_create_cb_set("MODULENAME");

    /* define a configuration function for the plugin */
    config->callbacks->config_cb = (cb_config)module_MODULENAME_config;

    /* register the callback set against the application core */
    bd_register_cb_set(bigdata, config->callbacks);
}
