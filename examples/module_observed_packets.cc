#include <module_observed_packets.h>

/* this structure is used hold configuration related items for the plugin. */
struct module_observed_packets_config {
    bd_cb_set *callbacks;	/* the callback set contains all the callback functions/events for the plugin.
                                 * this is effectivly the configuration of the plugin.
                                 */
};
static struct module_observed_packets_config *config;

/* structure to keep track of the number of packets observed. */
struct module_observed_packets_storage {
    uint64_t packets;
    uint64_t last_tick;
};



/* This is the packet processing threads starting function. This function is used
 * to initialise any storage required by the packet processing threads for this plugin.
 */
void *module_observed_packets_starting(void *tls) {

    /* declare and allocate memory for the packet counter */
    struct module_observed_packets_storage *storage;
    storage = (struct module_observed_packets_storage *)malloc(sizeof(
        struct module_observed_packets_storage));

    /* initialise the number of seen packets */
    storage->packets = 0;

    /* this structure must be returned by the starting function. It will now be accessable
     * within other packet processing threads function via the mls parameter.
     */
    return storage;
}

/* This function will be processed by the packet processing thread and will be called for
 * every packet received.
 */
int module_observed_packets_packet(bd_bigdata_t bigdata, void *tls, void *mls) {

    /* gain access to the packet counter structure */
    struct module_observed_packets_storage *storage;
    storage = (struct module_observed_packets_storage *)mls;

    /* increment the packet counter */
    storage->packets += 1;

    return 0;
}

/* This function will be triggered at periodic intervals to send results to the reporting thread */
int module_observed_packets_tick(bd_bigdata_t *bigdata, void *mls, uint64_t tick) {

    /* gain access to the packet counter structure */
    struct module_observed_packets_storage *storage;
    storage = (struct module_observed_packets_storage *)mls;

    /* create a new result structure to send to the reporter events */
    struct module_observed_packets_storage *result;
    result = (struct module_observed_packets_storage *)malloc(sizeof
        (struct module_observed_packets_storage));

    /* copy results over */
    result->packets = storage->packets;

    /* clear the observed packets for this round */
    storage->packets = 0;

    /* send the copied result to be combined. This will be processed by the
     * application core and will be transfered to the reporting thread combine function.
     */
    bd_result_combine(bigdata, (void *)result, tick, config->callbacks->id);

    return 0;

}

/* This function will be called when the packet processing thread stopping event is triggered.
 * It is used to free any storage allocated before the applications closes.
 */
int module_observed_packets_stopping(void *tls, void *mls) {

    /* gain access to the packet counter structure */
    struct module_observed_packets_storage *storage;
    storage = (struct module_observed_packets_storage *)mls;

    /* free memory allocated for the packet counter structure */
    free(storage);

    return 0;
}

/* This is the reporting thread starting function. */
void *module_observed_packets_reporter_starting(void *tls) {

    /* create storage to hold the combined results */
    struct module_observed_packets_storage *combined;
    combined = (struct module_observed_packets_storage *)malloc(sizeof(
        struct module_observed_packets_storage));

    /* initialise the combined tally */
    combined->packets = 0;
    combined->last_tick = 0;

    /* return structure to hold combined results. This is passed between reporting thread
     * events as the mls parameter */
    return combined;
}

/* this function will receive the result posted to the combiner in the tick function. */
void *module_observed_packets_combiner(bd_bigdata_t *bigdata, void *mls, uint64_t tick,
    void *result) {

    /* gain access to the combined result structure */
    struct module_observed_packets_storage *combined;
    combined = (struct module_observed_packets_storage *)mls;

    /* gain access to the partial result sent from the tick function to be combined */
    struct module_observed_packets_storage *partial;
    partial = (struct module_observed_packets_storage *)result;

    /* if last tick = 0 this must be the first time entering here. so set to current tick
     * which is the current timestamp.
     */
    if (combined->last_tick == 0) {
        combined->last_tick = tick;
    }

    /* if the tick is greater than the last_tick all results for the time period have been
     * received. so post the result */
    if (combined->last_tick < tick) {

        /* create a result */
        bd_result_set_t *result = bd_result_set_create(bigdata, "observed_packets");
        bd_result_set_insert_uint(result, "packets", combined->packets);
        /* insert a timestamp into the packet */
        bd_result_set_insert_timestamp(result, tick);

        /* publish the result */
        bd_result_set_publish(bigdata, result, tick);

        /* clear the combined result */
        combined->packets = 0;
    }

    /* increment the combined counter with results for this result */
    combined->packets += partial->packets;
    combined->last_tick = tick;

    /* free the partial result */
    free(partial);
}

/* this is called when the reporter thread is stopping/ when the application is stopping. */
int module_observed_packets_reporter_stopping(void *tls, void *mls) {

    /* gain access to the combined result */
    struct module_observed_packets_storage *combined;
    combined = (struct module_observed_packets_storage *)mls;

    /* free memory allocated for the combined result */
    free(combined);
}

/* this is the main entry point for the plugin. this is called from the setup thread
 * and is used setup plugins config/callbacks etc.
 */
int module_observed_packets_init(bd_bigdata_t *bigdata) {

    /* allocate memory for the config structure */
    config = (struct module_observed_packets_config *)malloc(sizeof(
        struct module_observed_packets_config));

    /* create a callback set. this holds information on registered events and callback
     * functions for those events.
     */
    config->callbacks = bd_create_cb_set("observed_packets");

    /* register the defined function above to their respective event */
    bd_register_start_event(config->callbacks, (cb_start)module_observed_packets_starting);
    bd_register_packet_event(config->callbacks, (cb_packet)module_observed_packets_packet);
    bd_register_tick_event(config->callbacks, (cb_tick)module_observed_packets_tick);
    bd_register_stop_event(config->callbacks, (cb_stop)module_observed_packets_stopping);
    bd_register_reporter_start_event(config->callbacks, (cb_reporter_start)
        module_observed_packets_reporter_starting);
    bd_register_reporter_combiner_event(config->callbacks, (cb_reporter_combiner)
        module_observed_packets_combiner);
    bd_register_reporter_stop_event(config->callbacks, (cb_reporter_stop)
        module_observed_packets_stopping);

    /* set the interval to trigger the tick event, lets set this to 60 seconds */
    bd_add_tickrate_to_cb_set(config->callbacks, 5);

    /* register the callback set */
    bd_register_cb_set(bigdata, config->callbacks);
}
