#include "bigdata_callbacks.h"

bd_cb_set *bd_create_cb_set(const char *module_name) {
    bd_cb_set *cbset = (bd_cb_set *)calloc(1, sizeof(bd_cb_set));
    if (cbset == NULL) {
        fprintf(stderr, "Unable to create callback set. func. "
            "bd_create_cb_set()\n");
        exit(BD_OUTOFMEMORY);
    }

    // assign the module name
    cbset->name = strdup(module_name);

    // assign default tickrate.
    cbset->tickrate = BIGDATA_TICKRATE;

    // clear protocol callbacks
    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        cbset->protocol_cb[i] = NULL;
    }

    return cbset;
}

int bd_add_filter_to_cb_set(bd_cb_set *cbset, const char *filter) {
    cbset->filter = trace_create_filter(filter);
    return 0;
}

int bd_add_tickrate_to_cb_set(bd_cb_set *cbset, size_t tickrate) {
    cbset->tickrate = tickrate;
    return 0;
}
// Register callback for a protocol event
int bd_register_protocol_event(bd_cb_set *cbset, cb_protocol callback, lpi_protocol_t protocol) {
    cbset->protocol_cb[protocol] = callback;
    return 0;
}


int bd_callback_trigger_output(bd_bigdata_t *bigdata, bd_result_set_t *result) {

    int ret;
    int cb_counter = 0;

    // get access to global data
    bd_global_t *global = bigdata->global;
    // gain access to thread storage
    bd_rthread_local_t *l_data = (bd_rthread_local_t *)bigdata->tls;

    // get the first callback set
    bd_cb_set *cbs = global->callbacks;

    // call each registered output module passing the result set
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->reporter_output_cb != NULL) {
            ret = cbs->reporter_output_cb(bigdata, l_data->mls[cb_counter], result);
            // if ret isnt 0 output failed so store and output and try again later??
            if (ret != 0) {
                fprintf(stderr, "Failed posting result to %s\n", cbs->name);
            } else if (global->config->debug) {
                fprintf(stderr, "DEBUG: Result posted to %s\n", cbs->name);
            }
        }
        cb_counter += 1;
    }

    return ret;
}

int bd_callback_trigger_combiner(bd_bigdata_t *bigdata, bd_result_set_wrap_t *res) {

    int ret;
    int cb_counter = 0;

    // get access to global data
    bd_global_t *global = bigdata->global;
    // gain access to thread storage
    bd_rthread_local_t *l_data = (bd_rthread_local_t *)bigdata->tls;

    // get the first callback set
    bd_cb_set *cbs = global->callbacks;

    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->reporter_combiner_cb != NULL) {
            // if this result if for the current module
            if (res->module_id == cbs->id) {
                ret = cbs->reporter_combiner_cb(bigdata, l_data->mls[cb_counter],
                    res->key, (void *)res->value);
            }
        }
        cb_counter += 1;
    }

    return ret;
}

int bd_callback_trigger_protocol(bd_bigdata_t *bigdata, lpi_protocol_t protocol) {

    int ret;
    int cb_counter = 0;

    // get access to global data
    bd_global_t *global = bigdata->global;
    // gain access to thread storage
    bd_thread_local_t *l_data = (bd_thread_local_t *)bigdata->tls;

    // get the first callback set
    bd_cb_set *cbs = global->callbacks;

    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->protocol_cb[protocol] != NULL) {
            ret = cbs->protocol_cb[protocol](bigdata, l_data->mls[cb_counter]);
        }
        cb_counter += 1;
    }

    return ret;
}

int bd_callback_trigger_packet(bd_bigdata_t *bigdata) {

    int ret;
    int cb_counter = 0;

    // get access to global data
    bd_global_t *global = bigdata->global;
    // gain access to thread storage
    bd_thread_local_t *l_data = (bd_thread_local_t *)bigdata->tls;

    // trigger packet event
    bd_cb_set *cbs = global->callbacks;

    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->packet_cb != NULL) {
            if (cbs->filter != NULL) {
                if (trace_apply_filter(cbs->filter, bigdata->packet)) {
                    ret = cbs->packet_cb(bigdata, l_data->mls[cb_counter]);
                }
            } else {
                ret = cbs->packet_cb(bigdata, l_data->mls[cb_counter]);
            }
        }
        cb_counter += 1;
    }

    return ret;
}

int bd_callback_trigger_tick(bd_bigdata_t *bigdata, uint64_t tick) {

    int ret = 0;
    int cb_counter = 0;

    // get the global data
    bd_global_t *global = (bd_global_t *)bigdata->global;
    // get global configuration
    bd_conf_t *config = global->config;

    // get the thread local data
    bd_thread_local_t *l_data = (bd_thread_local_t *)bigdata->tls;

    // convert ERF timestamp to seconds
    uint64_t timestamp_seconds = tick >> 32;

    bd_cb_set *cbs = global->callbacks;
    for (; cbs != NULL; cbs = cbs->next) {
        if (cbs->tick_cb != NULL) {

            // c_tickrate will be 0 on the first pass.
            if (l_data->c_tickrate[cb_counter] == 0) {
                // Align the output to nearest boundary.
                // E.G. output interval of 60 seconds will be on the minute boundary:
                // 12:00, 12:01, 12:02 etc.
                if ((timestamp_seconds % cbs->tickrate) == 0) {
                    l_data->c_tickrate[cb_counter] = timestamp_seconds + cbs->tickrate;
                    // if the module has a clear callback call it to reset any counters
                    if (cbs->clear_cb != NULL) {
                        ret = cbs->clear_cb(l_data->mls[cb_counter]);
                    }
                }

            // if the current module is due a tick
            // note: modules receive tick time in seconds
            } else if (l_data->c_tickrate[cb_counter] <= timestamp_seconds) {
                ret = cbs->tick_cb(bigdata, l_data->mls[cb_counter], timestamp_seconds);
                l_data->c_tickrate[cb_counter] = timestamp_seconds + cbs->tickrate;
            }
        }
        cb_counter += 1;
    }

    // output some libtrace stats if debug is enabled
    if (config->debug) {
        libtrace_stat_t *stats = trace_create_statistics();
        trace_get_statistics(bigdata->trace, stats);
        fprintf(stderr, "Accepted %lu packets, Dropped %lu packets\n",
            stats->accepted, stats->dropped);
        free(stats);
    }

    return ret;
}
