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
