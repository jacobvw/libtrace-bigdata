#include "bigdata_callbacks.h"

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
            if (res->module_id = cbs->id) {
                ret = cbs->reporter_combiner_cb(bigdata, l_data->mls[cb_counter],
                    res->key, (void *)res->value);
            }
        }
        cb_counter += 1;
    }

    return ret;
}
