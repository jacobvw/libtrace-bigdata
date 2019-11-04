#include "bigdata.h"
#include "bigdata_resultset.h"

bd_result_set_t *bd_result_set_create(const char *mod) {
    // create result set structure
    bd_result_set_t *res = (bd_result_set_t *)malloc(sizeof(bd_result_set_t));
    if (res == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_create_output_result_set()\n");
        exit(BD_OUTOFMEMORY);
    }
    // allocate space for results
    res->results = (bd_result_t *)malloc(sizeof(bd_result_t)*RESULT_SET_INIT_SIZE);
    if (res->results == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_create_output_result_set()\n");
        exit(BD_OUTOFMEMORY);
    }
    res->module = mod;
    res->num_results = 0;
    res->allocated_results = RESULT_SET_INIT_SIZE;
    res->timestamp = 0;

    return res;
}
int bd_result_set_insert(bd_result_set_t *result_set, char const *key, bd_record_type dtype,
    bd_record_value value) {

    if (result_set == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_insert()\n");
        exit(BD_OUTOFMEMORY);
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

    result_set->results[result_set->num_results].key = strdup(key);
    result_set->results[result_set->num_results].type = dtype;
    result_set->results[result_set->num_results].value = value;

    result_set->num_results += 1;

    return 0;

}
int bd_result_set_insert_string(bd_result_set_t *result_set, char const *key,
    const char *value) {

    union bd_record_value val;
    val.data_string = strdup(value);
    if (val.data_string == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_result_set_insert_string()\n");
        exit(BD_OUTOFMEMORY);
    }

    bd_result_set_insert(result_set, key, BD_TYPE_STRING, val);

    return 0;
}
int bd_result_set_insert_float(bd_result_set_t *result_set, char const *key,
    float value) {

    union bd_record_value val;
    val.data_float = value;
    bd_result_set_insert(result_set, key, BD_TYPE_FLOAT, val);

    return 0;
}
int bd_result_set_insert_double(bd_result_set_t *result_set, char const *key,
    double value) {

    union bd_record_value val;
    val.data_double = value;
    bd_result_set_insert(result_set, key, BD_TYPE_DOUBLE, val);

    return 0;
}
int bd_result_set_insert_int(bd_result_set_t *result_set, char const *key,
    int64_t value) {

    union bd_record_value val;
    val.data_int = value;
    bd_result_set_insert(result_set, key, BD_TYPE_INT, val);

    return 0;
}
int bd_result_set_insert_uint(bd_result_set_t *result_set, char const *key,
    uint64_t value) {

    union bd_record_value val;
    val.data_uint = value;
    bd_result_set_insert(result_set, key, BD_TYPE_UINT, val);

    return 0;
}
int bd_result_set_insert_bool(bd_result_set_t *result_set, char const *key,
    bool value) {

    union bd_record_value val;
    val.data_bool = value;
    bd_result_set_insert(result_set, key, BD_TYPE_BOOL, val);

    return 0;
}
int bd_result_set_insert_timestamp(bd_result_set_t *result_set, uint64_t timestamp) {
    result_set->timestamp = timestamp;
    return 0;
}
int bd_result_set_insert_tag(bd_result_set_t *result_set, char const *tag,
    const char *value) {

    union bd_record_value val;
    val.data_string = strdup(value);
    if (val.data_string == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_result_set_insert_string()\n");
        exit(BD_OUTOFMEMORY);
    }
    bd_result_set_insert(result_set, tag, BD_TYPE_TAG, val);

    return 0;
}

// to send a result set to any registered output modules. Should
// only be called by processing threads
int bd_result_set_publish(bd_bigdata_t *bigdata, bd_result_set_t *result, uint64_t key) {

    if (result == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_output()\n");
        return -1;
    }

    /* If the current thread is not a processing thread, trigger the output event
       directly */
    if (trace_get_perpkt_thread_id(bigdata->thread) == -1) {

        bd_callback_trigger_output(bigdata, result);

        /* and the result set now needs to be free'd when not running through
         * libtrace_public_result.
         */
        bd_result_set_free(result);

    /* Otherwise post to the reporter thread */
    } else {

        bd_result_set_wrap_t *res = (bd_result_set_wrap_t *)
            malloc(sizeof(bd_result_set_wrap_t));
        if (res == NULL) {
            fprintf(stderr, "Unable to allocate memory. func. bd_result_set_publish()\n");
            exit(BD_OUTOFMEMORY);
        }
        res->type = BD_RESULT_PUBLISH;
        res->value = (void *)result;
        res->module_id = 0;
        res->key = key;

        libtrace_generic_t gen;
        gen.ptr = (void *)res;

        trace_publish_result(bigdata->trace, bigdata->thread, key, gen, RESULT_USER);
    }

    return 0;
}

// to send a result to the registered combine callback for the supplied module id.
// Should only be called from a processing thread.
int bd_result_combine(bd_bigdata_t *bigdata, void *result, uint64_t key, int module_id) {

    if (result == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_combine()\n");
        return -1;
    }

    bd_result_set_wrap_t *res = (bd_result_set_wrap_t *)
        malloc(sizeof(bd_result_set_wrap_t));
    if (res == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_result_set_publish()\n");
        exit(BD_OUTOFMEMORY);
    }
    res->type = BD_RESULT_COMBINE;
    res->value = (void *)result;
    res->module_id = module_id;
    res->key = key;

    libtrace_generic_t gen;
    gen.ptr = (void *)res;

    /* If the current thread is not a processing thread, trigger the combiner event
       directly */
    if (trace_get_perpkt_thread_id(bigdata->thread) == -1) {

        bd_callback_trigger_combiner(bigdata, res);

        /* and the result wrapper now needs to be free'd when not running through
         * libtrace_public_result. The result value should have been free'd by the
         * plugins combining function.
         */
        bd_result_set_wrap_free(res);

    } else {

        trace_publish_result(bigdata->trace, bigdata->thread, key, gen, RESULT_USER);
    }


    return 0;
}

int bd_result_set_free(bd_result_set_t *result_set) {

    int i;

    /* result set already cleared */
    if (result_set == NULL) {
        return 0;
    }

    if (result_set->results != NULL) {
        // iterate over each clearing any strings
        for (i=0; i<result_set->num_results; i++) {
            if (result_set->results[i].type == BD_TYPE_STRING ||
                result_set->results[i].type == BD_TYPE_TAG) {

                if (result_set->results[i].value.data_string != NULL) {
                    free(result_set->results[i].value.data_string);
                    result_set->results[i].value.data_string = NULL;
                }

                if (result_set->results[i].key != NULL) {
                    free(result_set->results[i].key);
                    result_set->results[i].key = NULL;
                }
            }
        }
        free(result_set->results);
        result_set->results = NULL;
    }

    free(result_set);
    result_set = NULL;

    return 0;
}

int bd_result_set_wrap_free(bd_result_set_wrap_t *r) {
    int ret = 0;

    if (r == NULL) {
        fprintf(stderr, "NULL result wrapper. func. bd_result_set_wrap_free()\n");
        return -1;
    }

    /* ensure BD_RESULT_PUBLISH type, BD_RESULT_COMBINE contains a pointer to a
     * unknown datatype.
     */
    if (r->type == BD_RESULT_PUBLISH) {
        ret = bd_result_set_free((bd_result_set_t *)r->value);
    }

    free(r);
    r = NULL;

    return ret;
}
