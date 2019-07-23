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
int bd_result_set_insert(bd_result_set_t *result_set, const char *key, bd_record_type dtype,
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
        exit(BD_OUTOFMEMORY);
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
int bd_result_set_insert_timestamp(bd_result_set_t *result_set, uint64_t timestamp) {
    result_set->timestamp = timestamp;
    return 0;
}
int bd_result_set_insert_tag(bd_result_set_t *result_set, const char *tag,
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
int bd_result_set_publish(libtrace_t *trace, libtrace_thread_t *thread,
    bd_result_set_t *result) {

    if (result == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_output()\n");
        exit(BD_OUTOFMEMORY);
    }

    libtrace_generic_t gen;
    gen.ptr = (void *)result;
    uint64_t ts = (uint64_t)result->timestamp;

    // send the result to the reporter thread
    trace_publish_result(trace, thread, ts, gen, RESULT_USER);

    return 0;
}
int bd_result_set_free(bd_result_set_t *result_set) {

    int i;

    if (result_set == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_free()\n");
        exit(BD_OUTOFMEMORY);
    }

    if (result_set->results != NULL) {
        // iterate over each clearing any strings
        for (i=0; i<result_set->num_results; i++) {
            if (result_set->results[i].type == BD_TYPE_STRING ||
                result_set->results[i].type == BD_TYPE_TAG) {

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

