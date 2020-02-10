#include "bigdata.h"
#include "bigdata_resultset.h"
#include <string>
#include <iostream>
#include <stdio.h>

bd_result_set_t *bd_result_set_create(bd_bigdata_t *bigdata, const char *mod) {
    // create result set structure
    bd_result_set_t *res = (bd_result_set_t *)malloc(sizeof(bd_result_set_t));
    if (res == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_create_output_result_set()\n");
        exit(BD_OUTOFMEMORY);
    }
    // allocate space for the result pointers
    res->results = (bd_result_t **)malloc(sizeof(bd_result_t *)*RESULT_SET_INIT_SIZE);
    if (res->results == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_create_output_result_set()\n");
        exit(BD_OUTOFMEMORY);
    }
    res->module = mod;
    res->num_results = 0;
    res->allocated_results = RESULT_SET_INIT_SIZE;
    res->timestamp = 0;
    res->free_lock = 0;

    return res;
}
static int bd_result_set_insert(bd_result_set_t *result_set, char const *key, bd_record_type dtype,
    bd_record_value value, int num_values) {

    bd_result_t *newresult;

    if (result_set == NULL) {
        logger(LOG_CRIT, "NULL result set. func. bd_result_set_insert()\n");
        exit(BD_OUTOFMEMORY);
    }

    // re-allocated more result pointers if needed
    if (result_set->num_results >= result_set->allocated_results) {
        result_set->allocated_results += RESULT_SET_INC_SIZE;
        result_set->results = (bd_result_t **)realloc(result_set->results,
            sizeof(bd_result_t *)*result_set->allocated_results);
        if (result_set->results == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert()\n");
            exit(BD_OUTOFMEMORY);
        }
    }

    /* create the new result */
    newresult = (bd_result_t *)malloc(sizeof(bd_result_t));
    if (newresult == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_result_set_insert()\n");
        exit(BD_OUTOFMEMORY);
    }

    /* populate the new result */
    newresult->key = strdup(key);
    if (newresult->key == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert()");
        exit(BD_OUTOFMEMORY);
    }
    newresult->type = dtype;
    newresult->value = value;
    /* insert the number of values. only applies to array types */
    newresult->num_values = num_values;

    /* link the new result to the array of results */
    result_set->results[result_set->num_results] = newresult;

    /* increment the number of stored results */
    result_set->num_results += 1;

    return 0;

}
int bd_result_set_insert_string(bd_result_set_t *result_set, char const *key,
    const char *value) {

    if (value == NULL) {
        return 1;
    }

    union bd_record_value val;
    val.data_string = strdup(value);
    if (val.data_string == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert_string()");
        exit(BD_OUTOFMEMORY);
    }

    bd_result_set_insert(result_set, key, BD_TYPE_STRING, val, 0);

    return 0;
}
int bd_result_set_insert_string_array(bd_result_set_t *result_set, char const *key,
    int num_args, ...) {

    va_list ap;
    int i;

    /* create array of pointers for each string */
    char **strings = (char **)malloc(sizeof(char *)*num_args);
    if (strings == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert_string"
            "array()");
        exit(BD_OUTOFMEMORY);
    }

    va_start(ap, num_args);
    for (i = 0; i < num_args; i++) {
        strings[i] = strdup(va_arg(ap, const char *));
        if (strings[i] == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set"
                "insert_string_arraty()");
            exit(BD_OUTOFMEMORY);
        }
    }

    union bd_record_value val;
    val.data_string_array = strings;

    bd_result_set_insert(result_set, key, BD_TYPE_STRING_ARRAY, val, num_args);

    return 0;
}
int bd_result_set_insert_string_array(bd_result_set_t *result_set, char const *key,
    std::list<char *> *items) {

    std::list<char *>::iterator it = items->begin();

    /* create array of pointers for each string */
    char **strings = (char **)malloc(sizeof(char *)*items->size());
    if (strings == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert_string"
            "array()");
        exit(BD_OUTOFMEMORY);
    }

    for (int i = 0; i < items->size(); i++) {
        strings[i] = strdup(*it);
        if (strings[i] == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set"
                "insert_string_arraty()");
            exit(BD_OUTOFMEMORY);
        }
        it++;
    }

    union bd_record_value val;
    val.data_string_array = strings;

    bd_result_set_insert(result_set, key, BD_TYPE_STRING_ARRAY, val, items->size());

    return 0;
}
int bd_result_set_insert_float(bd_result_set_t *result_set, char const *key,
    float value) {

    union bd_record_value val;
    val.data_float = value;
    bd_result_set_insert(result_set, key, BD_TYPE_FLOAT, val, 0);

    return 0;
}
int bd_result_set_insert_float_array(bd_result_set_t *result_set, char const *key,
    int num_args, ...) {

    va_list ap;
    int i;

    /* create array of floats */
    float *floats = (float *)malloc(sizeof(float)*num_args);
    if (floats == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set"
            "insert_float_array()");
        exit(BD_OUTOFMEMORY);
    }

    va_start(ap, num_args);
    for (i = 0; i < num_args; i++) {
        /* note: floats are promoted to doubles for va_arg. */
        floats[i] = va_arg(ap, double);
    }

    union bd_record_value val;
    val.data_float_array = floats;

    bd_result_set_insert(result_set, key, BD_TYPE_FLOAT_ARRAY, val, num_args);

    return 0;
}
int bd_result_set_insert_double(bd_result_set_t *result_set, char const *key,
    double value) {

    union bd_record_value val;
    val.data_double = value;
    bd_result_set_insert(result_set, key, BD_TYPE_DOUBLE, val, 0);

    return 0;
}
int bd_result_set_insert_double_array(bd_result_set_t *result_set, char const *key,
    int num_args, ...) {

    va_list ap;
    int i;

    /* create space to hold double array */
    double *doubles = (double *)malloc(sizeof(double)*num_args);
    if (doubles == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set"
            "insert_double_array()");
        exit(BD_OUTOFMEMORY);
    }

    va_start(ap, num_args);
    for (i = 0; i < num_args; i++) {
        doubles[i] = va_arg(ap, double);
    }

    union bd_record_value val;
    val.data_double_array = doubles;

    bd_result_set_insert(result_set, key, BD_TYPE_DOUBLE_ARRAY, val, num_args);

    return 0;
}
int bd_result_set_insert_int(bd_result_set_t *result_set, char const *key,
    int64_t value) {

    union bd_record_value val;
    val.data_int = value;
    bd_result_set_insert(result_set, key, BD_TYPE_INT, val, 0);

    return 0;
}
int bd_result_set_insert_int_array(bd_result_set_t *result_set, char const *key,
    int num_args, ...) {

    va_list ap;
    int i;

    int64_t *ints = (int64_t *)malloc(sizeof(int64_t)*num_args);
    if (ints == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert"
            "int_array()");
        exit(BD_OUTOFMEMORY);
    }

    va_start(ap, num_args);
    for (i = 0; i < num_args; i++) {
        ints[i] = va_arg(ap, int64_t);
    }

    union bd_record_value val;
    val.data_int_array = ints;

    bd_result_set_insert(result_set, key, BD_TYPE_INT_ARRAY, val, num_args);

    return 0;
}
int bd_result_set_insert_uint(bd_result_set_t *result_set, char const *key,
    uint64_t value) {

    union bd_record_value val;
    val.data_uint = value;
    bd_result_set_insert(result_set, key, BD_TYPE_UINT, val, 0);

    return 0;
}
int bd_result_set_insert_uint_array(bd_result_set_t *result_set, char const *key,
    int num_args, ...) {

    va_list ap;
    int i;

    uint64_t *uints = (uint64_t *)malloc(sizeof(uint64_t)*num_args);
    if (uints == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert"
            "uint_array()");
        exit(BD_OUTOFMEMORY);
    }

    va_start(ap, num_args);
    for (i = 0; i < num_args; i++) {
        uints[i] = va_arg(ap, uint64_t);
    }

    union bd_record_value val;
    val.data_uint_array = uints;

    bd_result_set_insert(result_set, key, BD_TYPE_UINT_ARRAY, val, num_args);

    return 0;
}
int bd_result_set_insert_bool(bd_result_set_t *result_set, char const *key,
    bool value) {

    union bd_record_value val;
    val.data_bool = value;
    bd_result_set_insert(result_set, key, BD_TYPE_BOOL, val, 0);

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
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert_string()\n");
        exit(BD_OUTOFMEMORY);
    }
    bd_result_set_insert(result_set, tag, BD_TYPE_TAG, val, 0);

    return 0;
}
int bd_result_set_insert_ip_string(bd_result_set_t *result_set, char const *key,
    const char *value) {

    union bd_record_value val;
    val.data_string = strdup(value);
    if (val.data_string == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert_ip_string()\n");
        exit(BD_OUTOFMEMORY);
    }
    bd_result_set_insert(result_set, key, BD_TYPE_IP_STRING, val, 0);

    return 0;
}
int bd_result_set_insert_ip_string_array(bd_result_set_t *result_set, char const *key,
    int num_args, ...) {

    va_list ap;
    int i;

    /* create array of pointers for each string */
    char **strings = (char **)malloc(sizeof(char *)*num_args);
    if (strings == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert_string"
            "array()");
        exit(BD_OUTOFMEMORY);
    }

    va_start(ap, num_args);
    for (i = 0; i < num_args; i++) {
        strings[i] = strdup(va_arg(ap, const char *));
        if (strings[i] == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set"
                "insert_string_arraty()");
            exit(BD_OUTOFMEMORY);
        }
    }

    union bd_record_value val;
    val.data_string_array = strings;

    bd_result_set_insert(result_set, key, BD_TYPE_IP_STRING_ARRAY, val, num_args);

    return 0;
}
int bd_result_set_insert_result_set(bd_result_set_t *result_set, char const *key,
    bd_result_set_t *value) {

    if (result_set == NULL || value == NULL) {
        return -1;
    }

    union bd_record_value val;
    val.data_result_set = value;

    bd_result_set_insert(result_set, key, BD_TYPE_RESULT_SET, val, 0);

    return 0;
}
int bd_result_set_insert_result_set_array(bd_result_set_t *result_set,
    char const *key, std::list<bd_result_set_t *> *items) {

    if (result_set == NULL || items == NULL) {
        return -1;
    }

    std::list<bd_result_set_t *>::iterator it = items->begin();

    bd_result_set_t **results = (bd_result_set_t **)
        malloc(sizeof(bd_result_set_t *)*items->size());
    if (results == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_insert"
            "result_set_array()");
        exit(BD_OUTOFMEMORY);
    }

    for (int i = 0; i < items->size(); i++) {
        results[i] = *it;
        it++;
    }

    union bd_record_value val;
    val.data_result_set_array = results;

    bd_result_set_insert(result_set, key, BD_TYPE_RESULT_SET_ARRAY,
        val, items->size());

    return 0;
}

int bd_result_set_lock(bd_result_set_t *result_set) {
    result_set->free_lock += 1;

    return 0;
}
int bd_result_set_unlock(bd_result_set_t *result_set) {
    result_set->free_lock -= 1;
    bd_result_set_free(result_set);

    return 0;
}

int bd_result_set_publish(bd_bigdata_t *bigdata, bd_result_set_t *result, uint64_t key) {

    if (result == NULL) {
        logger(LOG_DEBUG, "NULL result set. func. bd_result_set_output()\n");
        return -1;
    }

    /* If the current thread is not a processing thread, trigger the output event
       directly */
    if (trace_get_perpkt_thread_id(bigdata->thread) == -1) {

        bd_callback_trigger_reporter_filter(bigdata, result);

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
            logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_publish()\n");
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

int bd_result_combine(bd_bigdata_t *bigdata, void *result, uint64_t key, int module_id) {

    if (result == NULL) {
        logger(LOG_DEBUG, "NULL result set. func. bd_result_set_combine()\n");
        return -1;
    }

    bd_result_set_wrap_t *res = (bd_result_set_wrap_t *)
        malloc(sizeof(bd_result_set_wrap_t));
    if (res == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_set_publish()\n");
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

    int i, j;

    /* result set already cleared */
    if (result_set == NULL) {
        return 0;
    }

    /* If a plugin has locked this result do not free it yet */
    if (result_set->free_lock > 0) {
        return 0;
    }

    if (result_set->results != NULL) {
        // iterate over each clearing any strings
        for (i = 0; i < result_set->num_results; i++) {

            /* free the data within the result set */
            switch (result_set->results[i]->type) {
                case BD_TYPE_RESULT_SET_ARRAY: {
                    /* loop over each result set and recursivly call this
                     * function */
                    for (j = 0; j < result_set->results[i]->num_values; j++) {
                        bd_result_set_free(result_set->results[i]->
                            value.data_result_set_array[j]);
                    }
                    /* now free the array of pointers */
                    free(result_set->results[i]->value.data_result_set_array);
                    break;
                }
                case BD_TYPE_RESULT_SET: {
                    /* recursively call this function to clear the result set */
                    bd_result_set_free(
                        result_set->results[i]->value.data_result_set);
                    break;
                }
                case BD_TYPE_STRING_ARRAY:
                case BD_TYPE_IP_STRING_ARRAY: {
                    /* loop over each element */
                    for (j = 0; j < result_set->results[i]->num_values; j++) {
                        /* free each element */
                        if (result_set->results[i]->value.data_string_array[j] != NULL) {
                            free(result_set->results[i]->value.data_string_array[j]);
                            result_set->results[i]->value.data_string_array[j] == NULL;
                        }
                    }
                    /* now free the array of pointers */
                    free(result_set->results[i]->value.data_string_array);
                    break;
                }
                case BD_TYPE_STRING:
                case BD_TYPE_IP_STRING:
                case BD_TYPE_TAG: {
                    free(result_set->results[i]->value.data_string);
                    break;
                }
                case BD_TYPE_FLOAT_ARRAY:
                    free(result_set->results[i]->value.data_float_array);
                    break;
                case BD_TYPE_DOUBLE_ARRAY:
                    free(result_set->results[i]->value.data_double_array);
                    break;
                case BD_TYPE_INT_ARRAY:
                    free(result_set->results[i]->value.data_int_array);
                    break;
                case BD_TYPE_UINT_ARRAY:
                    free(result_set->results[i]->value.data_uint_array);
                    break;
                default:
                    break;

            }

            /* free the result set key */
            if (result_set->results[i]->key != NULL) {
                free(result_set->results[i]->key);
                result_set->results[i]->key = NULL;
            }

            /* free the result */
            free(result_set->results[i]);
        }

        /* free the pointer array used to hold results */
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
        logger(LOG_DEBUG, "NULL result wrapper. func. bd_result_set_wrap_free()\n");
        return -1;
    }

    /* ensure BD_RESULT_PUBLISH type. BD_RESULT_COMBINE contains a pointer to a
     * unknown datatype so is the responsibility of the plugin to clear.
     */
    if (r->type == BD_RESULT_PUBLISH) {
        ret = bd_result_set_free((bd_result_set_t *)r->value);
    }

    free(r);
    r = NULL;

    return ret;
}

int bd_result_string_store(bd_cb_set *cbs, std::string result) {

    return fprintf(cbs->temp_file, "%s\n", result.c_str());
}

char *bd_result_string_read(bd_cb_set *cbs) {

    char *buf;
    long filesize;
    size_t readsize;

    // flush the files output buffer
    fflush(cbs->temp_file);

    // determine the filesize
    fseek(cbs->temp_file, 0, SEEK_END);
    filesize = ftell(cbs->temp_file);
    fseek(cbs->temp_file, 0, SEEK_SET);

    // if filesize is 0 nothing in file so return NULL
    if (filesize == 0) {
        return NULL;
    }

    /* allocate space to read the file into. include space to null terminate the string */
    buf = (char *)malloc(filesize + 1);
    if (buf == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. bd_result_string_read()\n");
        exit(BD_OUTOFMEMORY);
    }

    /* read the file into the buffer, this could become problematic if a datastore is down
     * for a long period of time causing a very large temp file. */
    readsize = fread(buf, 1, filesize, cbs->temp_file);
    /* make sure something was actually read, if not return */
    if (readsize == 0) {
        return NULL;
    }
    buf[filesize] = '\0';

    /* close the temp file, remove it, and recreate it */
    if (fclose(cbs->temp_file) != 0) {
        logger(LOG_CRIT, "Unable to close temporary file %s. func. "
            "bd_result_string_read()", cbs->temp_filename);
        exit(BD_TEMP_FILE);
    }
    if (remove(cbs->temp_filename) != 0) {
        logger(LOG_CRIT, "Unable to remove temporary file %s. func. "
            "bd_result_string_read()", cbs->temp_filename);
        exit(BD_TEMP_FILE);
    }
    if ((cbs->temp_file = fopen(cbs->temp_filename, "a+")) == NULL) {
        logger(LOG_CRIT, "Unable to create temporary file %s. func. "
            "bd_result_string_read()", cbs->temp_filename);
        exit(BD_TEMP_FILE);
    }

    return buf;
}

std::string bd_result_set_to_json_string(bd_result_set_t *result) {

    std::string json_string;
    bool first_pass = true;
    char *str;
    char buf[JSON_BUF_LEN] = "";

    // start the json string
    json_string += "{";

    // convert all fields
    for (int i = 0; i < result->num_results; i++) {

        if(i != 0) {
            json_string += ",";
        }

        json_string += "\"";
        json_string += result->results[i]->key;
        json_string += "\":";

        switch (result->results[i]->type) {
            case BD_TYPE_TAG:
            case BD_TYPE_IP_STRING:
            case BD_TYPE_STRING:
                json_string += "\"";
                json_string += result->results[i]->value.data_string;
                json_string += "\"";
                break;
            case BD_TYPE_FLOAT:
                snprintf(buf, JSON_BUF_LEN, "%f",
                    result->results[i]->value.data_float);
                json_string += buf;
                break;
            case BD_TYPE_DOUBLE:
                snprintf(buf, JSON_BUF_LEN, "%lf",
                    result->results[i]->value.data_double);
                json_string += buf;
                break;
            case BD_TYPE_INT:
                snprintf(buf, JSON_BUF_LEN, "%li",
                    result->results[i]->value.data_int);
                json_string += buf;
                break;
            case BD_TYPE_UINT:
                snprintf(buf, JSON_BUF_LEN, "%lu",
                    result->results[i]->value.data_uint);
                json_string += buf;
                break;
            case BD_TYPE_BOOL:
                if (result->results[i]->value.data_bool) {
                    json_string += "true";
                } else {
                    json_string += "false";
                }
                break;
            case BD_TYPE_STRING_ARRAY:
            case BD_TYPE_IP_STRING_ARRAY:
                json_string += "[";
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    json_string += "\"";
                    json_string += result->results[i]->value.data_string_array[j];
                    json_string += "\"";

                    if (j+1 != result->results[i]->num_values) {
                        json_string += ", ";
                    }
                }
                json_string += "]";
                break;
            case BD_TYPE_FLOAT_ARRAY:
                json_string += "[";
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%f",
                        result->results[i]->value.data_float_array[j]);
                    json_string += buf;
                    if (j+1 != result->results[i]->num_values) {
                        json_string += ", ";
                    }
                }
                json_string += "]";
                break;
            case BD_TYPE_DOUBLE_ARRAY:
                json_string += "[";
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%lf",
                        result->results[i]->value.data_double_array[j]);
                    json_string += buf;
                    if (j+1 != result->results[i]->num_values) {
                        json_string += ", ";
                    }
                }
                json_string += "]";
                break;
            case BD_TYPE_INT_ARRAY:
                json_string += "[";
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%ld",
                        result->results[i]->value.data_int_array[j]);
                    json_string += buf;
                    if (j+1 != result->results[i]->num_values) {
                        json_string += ", ";
                    }
                }
                json_string += "]";
                break;
            case BD_TYPE_UINT_ARRAY:
                json_string += "[";
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%lu",
                        result->results[i]->value.data_uint_array[j]);
                    json_string += buf;
                    if (j+1 != result->results[i]->num_values) {
                        json_string += ", ";
                    }
                }
                json_string += "]";
                break;
            case BD_TYPE_RESULT_SET:
                json_string += bd_result_set_to_json_string(
                    result->results[i]->value.data_result_set);
                break;
            case BD_TYPE_RESULT_SET_ARRAY:
                json_string += "[";
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    json_string += bd_result_set_to_json_string(
                        result->results[i]->value.data_result_set_array[j]);
                    if (j+1 != result->results[i]->num_values) {
                        json_string += ", ";
                    }
                }
                json_string += "]";
                break;
            default:
                break;
        }
    }

    // insert timestamp into the string
    if (result->timestamp != 0) {
        json_string += ",\"timestamp\":";
        // timestamp in milliseconds
        snprintf(buf, JSON_BUF_LEN, "%lu", (result->timestamp)*1000);
        json_string += buf;
    }

    // end the json string
    json_string += "}";

    return json_string;
}
