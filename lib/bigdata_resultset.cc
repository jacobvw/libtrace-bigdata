#include "bigdata.h"
#include "bigdata_resultset.h"
#include <string>
#include <iostream>
#include <stdio.h>

bd_result_set_t *bd_result_set_create(bd_bigdata_t *bigdata, const char *mod) {
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
    res->free_lock = 0;

    // insert the capture host into the result set
    bd_result_set_insert_tag(res, "capture_host", bigdata->global->config->hostname);

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
            exit(BD_OUTOFMEMORY);
        }
    }

    result_set->results[result_set->num_results].key = strdup(key);
    if (result_set->results[result_set->num_results].key == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_result_set_insert()\n");
        exit(BD_OUTOFMEMORY);
    }
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
int bd_result_set_insert_ip_string(bd_result_set_t *result_set, char const *key,
    const char *value) {

    union bd_record_value val;
    val.data_string = strdup(value);
    if (val.data_string == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_result_set_insert_ip_string()\n");
        exit(BD_OUTOFMEMORY);
    }
    bd_result_set_insert(result_set, key, BD_TYPE_IP_STRING, val);
}
int bd_result_set_lock(bd_result_set_t *result_set) {
    result_set->free_lock += 1;
}
int bd_result_set_unlock(bd_result_set_t *result_set) {
    result_set->free_lock -= 1;
    bd_result_set_free(result_set);
}

int bd_result_set_publish(bd_bigdata_t *bigdata, bd_result_set_t *result, uint64_t key) {

    if (result == NULL) {
        fprintf(stderr, "NULL result set. func. bd_result_set_output()\n");
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

    /* If a plugin has locked this result do not free it yet */
    if (result_set->free_lock > 0) {
        return 0;
    }

    if (result_set->results != NULL) {
        // iterate over each clearing any strings
        for (i=0; i<result_set->num_results; i++) {

            /* free the value */
            if (result_set->results[i].type == BD_TYPE_STRING ||
                result_set->results[i].type == BD_TYPE_TAG ||
                result_set->results[i].type == BD_TYPE_IP_STRING) {

                if (result_set->results[i].value.data_string != NULL) {
                    free(result_set->results[i].value.data_string);
                    result_set->results[i].value.data_string = NULL;
                }

            }

            /* free the key */
            if (result_set->results[i].key != NULL) {
                free(result_set->results[i].key);
                result_set->results[i].key = NULL;
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

    return fprintf(cbs->temp_stor, "%s\n", result.c_str());
}

char *bd_result_string_read(bd_cb_set *cbs) {

    char *buf;
    long filesize;
    char filename[100];
    size_t readsize;

    // flush the files output buffer
    fflush(cbs->temp_stor);

    // determine the filesize
    fseek(cbs->temp_stor, 0, SEEK_END);
    filesize = ftell(cbs->temp_stor);
    fseek(cbs->temp_stor, 0, SEEK_SET);

    // if filesize is 0 nothing in file so return NULL
    if (filesize == 0) {
        return NULL;
    }

    /* allocate space to read the file into. include space to null terminate the string */
    buf = (char *)malloc(filesize + 1);
    if (buf == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. bd_result_string_read()\n");
        exit(BD_OUTOFMEMORY);
    }

    /* read the file into the buffer, this could become problematic if a datastore is down
     * for a long period of time causing a very large temp file. */
    readsize = fread(buf, 1, filesize, cbs->temp_stor);
    /* make sure something was actually read, if not return */
    if (readsize == 0) {
        return NULL;
    }
    buf[filesize] = '\0';

    /* close the temp file, remove it, and recreate it */
    fclose(cbs->temp_stor);
    snprintf(filename, sizeof(filename), "/tmp/libtrace-bigdata.%s", cbs->name);
    remove(filename);
    cbs->temp_stor = fopen(filename, "a+");

    return buf;
}

std::string bd_result_set_to_json_string(bd_result_set_t *result) {

    std::string json_string;
    bool first_pass = true;
    char *str;
    char buf[JSON_BUF_LEN] = "";

    // start the json string
    json_string += "{";

    // insert capture application and hostname
    json_string += "\"capture_application\":\"libtrace-bigdata\"";

    // convert all tag fields
    for (int i = 0; i < result->num_results; i++) {

        json_string += ",\"";
        json_string += result->results[i].key;
        json_string += "\":";

        switch (result->results[i].type) {
            case BD_TYPE_TAG:
            case BD_TYPE_IP_STRING:
            case BD_TYPE_STRING:
                json_string += "\"";
                json_string += result->results[i].value.data_string;
                json_string += "\"";
                break;
            case BD_TYPE_FLOAT:
                snprintf(buf, JSON_BUF_LEN, "%f",
                    result->results[i].value.data_float);
                json_string += buf;
                break;
            case BD_TYPE_DOUBLE:
                snprintf(buf, JSON_BUF_LEN, "%lf",
                    result->results[i].value.data_double);
                json_string += buf;
                break;
            case BD_TYPE_INT:
                snprintf(buf, JSON_BUF_LEN, "%li",
                    result->results[i].value.data_int);
                json_string += buf;
                break;
            case BD_TYPE_UINT:
                snprintf(buf, JSON_BUF_LEN, "%lu",
                    result->results[i].value.data_uint);
                json_string += buf;
                break;
            case BD_TYPE_BOOL:
                if (result->results[i].value.data_bool) {
                    json_string += "true";
                } else {
                    json_string += "false";
                }
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

bd_result_set_t *bd_result_set_parse_json_string(std::string json) {

}
