#include "module_influxdb.h"
#include <curl/curl.h>
#include <string>

#define INFLUX_BUF_LEN 2000
#define INFLUX_LINE_LEN 4000

struct module_influxdb_conf {
    bd_cb_set *callbacks;
    bool enabled;
    char *host;
    int port;
    char *db;
    char *usr;
    char *pwd;
    bool ssl_verifypeer;
    bool batch_results;
    int batch_count;
};
static struct module_influxdb_conf *config;

typedef struct module_influxdb_options {
    CURL *curl;
    bd_result_set_t **results;
    int num_results;
    bool influx_online;
} mod_influxdb_opts_t;

void *module_influxdb_starting(void *tls);
int module_influxdb_post(bd_bigdata_t *bigdata, void *mls, bd_result_set *result);
void *module_influxdb_stopping(void *tls, void *mls);
static std::string module_influxdb_result_to_query(bd_result_set *result);

void *module_influxdb_starting(void *tls) {

    mod_influxdb_opts_t *opts;

    // create local storage for the module
    opts = (mod_influxdb_opts_t *)malloc(sizeof(mod_influxdb_opts_t));
    if (opts == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_influxdb_starting()");
        exit(BD_OUTOFMEMORY);
    }

    // create pointer space for results if batch processing is enabled
    if (config->batch_results) {
        opts->results = (bd_result_set_t **)malloc(sizeof(
            bd_result_set_t *) * config->batch_count);
        if (opts->results == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. "
                "module_influxdb_starting()");
            exit(BD_OUTOFMEMORY);
        }
        opts->num_results = 0;
    }
    opts->influx_online = 0;

    // Initialise curl
    curl_global_init(CURL_GLOBAL_ALL);

    // get a curl handle
    opts->curl = curl_easy_init();
    if (opts->curl) {
        char buff[200];
        snprintf(buff, sizeof(buff), "%s%s%s%s%s%s%s", config->host, "/write?db=", config->db,
            "&u=", config->usr, "&p=", config->pwd);

        curl_easy_setopt(opts->curl, CURLOPT_URL, buff);
        curl_easy_setopt(opts->curl, CURLOPT_PORT, config->port);

        if (config->ssl_verifypeer) {
            curl_easy_setopt(opts->curl, CURLOPT_SSL_VERIFYPEER, 1);
        } else {
            curl_easy_setopt(opts->curl, CURLOPT_SSL_VERIFYPEER, 0);
        }
    }

    return opts;
}

int module_influxdb_export_result(bd_bigdata_t *bigdata, mod_influxdb_opts_t *opts,
    const char *result) {

    CURLcode ret;

    curl_easy_setopt(opts->curl, CURLOPT_POSTFIELDS, result);

    /* Perform the request, ret will get the return code */
    ret = curl_easy_perform(opts->curl);

    /* Check for errors */
    if(ret != CURLE_OK) {

        logger(LOG_INFO, "InfluxDB is offline, result written to temp storage.");
        logger(LOG_DEBUG, "Failed to post to influxDB: %s.", curl_easy_strerror(ret));

        /* Set influxDB to offline */
        opts->influx_online = 0;

        /* Send the result to the temp file */
        bd_result_string_store(config->callbacks, result);

        return 2;
    } else {

        /* If InfluxDB was previously offline */
        if (!opts->influx_online) {
            logger(LOG_INFO, "InfluxDB is online.");
        }

        logger(LOG_DEBUG, "InfluxDB executed: %s", result);

        opts->influx_online = 1;

        return 0;
    }
}

int module_influxdb_post(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    std::string out;
    std::string influx_line;;
    int i;
    bd_result_set_t *cur_res;
    char *result_queue;
    int ret = 1;

    mod_influxdb_opts_t *opts = (mod_influxdb_opts_t *)mls;

    // if influx is online try to proccess any results that may be stored within influx's
    // temp file
    if (opts->influx_online) {
        if ((result_queue = bd_result_string_read(config->callbacks)) != NULL) {

            /* Export the queued results */
            ret = module_influxdb_export_result(bigdata, opts, result_queue);

            free(result_queue);
        }
    }

    if (config->batch_results) {

        if (opts->num_results >= config->batch_count) {

            for (i = 0; i < opts->num_results; i++) {

                // get the current result
                cur_res = opts->results[i];
                // convert to influxdb line protocol
                influx_line = module_influxdb_result_to_query(cur_res);

                // join to the output string
                out += influx_line;
                out += "\n";

                // finished with this result so unlock it
                bd_result_set_unlock(cur_res);
            }

            // reset the number of results held and export result
            opts->num_results = 0;

            ret = module_influxdb_export_result(bigdata, opts, out.c_str());
        }

        // store the current result in the batch set
        bd_result_set_lock(result);
        opts->results[opts->num_results] = result;
        opts->num_results += 1;

    // not batch processing
    } else {

        // convert the current result set into influxDB line query
        influx_line = module_influxdb_result_to_query(result);
        out = influx_line;

        ret = module_influxdb_export_result(bigdata, opts, out.c_str());
    }

    return ret;
}

void *module_influxdb_stopping(void *tls, void *mls) {
    mod_influxdb_opts_t *opts = (mod_influxdb_opts_t *)mls;

    /* always cleanup */
    curl_easy_cleanup(opts->curl);

    curl_global_cleanup();

    free(opts);

    return 0;
}

int module_influxdb_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

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
                if (strcmp((char *)event->data.scalar.value, "host") == 0) {
                    consume_event(parser, event, level);
                    config->host = strdup((char *)event->data.scalar.value);
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "port") == 0) {
                    consume_event(parser, event, level);
                    config->port = atoi((char *)event->data.scalar.value);
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "database") == 0) {
                    consume_event(parser, event, level);
                    config->db = strdup((char *)event->data.scalar.value);
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "username") == 0) {
                    consume_event(parser, event, level);
                    config->usr = strdup((char *)event->data.scalar.value);;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "password") == 0) {
                    consume_event(parser, event, level);
                    config->pwd = strdup((char *)event->data.scalar.value);;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "ssl_verify_peer") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0) {

                        config->ssl_verifypeer = 1;
                    } else {
                        config->ssl_verifypeer = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "batch_results") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "t") == 0) {

                        config->batch_results = 1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "batch_count") == 0) {
                    consume_event(parser, event, level);
                    config->batch_count = atoi((char *)event->data.scalar.value);
                    break;
                }
                consume_event(parser, event, level);
                break;
            default:
                consume_event(parser, event, level);
                break;

        }
    }

    if (config->enabled) {
        // Because this is a output only module we register callbacks against
        // the reporter thread.
        config->callbacks->reporter_start_cb =(cb_reporter_start)module_influxdb_starting;
        config->callbacks->reporter_output_cb = (cb_reporter_output)module_influxdb_post;
        config->callbacks->reporter_stop_cb = (cb_reporter_stop)module_influxdb_stopping;

        logger(LOG_INFO, "InfluxDB Plugin Enabled");
    }

    return 0;
}

int module_influxdb_init(bd_bigdata_t *bigdata) {

    config = (struct module_influxdb_conf *)malloc(sizeof(
        struct module_influxdb_conf));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_influxdb_init()");
        exit(BD_OUTOFMEMORY);
    }

    config->enabled = 0;
    config->host = NULL;
    config->port = 8086;
    config->db = NULL;
    config->usr = NULL;
    config->pwd = NULL;
    config->ssl_verifypeer = 1;
    config->batch_results = 0;
    config->batch_count = 200;

    // create callback set
    config->callbacks = bd_create_cb_set("influxdb");

    // define config callback
    config->callbacks->config_cb = (cb_config)module_influxdb_config;

    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}

static std::string module_influxdb_result_to_query(bd_result_set *result) {

    bool first_pass = true;
    std::string influx_line;
    char buf[INFLUX_BUF_LEN] = "";

    // insert measurement/module name
    influx_line += result->module;
    influx_line += ",";

    // add tag sets. This is meta data that doesnt change
    influx_line += "capture_application=libtrace-bigdata";
    for (int i = 0; i < result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_TAG) {
            /* tag keys and tag values should escape commas, equal signs and spaces */

            influx_line += ",";
            /* if the tag key contains a space */
            if (strstr(result->results[i].key, " ")) {
                // escape all spaces
                char *w = bd_replaceWord(result->results[i].key, " ", "\\ ");
                influx_line += w;
                free(w);
            } else {
                influx_line += result->results[i].key;
            }

            influx_line += "=";

            /* if the tag result contains a space */
            if (strstr(result->results[i].value.data_string, " ")) {
                /* escape all spaces */
                char *w = bd_replaceWord(result->results[i].value.data_string,
                    " ", "\\ ");
                influx_line += w;
                free(w);
            } else {
                influx_line += result->results[i].value.data_string;
            }
        }
    }

    // a space is required between tags and values
    influx_line += " ";

    // add data as field sets. This is data that does change
    for (int i = 0; i < result->num_results; i++) {

        if (!first_pass && result->results[i].type != BD_TYPE_TAG) {
            influx_line += ",";
        }

        switch (result->results[i].type) {
            /* field keys should escape commas, equal signs and spaces */
            case BD_TYPE_IP_STRING:
            case BD_TYPE_STRING:
                influx_line += result->results[i].key;
                influx_line += "=\"";

                /* string field values should escape double quotes and backslashes */
                if (strstr(result->results[i].value.data_string, "\"")) {
                    char *w = bd_replaceWord(result->results[i].value.data_string,
                        "\"", "\\\"");
                    influx_line += w;
                    free(w);
                } else {
                    influx_line += result->results[i].value.data_string;
                }
                influx_line += "\"";
                first_pass = 0;
                break;
            case BD_TYPE_FLOAT:
                snprintf(buf, INFLUX_BUF_LEN, "%f", result->results[i].value.data_float);
                influx_line += result->results[i].key;
                influx_line += "=";
                influx_line += buf;
                first_pass = 0;
                break;
            case BD_TYPE_DOUBLE:
                snprintf(buf, INFLUX_BUF_LEN, "%lf", result->results[i].value.data_double);
                influx_line += result->results[i].key;
                influx_line += "=";
                influx_line += buf;
                first_pass = 0;
                break;
            case BD_TYPE_INT:
                snprintf(buf, INFLUX_BUF_LEN, "%li", result->results[i].value.data_int);
                /* influxDB expects "i" and the end of a integer */
                influx_line += result->results[i].key;
                influx_line += "=";
                influx_line += buf;
                influx_line += "i";
                first_pass = 0;
                break;
            case BD_TYPE_UINT:
                snprintf(buf, INFLUX_BUF_LEN, "%li", result->results[i].value.data_uint);
                /* influxDB expects "u" at the end of uint however most versions do not
                   support it yet */
                influx_line += result->results[i].key;
                influx_line += "=";
                influx_line += buf;
                influx_line += "i";
                first_pass = 0;
                break;
            case BD_TYPE_BOOL:
                influx_line += result->results[i].key;
                influx_line += "=";
                if (result->results[i].value.data_bool) { influx_line += "t"; }
                else { influx_line += "f"; }
                first_pass = 0;
                break;
            default:
                break;
        }
    }

    // add the timestamp if it was set
    if (result->timestamp != 0) {
        influx_line += " ";
        // influx expects timestamp in nanoseconds
        snprintf(buf, INFLUX_BUF_LEN, "%lu", (result->timestamp*1000)*1000000);
        influx_line += buf;
    }

    return influx_line;
}

static int module_influxdb_contains_invalid_field_value(char *value) {

    for (int i = 0; i <= sizeof(value); i++) {
        if (value[i] == '"') {
            return 1;
        }

        if (value[i] == '\\') {
            return 2;
        }
    }

    return 0;
}

static int module_influxdb_contains_invalid_tag(char *value) {

    for (int i = 0; i <= sizeof(value); i++) {
        if (value[i] == ',') {
            return 1;
        }

        if (value[2] == '=') {
           return 2;
        }

        if (value[3] == ' ') {
            return 3;
        }
    }

    return 0;
}
