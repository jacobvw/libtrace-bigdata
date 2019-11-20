#include "module_influxdb.h"
#include <curl/curl.h>

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
};
static struct module_influxdb_conf *config;

typedef struct module_influxdb_options {
    CURL *curl;
} mod_influxdb_opts_t;

void *module_influxdb_starting(void *tls);
int module_influxdb_post(bd_bigdata_t *bigdata, void *mls, bd_result_set *result);
void *module_influxdb_stopping(void *tls, void *mls);
static char *module_influxdb_result_to_query(bd_result_set *result);

void *module_influxdb_starting(void *tls) {
    mod_influxdb_opts_t *opts = (mod_influxdb_opts_t *)malloc(sizeof(mod_influxdb_opts_t));

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

int module_influxdb_post(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    char *query;
    CURLcode res;

    mod_influxdb_opts_t *opts = (mod_influxdb_opts_t *)mls;

    /* convert result set into influxDB query */
    query = module_influxdb_result_to_query(result);

    /* Now specify the POST data */
    curl_easy_setopt(opts->curl, CURLOPT_POSTFIELDS, query);

    /* Perform the request, res will get the return code */
    res = curl_easy_perform(opts->curl);
    /* Check for errors */
    if(res != CURLE_OK) {
      fprintf(stderr, "failed to post to influxDB: %s\n", curl_easy_strerror(res));
    }

    if (bigdata->global->config->debug) {
        fprintf(stderr, "%s\n", query);
    }

    free(query);

    return res;
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

        fprintf(stdout, "InfluxDB Plugin Enabled\n");
    }

    return 0;
}

int module_influxdb_init(bd_bigdata_t *bigdata) {

    config = (struct module_influxdb_conf *)malloc(sizeof(
        struct module_influxdb_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_influxdb_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    config->enabled = 0;
    config->host = NULL;
    config->port = 8086;
    config->db = NULL;
    config->usr = NULL;
    config->pwd = NULL;
    config->ssl_verifypeer = 1;

    // create callback set
    config->callbacks = bd_create_cb_set("influxdb");

    // define config callback
    config->callbacks->config_cb = (cb_config)module_influxdb_config;

    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}

static char *module_influxdb_result_to_query(bd_result_set *result) {

    bool first_pass = true;
    char *str;
    char buf[INFLUX_BUF_LEN] = "";

    str = (char *)malloc(INFLUX_LINE_LEN);
    if (str == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. module_influxdb_post()\n");
        exit(BD_OUTOFMEMORY);
    }
    str[0] = '\0';

    // insert measurement/module name
    strcat(str, result->module);
    strcat(str, ",");

    // add tag sets. This is meta data that doesnt change
    strcat(str, "capture_application=libtrace-bigdata");
    for (int i = 0; i < result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_TAG) {
            strcat(str, ",");
            /* if the tag key contains a space */
            if (strstr(result->results[i].key, " ")) {
                // escape all spaces
                char *w = bd_replaceWord(result->results[i].key, " ", "\\ ");
                strcat(str, w);
                free(w);
            } else {
                strcat(str, result->results[i].key);
            }

            strcat(str, "=");

            /* if the tag result contains a space */
            if (strstr(result->results[i].value.data_string, " ")) {
                /* escape all spaces */
                char *w = bd_replaceWord(result->results[i].value.data_string,
                    " ", "\\ ");
                strcat(str, w);
                free(w);
            } else {
                strcat(str, result->results[i].value.data_string);
            }
        }
    }

    // a space is required between tags and values
    strcat(str, " ");

    // add data as field sets. This is data that does change
    for (int i = 0; i < result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_STRING) {
            if (!first_pass) strcat(str, ",");
            strcat(str, result->results[i].key);
            strcat(str, "=\"");
            strcat(str, result->results[i].value.data_string);
            strcat(str, "\"");
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_FLOAT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, INFLUX_BUF_LEN, "%f", result->results[i].value.data_float);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_DOUBLE) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, INFLUX_BUF_LEN, "%lf", result->results[i].value.data_double);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_INT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, INFLUX_BUF_LEN, "%li", result->results[i].value.data_int);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            // influx expects "i" at the end of a int64
            strcat(str, "i");
            first_pass = false;
        // influxdb needs to be compiled with uint64 support. NOTE i at end
        } else if (result->results[i].type == BD_TYPE_UINT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, INFLUX_BUF_LEN, "%lu", result->results[i].value.data_uint);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            // influx expects "u" at the end of a uint64, however most versions dont
            // support it yet unless compiled with a specific flag
            strcat(str, "i");
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_BOOL) {
            if (!first_pass) strcat(str, ",");
            strcat(str, result->results[i].key);
            strcat(str, "=");
            if (result->results[i].value.data_bool) {
                strcat(str, "t");
            } else {
                strcat(str, "f");
            }
            first_pass = false;
        }
    }

    // add the timestamp if it was set
    if (result->timestamp != 0) {
        strcat(str, " ");
        // influx expects timestamp in nanoseconds
        snprintf(buf, INFLUX_BUF_LEN, "%lu", (result->timestamp*1000000)*1000);
        strcat(str, buf);
    }

    return str;
}


