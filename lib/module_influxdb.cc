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

    char retention[10];	/* how long each result is kept within influx */
    int replication;	/* how many times each result is replicated
			 * witin the influx cluster. */
};
static struct module_influxdb_conf *config;

typedef struct module_influxdb_options {
    CURL *curl;
    bd_result_set_t **results;
    int num_results;
    int influx_online;
} mod_influxdb_opts_t;

void *module_influxdb_starting(void *tls);
int module_influxdb_post(bd_bigdata_t *bigdata, void *mls, bd_result_set *result);
void *module_influxdb_stopping(void *tls, void *mls);
static std::string module_influxdb_result_to_query(bd_result_set *result);
static size_t module_influxdb_callback(void *buffer, size_t size, size_t nmemb,
    void *userp);
static size_t module_influxdb_policy_callback(void *buffer, size_t size,
    size_t nmemb, void *userp);
static void module_influxdb_policy_create(const char *action);

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
    /* set to -1. Unknown */
    opts->influx_online = -1;

    // Initialise curl
    curl_global_init(CURL_GLOBAL_ALL);

    // get a curl handle
    opts->curl = curl_easy_init();
    if (opts->curl) {
        char buf[200];
        snprintf(buf, sizeof(buf), "%s%s%s%s%s%s%s", config->host, "/write?db=", config->db,
            "&u=", config->usr, "&p=", config->pwd);

        curl_easy_setopt(opts->curl, CURLOPT_URL, buf);
        curl_easy_setopt(opts->curl, CURLOPT_PORT, config->port);

        /* define callback function */
        curl_easy_setopt(opts->curl, CURLOPT_WRITEFUNCTION,
            module_influxdb_callback);

        if (config->ssl_verifypeer) {
            curl_easy_setopt(opts->curl, CURLOPT_SSL_VERIFYPEER, 1);
        } else {
            curl_easy_setopt(opts->curl, CURLOPT_SSL_VERIFYPEER, 0);
        }
    }

    /* Apply the policy for the database */
    module_influxdb_policy_create("CREATE");

    return opts;
}

static void module_influxdb_policy_create(const char *action) {

    CURL *retention_curl;
    char retention_url[200];
    char retention_data[200];

    /* set retension and replication options */
    retention_curl = curl_easy_init();
    if (retention_curl) {

        /* set the curl URL */
        snprintf(retention_url, sizeof(retention_url), "%s/query?u=%s&p=%s",
            config->host, config->usr, config->pwd);
        /* create the new policy */
        snprintf(retention_data, sizeof(retention_data), "q=%s RETENTION "
            "POLICY \"libtracebigdata\" ON \"%s\" DURATION %s REPLICATION "
            "%d DEFAULT", action, config->db, config->retention, config->replication);

        curl_easy_setopt(retention_curl, CURLOPT_URL, retention_url);
        curl_easy_setopt(retention_curl, CURLOPT_PORT, config->port);
        curl_easy_setopt(retention_curl, CURLOPT_WRITEFUNCTION,
            module_influxdb_policy_callback);

        if (config->ssl_verifypeer) {
            curl_easy_setopt(retention_curl, CURLOPT_SSL_VERIFYPEER, 1);
        } else {
            curl_easy_setopt(retention_curl, CURLOPT_SSL_VERIFYPEER, 0);
        }

        curl_easy_setopt(retention_curl, CURLOPT_POSTFIELDS, retention_data);
        curl_easy_perform(retention_curl);
        curl_easy_cleanup(retention_curl);
    }
}

static size_t module_influxdb_policy_callback(void *buffer, size_t size,
    size_t nmemb, void *userp) {

    /* match the following on retention policy existing.
     * {"results":[{"statement_id":0,"error":"retention policy already exists"}]}
     * if matches try to alter the policy instead */

    char *errorstr;
    errorstr = strstr((char *)buffer, "error");
    if (errorstr != NULL) {
        errorstr = strstr((char *)buffer, "exists");
        if (errorstr != NULL) {
            module_influxdb_policy_create("ALTER");
        }
    }

    return size *nmemb;
}

static size_t module_influxdb_callback(void *buffer, size_t size, size_t nmemb,
    void *userp) {

    bool error;
    char *errorstr;

    /* influx only returns a string on error? */
    errorstr = strstr((char *)buffer, "error");
    if (errorstr == NULL) {
        error = 0;
    } else {
        logger(LOG_INFO, "InfluxDB error: %.*s", strlen((char *)buffer)-1,
            (char *)buffer);
    }

    return size *nmemb;
}

int module_influxdb_export_result(bd_bigdata_t *bigdata, mod_influxdb_opts_t *opts,
    const char *result) {

    CURLcode ret;

    curl_easy_setopt(opts->curl, CURLOPT_POSTFIELDS, result);

    /* Perform the request, ret will get the return code */
    ret = curl_easy_perform(opts->curl);

    /* Check for errors */
    if(ret != CURLE_OK) {

        /* If InfluxDB was previously online */
        if (opts->influx_online) {
            logger(LOG_INFO, "InfluxDB is offline.");
        }

        logger(LOG_DEBUG, "Failed to post to influxDB: %s.", curl_easy_strerror(ret));

        /* Set influxDB to offline */
        opts->influx_online = 0;

        /* Send the result to the temp file */
        bd_result_string_store(config->callbacks, result);

        return 2;
    } else {

        /* If InfluxDB was previously offline or status was unknown */
        if (opts->influx_online < 1) {
            logger(LOG_INFO, "InfluxDB is online.");
        }

        logger(LOG_DEBUG, "InfluxDB executed: %s", result);

        /* set influxDB as online */
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
                    config->pwd = strdup((char *)event->data.scalar.value);
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
                if (strcmp((char *)event->data.scalar.value, "retention") == 0) {
                    consume_event(parser, event, level);
                    strncpy(config->retention, (char *)event->data.scalar.value,
                        sizeof(config->retention));
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "replication") == 0) {
                    consume_event(parser, event, level);
                    config->replication = atoi((char *)event->data.scalar.value);
                    if (config->replication == 0) {
                        logger(LOG_WARNING, "Invalid replication value. "
                            "module_influxDB. setting to default 1");
                        config->replication = 1;
                    }
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
    strncpy(config->retention, "inf", 3);
    config->replication = 1;

    // create callback set
    config->callbacks = bd_create_cb_set("influxdb");

    // define config callback
    config->callbacks->config_cb = (cb_config)module_influxdb_config;

    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}

static std::string module_influxdb_result_to_query_tags(bd_result_set *result,
    std::string prefix) {

    std::string influx_line = "";
    std::string new_prefix = "";
    bool seen_tag = 0;
    int i;

    for (i = 0; i < result->num_results; i++) {

        switch (result->results[i]->type) {

            case BD_TYPE_TAG: {

                influx_line += ",";

                /* if the tag key contains a space */
                if (strstr(result->results[i]->key, " ")) {
                    // escape all spaces
                    char *w = bd_replaceWord(result->results[i]->key, " ", "\\ ");
                    influx_line += prefix;
                    influx_line += w;
                    free(w);
                } else {
                    influx_line += prefix;
                    influx_line += result->results[i]->key;
                }

                influx_line += "=";

                /* if the tag result contains a space */
                if (strstr(result->results[i]->value.data_string, " ")) {
                    /* escape all spaces */
                    char *w = bd_replaceWord(result->results[i]->value.data_string,
                        " ", "\\ ");
                    influx_line += w;
                    free(w);
                } else {
                    influx_line += result->results[i]->value.data_string;
                }
                break;
            }
            case BD_TYPE_RESULT_SET: {
                /* generate new tag prefix */
                new_prefix += prefix;

                /* if the tag key contains a space */
                if (strstr(result->results[i]->key, " ")) {
                    // escape all spaces
                    char *w = bd_replaceWord(result->results[i]->key, " ", "\\ ");
                    new_prefix += w;
                } else {
                    new_prefix += result->results[i]->key;
                }

                new_prefix += ".";

                influx_line += module_influxdb_result_to_query_tags(
                    result->results[i]->value.data_result_set,
                    new_prefix);
                break;
            }
            default:
                break;
        }
    }

    return influx_line;

}

static std::string module_influxdb_result_to_query_fields(bd_result_set *result,
    std::string prefix, bool nested) {

    std::string influx_line = "";
    std::string new_prefix;
    char buf[INFLUX_BUF_LEN] = "";
    bool first_pass = 1;

    // add data as field sets. This is data that does change
    for (int i = 0; i < result->num_results; i++) {

        switch (result->results[i]->type) {
            // field keys should escape commas, equal signs and spaces
            case BD_TYPE_IP_STRING:
            case BD_TYPE_STRING:
                // only not add preceding , if this is the first item and
                // this is not a nested result.
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                influx_line += (prefix + result->results[i]->key);
                influx_line += "=\"";

                // string field values should escape double quotes and backslashes
                if (strstr(result->results[i]->value.data_string, "\"")) {
                    char *w = bd_replaceWord(result->results[i]->value.data_string,
                        "\"", "\\\"");
                    influx_line += w;
                    free(w);
                } else {
                    influx_line += result->results[i]->value.data_string;
                }
                influx_line += "\"";
                break;
            case BD_TYPE_FLOAT:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                snprintf(buf, INFLUX_BUF_LEN, "%f", result->results[i]->value.data_float);
                influx_line += (prefix + result->results[i]->key);
                influx_line += "=";
                influx_line += buf;
                break;
            case BD_TYPE_DOUBLE:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                snprintf(buf, INFLUX_BUF_LEN, "%lf", result->results[i]->value.data_double);
                influx_line += (prefix + result->results[i]->key);
                influx_line += "=";
                influx_line += buf;
                break;
            case BD_TYPE_INT:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                snprintf(buf, INFLUX_BUF_LEN, "%li", result->results[i]->value.data_int);
                // influxDB expects "i" and the end of a integer
                influx_line += (prefix + result->results[i]->key);
                influx_line += "=";
                influx_line += buf;
                influx_line += "i";
                break;
            case BD_TYPE_UINT:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                snprintf(buf, INFLUX_BUF_LEN, "%li", result->results[i]->value.data_uint);
                // influxDB expects "u" at the end of uint however most versions do not
                //   support it yet
                influx_line += (prefix + result->results[i]->key);
                influx_line += "=";
                influx_line += buf;
                influx_line += "i";
                break;
            case BD_TYPE_BOOL:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                influx_line += (prefix + result->results[i]->key);
                influx_line += "=";
                if (result->results[i]->value.data_bool) { influx_line += "t"; }
                else { influx_line += "f"; }
                break;
            case BD_TYPE_STRING_ARRAY:
            case BD_TYPE_IP_STRING_ARRAY:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%s%s.%d",
                        prefix.c_str(), result->results[i]->key, j);
                    influx_line += buf;
                    influx_line += "=\"";
                    if (strstr(result->results[i]->value.data_string_array[j], "\"")) {
                        char *w = bd_replaceWord(
                            result->results[i]->value.data_string_array[j],
                            "\"", "\\\"");
                        influx_line += w;
                        free(w);
                    } else {
                        influx_line += result->results[i]->value.data_string_array[j];
                    }
                    influx_line += "\"";
                    if (j+1 != result->results[i]->num_values) {
                        influx_line += ",";
                    }
                }
                break;
            case BD_TYPE_FLOAT_ARRAY:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%s%s.%d",
                        prefix.c_str(), result->results[i]->key, j);
                    influx_line += buf;
                    influx_line += "=";
                    snprintf(buf, sizeof(buf), "%f",
                        result->results[i]->value.data_float_array[j]);
                    influx_line += buf;
                    if (j+1 != result->results[i]->num_values) {
                        influx_line += ",";
                    }
                }
                break;
            case BD_TYPE_DOUBLE_ARRAY:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%s%s.%d",
                        prefix.c_str(), result->results[i]->key, j);
                    influx_line += buf;
                    influx_line += "=";
                    snprintf(buf, sizeof(buf), "%lf",
                        result->results[i]->value.data_double_array[j]);
                    influx_line += buf;
                    if (j+1 != result->results[i]->num_values) {
                        influx_line += ",";
                    }
                }
                break;
            case BD_TYPE_INT_ARRAY:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%s%s.%d",
                        prefix.c_str(), result->results[i]->key, j);
                    influx_line += buf;
                    influx_line += "=";
                    snprintf(buf, sizeof(buf), "%li",
                        result->results[i]->value.data_int_array[j]);
                    influx_line += buf;
                    if (j+1 != result->results[i]->num_values) {
                        influx_line += ",";
                    }
                }
                break;
            case BD_TYPE_UINT_ARRAY:
                if (!first_pass || nested) {
                    influx_line += ",";
                }
                first_pass = 0;
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(buf), "%s%s.%d",
                        prefix.c_str(), result->results[i]->key, j);
                    influx_line += buf;
                    influx_line += "=";
                    snprintf(buf, sizeof(buf), "%lu",
                        result->results[i]->value.data_uint_array[j]);
                    influx_line += buf;
                    if (j+1 != result->results[i]->num_values) {
                        influx_line += ",";
                    }
                }
                break;
            case BD_TYPE_RESULT_SET:
                new_prefix = prefix;
                new_prefix += result->results[i]->key;
                new_prefix += ".";

                influx_line += module_influxdb_result_to_query_fields(
                    result->results[i]->value.data_result_set,
                    new_prefix,
                    1);
                break;
            case BD_TYPE_RESULT_SET_ARRAY:
                for (int j = 0; j < result->results[i]->num_values; j++) {
                    snprintf(buf, sizeof(new_prefix), "%s%s.%d.",
                        prefix.c_str(), result->results[i]->key, j);
                    influx_line += module_influxdb_result_to_query_fields(
                        result->results[i]->value.data_result_set_array[j],
                        buf,
                        1);
                }
                break;
            default:
                break;
        }
    }

    return influx_line;
}

static std::string module_influxdb_result_to_query(bd_result_set *result) {

    std::string influx_line;
    char buf[INFLUX_BUF_LEN] = "";

    // insert measurement/module name
    influx_line += result->module;

    // insert any tags
    influx_line += module_influxdb_result_to_query_tags(result, "");

    // a space is required between tags and fields
    influx_line += " ";

    // insert any fields
    influx_line += module_influxdb_result_to_query_fields(result, "", 0);

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
