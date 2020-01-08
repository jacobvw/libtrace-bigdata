#include "module_elasticsearch.h"
#include <curl/curl.h>
#include <string>

#define BATCH_STRING_BUF 100

struct module_elasticsearch_conf {
    bd_cb_set *callbacks;
    bool enabled;
    char *host;
    int port;
    bool ssl_verifypeer;
    char *username;
    char *password;
    bool require_user_auth;
    bool batch_results;
    int batch_count;
};
static struct module_elasticsearch_conf *config;

typedef struct module_elasticsearch_options {
    CURL *curl;
    bd_result_set_t **results;
    int num_results;
    bool elastic_online;
} mod_elastic_opts_t;

void *module_elasticsearch_starting(void *tls) {

    struct curl_slist *headers = NULL;

    mod_elastic_opts_t *opts = (mod_elastic_opts_t *)malloc(sizeof(
        mod_elastic_opts_t));
    if (opts == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_elasticsearch_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    // create pointer space for results if batching is enabled
    if (config->batch_results) {
        opts->results = (bd_result_set_t **)malloc(sizeof(
            bd_result_set_t *) * config->batch_count);
        if (opts->results == NULL) {
            fprintf(stderr, "Unable to allocate memory. func. "
                "module_elasticsearch_starting()\n");
            exit(BD_OUTOFMEMORY);
        }
        opts->num_results = 0;
    }
    opts->elastic_online = 0;

    // init curl
    curl_global_init(CURL_GLOBAL_ALL);

    // get a curl handle
    opts->curl = curl_easy_init();
    if (opts->curl) {

        curl_easy_setopt(opts->curl, CURLOPT_PORT, config->port);

        headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");
        curl_easy_setopt(opts->curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(opts->curl, CURLOPT_POST, 1L);

        // if user auth is required
        if (config->require_user_auth) {
            // set username/password
            curl_easy_setopt(opts->curl, CURLOPT_USERNAME, config->username);
            curl_easy_setopt(opts->curl, CURLOPT_PASSWORD, config->password);
        }

        if (config->ssl_verifypeer) {
            curl_easy_setopt(opts->curl, CURLOPT_SSL_VERIFYPEER, 1);
        } else {
            curl_easy_setopt(opts->curl, CURLOPT_SSL_VERIFYPEER, 0);
        }
    }

    return opts;
}

/* define callback function for curl so output isnt spammed to standard output */
static size_t module_elasticsearch_callback(void *buffer, size_t size, size_t nmemb,
    void *userp) {

    return size * nmemb;
}

static int module_elasticsearch_export(bd_bigdata_t *bigdata, mod_elastic_opts_t *opts,
    const char *result, char *url) {

    CURLcode ret;

    // set the URL in curl
    curl_easy_setopt(opts->curl, CURLOPT_URL, url);
    // set the payload in curl
    curl_easy_setopt(opts->curl, CURLOPT_POSTFIELDS, result);
    // set callback to prevent libcurl sending spam to stdout
    curl_easy_setopt(opts->curl, CURLOPT_WRITEFUNCTION,
        module_elasticsearch_callback);

    // send to elasticsearch
    ret = curl_easy_perform(opts->curl);

    if (ret != CURLE_OK) {

        if (bigdata->global->config->debug > 0) {
            fprintf(stderr, "DEBUG 1: Elasticsearch is offline, result written to "
                "temp storage.\n");

            if (bigdata->global->config->debug > 1) {
                fprintf(stderr, "DEBUG 2: Failed to post to elasticsearch: %s.\n",
                    curl_easy_strerror(ret));
            }
        }

        /* set elasticsearch to offline */
        opts->elastic_online = 0;

        /* send the result to the temp file */
        bd_result_string_store(config->callbacks, result);

        return 2;
    } else {

        if (!opts->elastic_online && bigdata->global->config->debug > 0) {
            fprintf(stderr, "DEBUG 1: Elasticsearch is online.\n");
        }

        opts->elastic_online = 1;

        return 0;
    }
}

int module_elasticsearch_result(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    std::string out;
    std::string json;
    char buf[200];
    char buf2[200];
    int i;
    bd_result_set_t *cur_res;
    int ret = 1;
    char *result_queue;
    mod_elastic_opts_t *opts = (mod_elastic_opts_t *)mls;

    /* build the curl url */
    snprintf(buf, sizeof(buf), "%s%s%d%s%s%s", config->host, ":", config->port,
        "/", result->module, "/_bulk");

    /* If elasticsearch is online try to procces any results that may be stored within
     * elasticsearch's temp file */
    if (opts->elastic_online) {
        if ((result_queue = bd_result_string_read(config->callbacks)) != NULL) {

            ret = module_elasticsearch_export(bigdata, opts, result_queue, buf);

            free(result_queue);
        }
    }

    if (config->batch_results) {

        // if its time to output results construct a batch result all of them.
        if (opts->num_results >= config->batch_count) {

            // generate json a single json string for all results
            for (i = 0; i < opts->num_results; i++) {

                // get the current result
                cur_res = opts->results[i];

                // build the batch command
                snprintf(buf2, sizeof(buf2), "%s%s%s", "{\"index\":{\"_index\":\"",
                    cur_res->module, "\",\"_type\":\"_doc\"}}");
                // build the json string
                json = bd_result_set_to_json_string(cur_res);

                out += buf2;
                out += "\n";
                out += json;
                out += "\n";

                // finished with this result so unlock it
                bd_result_set_unlock(cur_res);
            }

            // reset the number of results held
            opts->num_results = 0;

            ret = module_elasticsearch_export(bigdata, opts, out.c_str(), buf);

       }

        // Store the current result in the batch
        // lock the result set
        bd_result_set_lock(result);
        // add to the array of results
        opts->results[opts->num_results] = result;
        // increment number of results
        opts->num_results += 1;

    } else {

        // build the index string
        snprintf(buf2, sizeof(buf2), "%s%s%s", "{\"index\":{\"_index\":\"",
            result->module, "\",\"_type\":\"_doc\"}}");
        /* get the json representation for the result */
        json = bd_result_set_to_json_string(result);

        out = buf2;
        out += json;

        ret = module_elasticsearch_export(bigdata, opts, out.c_str(), buf);
    }

    return ret;
}

int module_elasticsearch_stopping(void *tls, void *mls) {

    mod_elastic_opts_t *opts = (mod_elastic_opts_t *)mls;

    // cleanup curl
    curl_easy_cleanup(opts->curl);
    curl_global_cleanup();

    free(opts);

    return 0;
}

int module_elasticsearch_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

    int enter_level = *level;
    bool first_pass = 1;

    while (enter_level != *level || first_pass) {
        first_pass = 0;
        switch (event->type) {
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
                if (strcmp((char *)event->data.scalar.value, "require_user_auth") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0) {

                        config->require_user_auth = 1;
                    } else {
                        config->require_user_auth = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "username") == 0) {
                    consume_event(parser, event, level);
                    config->username = strdup((char *)event->data.scalar.value);
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "password") == 0) {
                    consume_event(parser, event, level);
                    config->password = strdup((char *)event->data.scalar.value);
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "port") == 0) {
                    consume_event(parser, event, level);
                    config->port = atoi((char *)event->data.scalar.value);
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
        bd_register_reporter_start_event(config->callbacks, module_elasticsearch_starting);
        bd_register_reporter_output_event(config->callbacks, module_elasticsearch_result);
        bd_register_reporter_stop_event(config->callbacks, module_elasticsearch_stopping);

        fprintf(stdout, "Elasticsearch Plugin Enabled\n");
    }
}

int module_elasticsearch_init(bd_bigdata_t *bigdata) {

    config = (struct module_elasticsearch_conf *)malloc(sizeof(
        struct module_elasticsearch_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_elasticsearch_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    config->enabled = 0;
    config->host = NULL;
    config->port = 9200;
    config->username = NULL;
    config->password = NULL;
    config->require_user_auth = 0;
    config->batch_results = 0;
    config->batch_count = 200;

    // create callback structure
    config->callbacks = bd_create_cb_set("elasticsearch");

    // register for the config event
    bd_register_config_event(config->callbacks, module_elasticsearch_config);
    config->callbacks->config_cb = (cb_config)module_elasticsearch_config;

    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);
}
