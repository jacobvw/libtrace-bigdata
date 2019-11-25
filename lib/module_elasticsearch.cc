#include "module_elasticsearch.h"
#include <curl/curl.h>

struct module_elasticsearch_conf {
    bd_cb_set *callbacks;
    bool enabled;
    char *host;
    int port;
    bool ssl_verifypeer;
    char *username;
    char *password;
    bool require_user_auth;
};
static struct module_elasticsearch_conf *config;

typedef struct module_elasticsearch_options {
    CURL *curl;
} mod_elastic_opts_t;

void *module_elasticsearch_starting(void *tls) {

    mod_elastic_opts_t *opts = (mod_elastic_opts_t *)malloc(sizeof(
        mod_elastic_opts_t));
    if (opts == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_elasticsearch_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    struct curl_slist *headers = NULL;

    // init curl
    curl_global_init(CURL_GLOBAL_ALL);

    // get a curl handle
    opts->curl = curl_easy_init();
    if (opts->curl) {

        curl_easy_setopt(opts->curl, CURLOPT_PORT, config->port);

        headers = curl_slist_append(headers, "Content-Type: application/json");
        curl_easy_setopt(opts->curl, CURLOPT_HTTPHEADER, headers);

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

int module_elasticsearch_result(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    char buf[200];
    CURLcode res;
    char *json;
    mod_elastic_opts_t *opts = (mod_elastic_opts_t *)mls;

    if (opts->curl) {
        snprintf(buf, sizeof(buf), "%s%s%d%s%s%s", config->host, ":", config->port,
            "/", result->module, "/_doc");

        curl_easy_setopt(opts->curl, CURLOPT_URL, buf);

        json = bd_result_set_to_json_string(result);
        curl_easy_setopt(opts->curl, CURLOPT_POSTFIELDS, json);

        res = curl_easy_perform(opts->curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "Failed to post to elasticsearch: %s\n",
                curl_easy_strerror(res));
        }

        if (bigdata->global->config->debug) {
            fprintf(stderr, "elasticsearch: %s\n", json);
        }

        free(json);
    }

    return 0;
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

    // create callback structure
    config->callbacks = bd_create_cb_set("elasticsearch");

    // register for the config event
    bd_register_config_event(config->callbacks, module_elasticsearch_config);
    config->callbacks->config_cb = (cb_config)module_elasticsearch_config;

    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);
}
