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

    bool template_enabled;
    char *template_name;
    char *template_mapping;
    /* ILM policy settings */
    bool ilm_policy_enabled;
    char *ilm_policy_name;
    /* hot ilm phase */
    char *hot_max_index_size;
    int hot_max_documents;
    char *hot_max_age;
    int hot_index_priority;
    /* warm ilm phase */
    bool warm_phase_enabled;
    char *warm_min_age;
    int warm_number_replicas;
    int warm_shrink_shards;
    int warm_merge_segments;
    int warm_index_priority;
    /* cold ilm phase */
    bool cold_phase_enabled;
    char *cold_min_age;
    int cold_number_replicas;
    bool cold_freeze_index;
    int cold_index_priority;
    /* delete phase */
    bool delete_phase_enabled;
    char *delete_min_age;
};
static struct module_elasticsearch_conf *config;

typedef struct module_elasticsearch_options {
    CURL *curl;
    bd_result_set_t **results;
    int num_results;
    int elastic_online;
} mod_elastic_opts_t;

struct ilm_json_put {
    const char *data;
    size_t len;
};

static size_t module_elasticsearch_callback(void *buffer, size_t size, size_t nmemb,
    void *userp);

static void module_elasticsearch_policy_create();
static int module_elasticsearch_valid_policy_age(char *age);
static int module_elasticsearch_valid_policy_size(char *size);

static void module_elasticsearch_template_create();

static int module_elasticsearch_put(char *endpoint, char *data,
    size_t len);
static size_t module_elasticsearch_put_read_cb(void *buffer, size_t size, size_t nmemb,
    void *userp);
static size_t module_elasticsearch_put_write_cb(void *buffer, size_t size, size_t nmemb,
    void *userp);

void *module_elasticsearch_starting(void *tls) {

    struct curl_slist *headers = NULL;

    mod_elastic_opts_t *opts = (mod_elastic_opts_t *)malloc(sizeof(
        mod_elastic_opts_t));
    if (opts == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_elasticsearch_starting()");
        exit(BD_OUTOFMEMORY);
    }

    // create pointer space for results if batching is enabled
    if (config->batch_results) {
        opts->results = (bd_result_set_t **)malloc(sizeof(
            bd_result_set_t *) * config->batch_count);
        if (opts->results == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. "
                "module_elasticsearch_starting()");
            exit(BD_OUTOFMEMORY);
        }
        opts->num_results = 0;
    }
    /* set to -1. Unknown */
    opts->elastic_online = -1;

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

        // set the callback function
        curl_easy_setopt(opts->curl, CURLOPT_WRITEFUNCTION,
            module_elasticsearch_callback);
    }

    /* create elasticseach template and policy */
    module_elasticsearch_template_create();
    module_elasticsearch_policy_create();

    return opts;
}

static size_t module_elasticsearch_callback(void *buffer, size_t size, size_t nmemb,
    void *userp) {

    bool error;
    char *errorstr;

    /* find the first occurance of errors in the json result */
    errorstr = strstr((char *)buffer, "errors");
    if (errorstr == NULL) {
        error = 0;
    } else {
        // 8th char after the buffer should be t of f
        if (errorstr[8] == 't') {
            logger(LOG_INFO, "Elasticsearch error: %s", (char *)buffer);
        }
    }

    return size * nmemb;
}

static int module_elasticsearch_export(bd_bigdata_t *bigdata, mod_elastic_opts_t *opts,
    const char *result, char *url) {

    CURLcode ret;

    // set the URL in curl
    curl_easy_setopt(opts->curl, CURLOPT_URL, url);
    // set the payload in curl
    curl_easy_setopt(opts->curl, CURLOPT_POSTFIELDS, result);

    // send to elasticsearch
    ret = curl_easy_perform(opts->curl);

    if (ret != CURLE_OK) {

        /* If elasticsearch was previously online */
        if (opts->elastic_online) {
            logger(LOG_INFO, "Elasticsearch is offline.");
        }

        logger(LOG_DEBUG, "Failed to post to elasticsearch: %s",
            curl_easy_strerror(ret));

        /* set elasticsearch to offline */
        opts->elastic_online = 0;

        /* send the result to the temp file */
        bd_result_string_store(config->callbacks, result);

        return 2;
    } else {

        /* if elasticsearch was previously offline or status was unknonwn */
        if (opts->elastic_online < 1) {
            logger(LOG_INFO, "Elasticsearch is online.");
        }

        logger(LOG_DEBUG, "Elasticsearch executed %s", result);

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
                snprintf(buf2, sizeof(buf2), "{\"index\":{\"_index\":\""
                    "libtrace-bigdata\",\"_type\":\"_doc\"}}");
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
        snprintf(buf2, sizeof(buf2), "{\"index\":{\"_index\":\""
            "libtrace-bigdata\",\"_type\":\"_doc\"}}");
        /* get the json representation for the result */
        json = bd_result_set_to_json_string(result);

        out = buf2;
        out += "\n";
        out += json;
        out += "\n";

        ret = module_elasticsearch_export(bigdata, opts, out.c_str(), buf);
    }

    return ret;
}

int module_elasticsearch_stopping(void *tls, void *mls) {

    mod_elastic_opts_t *opts = (mod_elastic_opts_t *)mls;

    // cleanup curl
    curl_easy_cleanup(opts->curl);
    curl_global_cleanup();

    if (config->username != NULL) {
        free(config->username);
    }
    if (config->password != NULL) {
        free(config->password);
    }
    if (config->hot_max_index_size != NULL) {
        free(config->hot_max_index_size);
    }
    if (config->hot_max_age != NULL) {
        free(config->hot_max_age);
    }
    if (config->warm_min_age != NULL) {
        free(config->warm_min_age);
    }
    if (config->cold_min_age != NULL) {
        free(config->cold_min_age);
    }
    if (config->delete_min_age != NULL) {
        free(config->delete_min_age);
    }

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
                if (strcmp((char *)event->data.scalar.value, "template_enabled") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0) {

                        config->template_enabled = 1;
                    } else {
                        config->template_enabled = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "template_name") == 0) {
                    consume_event(parser, event, level);
                    config->template_name = strdup((char *)event->data.scalar.value);
                }
                if (strcmp((char *)event->data.scalar.value, "template_mapping") == 0) {
                    consume_event(parser, event, level);
                    config->template_mapping = strdup((char *)event->data.scalar.value);
                }
                /* ILM policy hot phase */
                if (strcmp((char *)event->data.scalar.value, "ilm_policy_enabled") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0) {

                        config->ilm_policy_enabled = 1;
                    } else {
                        config->ilm_policy_enabled = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "ilm_policy_name") == 0) {
                    consume_event(parser, event, level);
                    config->ilm_policy_name = strdup((char *)event->data.scalar.value);
                }
                if (strcmp((char *)event->data.scalar.value, "hot_max_index_size") == 0) {
                    consume_event(parser, event, level);
                    if (!module_elasticsearch_valid_policy_size((char *)event->data.scalar.value)) {
                        logger(LOG_INFO, "Invalid value for elasticsearch hot_max_index_size");
                    } else {
                        config->hot_max_index_size = strdup((char *)event->data.scalar.value);
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "hot_max_documents") == 0) {
                    consume_event(parser, event, level);
                    config->hot_max_documents = atoi((char *)event->data.scalar.value);
                    if (config->hot_max_documents == 0) {
                        logger(LOG_INFO, "Invalid value for elasticsearch hot_max_documents");
                        config->hot_max_documents = -1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "hot_max_age") == 0) {
                    consume_event(parser, event, level);
                    if (!module_elasticsearch_valid_policy_age((char *)event->data.scalar.value)) {
                        logger(LOG_INFO, "Invalid value for elasticsearch hot_max_age");
                    } else {
                        config->hot_max_age = strdup((char *)event->data.scalar.value);
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "hot_index_priority") == 0) {
                    consume_event(parser, event, level);
                    config->hot_index_priority = atoi((char *)event->data.scalar.value);
                    if (config->hot_index_priority == 0) {
                        logger(LOG_INFO, "Invalid value for elasticsearch hot_index_priority");
                        config->hot_index_priority = -1;
                    }
                    break;
                }
                /* ILM policy warm phase */
                if (strcmp((char *)event->data.scalar.value, "warm_phase_enabled") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0) {

                        config->warm_phase_enabled = 1;
                    } else {
                        config->warm_phase_enabled = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "warm_min_age") == 0) {
                    consume_event(parser, event, level);
                    if (!module_elasticsearch_valid_policy_age((char *)event->data.scalar.value)) {
                        logger(LOG_INFO, "Invalid value for elasticsearch warm_min_age");
                    } else {
                        config->warm_min_age = strdup((char *)event->data.scalar.value);
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "warm_number_replicas") == 0) {
                    consume_event(parser, event, level);
                    config->warm_number_replicas = atoi((char *)event->data.scalar.value);
                    if (config->warm_number_replicas == 0) {
                        logger(LOG_INFO, "Invalid value for elasticsearch warm_number_replicas");
                        config->warm_number_replicas = -1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "warm_shrink_shards") == 0) {
                    consume_event(parser, event, level);
                    config->warm_shrink_shards = atoi((char *)event->data.scalar.value);
                    if (config->warm_shrink_shards == 0) {
                        logger(LOG_INFO, "Invalid value for elasticsearch warm_shrink_shards");
                        config->warm_shrink_shards = -1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "warm_merge_segments") == 0) {
                    consume_event(parser, event, level);
                    config->warm_merge_segments = atoi((char *)event->data.scalar.value);
                    if (config->warm_merge_segments == 0) {
                        logger(LOG_INFO, "Invalid value for elasticsearch warm_merge_segments");
                        config->warm_merge_segments = -1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "warm_index_priority") == 0) {
                    consume_event(parser, event ,level);
                    config->warm_index_priority = atoi((char *)event->data.scalar.value);
                    if (config->warm_index_priority == 0) {
                        logger(LOG_INFO, "Invalid value for elasticsearch warm_index_priority");
                        config->warm_index_priority = -1;
                    }
                    break;
                }
                /* ILM cold phase */
                if (strcmp((char *)event->data.scalar.value, "cold_phase_enabled") == 0) {
                    consume_event(parser, event ,level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0) {

                        config->cold_phase_enabled = 1;
                    } else {
                        config->cold_phase_enabled = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "cold_min_age") == 0) {
                    consume_event(parser, event ,level);
                    if (!module_elasticsearch_valid_policy_age((char *)event->data.scalar.value)) {
                        logger(LOG_INFO, "Invalid value for elasticsearch cold_min_age");
                    } else {
                        config->cold_min_age = strdup((char *)event->data.scalar.value);
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "cold_number_replicas") == 0) {
                    consume_event(parser, event ,level);
                    config->cold_number_replicas = atoi((char *)event->data.scalar.value);
                    if (config->cold_number_replicas == 0) {
                        logger(LOG_INFO, "Invalid value for elasticsearch cold_number_replicas");
                        config->cold_number_replicas = -1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "cold_freeze_index") == 0) {
                    consume_event(parser, event ,level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0) {

                        config->cold_freeze_index = 1;
                    } else {
                        config->cold_freeze_index = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "cold_index_priority") == 0) {
                    consume_event(parser, event ,level);
                    config->cold_index_priority = atoi((char *)event->data.scalar.value);
                    if (config->cold_index_priority == 0) {
                        logger(LOG_INFO, "Invalid value for elasticsearch cold_index_priority");
                        config->cold_index_priority = -1;
                    }
                    break;
                }
                /* ILM delete phase */
                if (strcmp((char *)event->data.scalar.value, "delete_phase_enabled") == 0) {
                    consume_event(parser, event ,level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0) {

                        config->delete_phase_enabled = 1;
                    } else {
                        config->delete_phase_enabled = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "delete_min_age") == 0) {
                    consume_event(parser, event ,level);
                    if (!module_elasticsearch_valid_policy_age((char *)event->data.scalar.value)) {
                        logger(LOG_INFO, "Invalid value for elasticsearch delete_min_age");
                    } else {
                        config->delete_min_age = strdup((char *)event->data.scalar.value);
                    }
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

        logger(LOG_INFO, "Elasticsearch Plugin Enabled");
    }

    return 0;
}

int module_elasticsearch_init(bd_bigdata_t *bigdata) {

    config = (struct module_elasticsearch_conf *)malloc(sizeof(
        struct module_elasticsearch_conf));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_elasticsearch_init()");
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

    config->template_enabled = 0;
    config->template_name = NULL;
    config->template_mapping = NULL;

    /* ILM policy settings */
    config->ilm_policy_enabled = 0;
    config->ilm_policy_name = NULL;
    /* hot ilm phase */
    config->hot_max_index_size = NULL;
    config->hot_max_documents = -1;
    config->hot_max_age = NULL;
    config->hot_index_priority = -1;
    /* warm ilm phase */
    config->warm_phase_enabled = 0;
    config->warm_min_age = NULL;
    config->warm_number_replicas = -1;
    config->warm_shrink_shards = -1;
    config->warm_merge_segments = -1;
    config->warm_index_priority = -1;
    /* cold ilm phase */
    config->cold_phase_enabled = 0;
    config->cold_min_age = NULL;
    config->cold_number_replicas = -1;
    config->cold_freeze_index = 0;
    config->cold_index_priority = -1;
    /* delete phase */
    config->delete_phase_enabled = 0;
    config->delete_min_age = NULL;

    // create callback structure
    config->callbacks = bd_create_cb_set("elasticsearch");

    // register for the config event
    bd_register_config_event(config->callbacks, module_elasticsearch_config);
    config->callbacks->config_cb = (cb_config)module_elasticsearch_config;

    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}

static int module_elasticsearch_valid_policy_age(char *age) {

    int len = strlen(age);

    /* len must be atleast 2 */
    if (len < 2) {
        return 0;
    }
    if (age[len-1] == 'd' ||
        age[len-1] == 'h' ||
        age[len-1] == 'm' ||
        age[len-1] == 's') {

        return 1;
    }

    /* len must now be 3 or more */
    if (len < 3) {
        return 0;
    }
    if (age[len-2] == 'm' && age[len-1] == 's') {
        return 1;
    }

    /* len must now be 6 or more */
    if (len < 6) {
        return 0;
    }
    if (age[len-5] == 'n' && age[len-4] == 'a' && age[len-3] == 'n' &&
        age[len-2] == 'o' && age[len-1] == 's') {

        return 1;
    }

    /* len must now be 7 or more */
    if (len < 7) {
        return 0;
    }
    if (age[len-6] == 'm' && age[len-5] == 'i' && age[len-4] == 'c' &&
        age[len-3] == 'r' && age[len-2] == 'o' && age[len-1] == 's') {

        return 1;
    }

    return 0;
}

static int module_elasticsearch_valid_policy_size(char *size) {

    int len = strlen(size);

    /* must be atleast 2 */
    if (len < 2) {
        return 0;
    }
    if (size[len-1] == 'b') {
        return 1;
    }

    /* must be atleast 3 */
    if (size[len-1] == 'b') {

        if (size[len-2] == 't' || size[len-2] == 'p' ||
            size[len-2] == 'g' || size[len-2] == 'm' ||
            size[len-2] == 'k') {

            return 1;
        }
    }

    return 0;
}

static void module_elasticsearch_policy_create() {

    std::string policy_json;
    char buf[100];
    bool prev = 0;

    /* return if ilm policy is not enabled */
    if (!(config->ilm_policy_enabled)) {
        return;
    }

    /* generate the policy json */
    policy_json = "{\"policy\":{\"phases\":{";
    policy_json += "\"hot\":{\"min_age\":\"0\",\"actions\":{";

    if (config->hot_max_index_size != NULL ||
        config->hot_max_documents > 0 ||
        config->hot_max_age != NULL) {

        policy_json += "\"rollover\":{";

        if (config->hot_max_index_size != NULL) {
            policy_json += "\"max_size\":\"";
            policy_json += config->hot_max_index_size;
            policy_json += "\"";
            prev = 1;
        }

        if (config->hot_max_documents > 0) {
            if (prev) { policy_json += ","; }
            snprintf(buf, sizeof(buf), "%d", config->hot_max_documents);
            policy_json += "\"max_docs\":";
            policy_json += buf;
            prev = 1;
        }

        if (config->hot_max_age != NULL) {
            if (prev) { policy_json += ","; }
            policy_json += "\"max_age\":\"";
            policy_json += config->hot_max_age;
            policy_json += "\"";
            prev = 1;
        }

            policy_json += "}";
    }

    if (config->hot_index_priority > 0) {
        if (prev) { policy_json += ","; }
        snprintf(buf, sizeof(buf), "%d", config->hot_index_priority);
        policy_json += "\"set_priority\":{\"priority\":";
        policy_json += buf;
        policy_json += "}";
    }

    policy_json += "}}";

    /* warm phase */
    if (config->warm_phase_enabled &&
        config->warm_min_age != NULL) {

        policy_json += ",\"warm\":{\"min_age\":\"";
        policy_json += config->warm_min_age;
        policy_json += "\",\"actions\":{";
        prev = 0;

        if (config->warm_number_replicas > 0) {
            snprintf(buf, sizeof(buf), "%d", config->warm_number_replicas);
            policy_json += "\"allocate\":{\"number_of_replicas\":";
            policy_json += buf;
            policy_json += "}";
            prev = 1;
        }

        if (config->warm_merge_segments > 0) {
            if (prev) { policy_json += ","; }
            snprintf(buf, sizeof(buf), "%d", config->warm_merge_segments);
            policy_json += "\"forcemerge\":{\"max_num_segments\":";
            policy_json += buf;
            policy_json += "}";
            prev = 1;
        }

        if (config->warm_shrink_shards > 0) {
            if (prev) { policy_json += ","; }
            snprintf(buf, sizeof(buf), "%d", config->warm_shrink_shards);
            policy_json += "\"shrink\":{\"number_of_shards\":";
            policy_json += buf;
            policy_json += "}";
            prev = 1;
        }

        if (config->warm_index_priority > 0) {
            if (prev) { policy_json += ","; }
            snprintf(buf, sizeof(buf), "%d", config->warm_index_priority);
            policy_json += "\"set_priority\":{\"priority\":";
            policy_json += buf;
            policy_json += "}";
            prev = 1;
        }

        policy_json += "}}";
    }

    /* cold phase */
    if (config->cold_phase_enabled &&
        config->cold_min_age != NULL) {

        policy_json += ",\"cold\":{\"min_age\":\"";
        policy_json += config->cold_min_age;
        policy_json += "\",\"actions\":{";
        prev = 0;

        if (config->cold_number_replicas > 0) {
            snprintf(buf, sizeof(buf), "%d", config->cold_number_replicas);
            policy_json += "\"allocate\":{\"number_of_replicas\":";
            policy_json += buf;
            policy_json += "}";
            prev = 1;
        }

        if (config->cold_freeze_index) {
            if (prev) { policy_json += ","; }
            policy_json += "\"freeze\": {}";
            prev = 1;
        }

        if (config->cold_index_priority > 0) {
            if (prev) { policy_json += ","; }
            snprintf(buf, sizeof(buf), "%d", config->cold_index_priority);
            policy_json += "\"set_priority\":{\"priority\":";
            policy_json += buf;
            policy_json += "}";
            prev = 1;
        }

        policy_json += "}}";
    }

    /* delete phase */
    if (config->delete_phase_enabled &&
        config->delete_min_age != NULL) {

        policy_json += ",\"delete\":{\"min_age\":\"";
        policy_json += config->delete_min_age;
        policy_json += "\",\"actions\":{\"delete\":{}}}";
    }

    policy_json += "}}}";

    /* HTTP PUT request with the policy */
    snprintf(buf, sizeof(buf), "_ilm/policy/%s",
        config->ilm_policy_name);
    module_elasticsearch_put(buf, (char *)policy_json.c_str(),
        policy_json.size());
}

static void module_elasticsearch_template_create() {

    FILE *fp;
    long filesize;
    size_t readsize;
    char *buf, endpoint[100];

    if (!(config->template_enabled)) {
        return;
    }

    if (config->template_name == NULL) {
        logger(LOG_DEBUG, "Elasticsearch template name not supplied."
            " Not creating template");
        return;
    }

    if ((fp = fopen(config->template_mapping, "r")) == NULL) {
        logger(LOG_CRIT, "Unable to open elasticsearch template"
            " mapping: %s", config->template_mapping);
        exit(1);
    }

    // determine the filesize
    fseek(fp, 0, SEEK_END);
    filesize = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // if filesize is 0 nothing in file so return NULL
    if (filesize == 0) {
        logger(LOG_DEBUG, "Invalid elasticsearch template");
        return;
    }

    /* allocate space to read the file into. include space to null terminate the string */
    buf = (char *)malloc(filesize + 1);
    if (buf == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_elasticsearch_template_create()");
        exit(BD_OUTOFMEMORY);
    }

    /* read data from the file */
    readsize = fread(buf, 1, filesize, fp);
    /* make sure something was actually read, if not return */
    if (readsize == 0) {
        logger(LOG_DEBUG, "Invalid elasticsearch template");
        free(buf);
        return;
    }
    buf[filesize] = '\0';

    /* close the file */
    if (fclose(fp) != 0) {
        logger(LOG_CRIT, "Unable to close elasticsearch template file");
        free(buf);
        exit(1);
    }

    /* perform the put request */
    snprintf(endpoint, sizeof(endpoint), "_template/%s",
        config->template_name);
    module_elasticsearch_put(endpoint, buf, readsize);

    /* free the buffer */
    free(buf);
}

static int module_elasticsearch_put(char *endpoint, char *data,
    size_t len) {

    CURL *c = curl_easy_init();
    char buf[100];
    struct curl_slist *headers = NULL;

    if (c) {

        /* set the URI */
        snprintf(buf, sizeof(buf), "%s:%d/%s", config->host,
            config->port, endpoint);
        curl_easy_setopt(c, CURLOPT_URL, buf);

        curl_easy_setopt(c, CURLOPT_PORT, config->port);
        curl_easy_setopt(c, CURLOPT_WRITEFUNCTION,
            module_elasticsearch_put_write_cb);
        curl_easy_setopt(c, CURLOPT_READFUNCTION,
            module_elasticsearch_put_read_cb);

        headers = curl_slist_append(headers, "Content-Type: application/x-ndjson");
        curl_easy_setopt(c, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(c, CURLOPT_UPLOAD, 1L);
        curl_easy_setopt(c, CURLOPT_PUT, 1L);

        if (config->require_user_auth) {
            curl_easy_setopt(c, CURLOPT_USERNAME, config->username);
            curl_easy_setopt(c, CURLOPT_PASSWORD, config->password);
        }

        if (config->ssl_verifypeer) {
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 1);
        } else {
            curl_easy_setopt(c, CURLOPT_SSL_VERIFYPEER, 0);
        }

        struct ilm_json_put ilm_data;
        ilm_data.data = data;
        ilm_data.len = len;

        curl_easy_setopt(c, CURLOPT_READDATA, &ilm_data);

        curl_easy_perform(c);
        curl_slist_free_all(headers);
        curl_easy_cleanup(c);

        return 0;
    }

    return 1;
}

static size_t module_elasticsearch_put_read_cb(void *buffer, size_t size, size_t nmemb,
    void *userp) {

    struct ilm_json_put *userdata = (struct ilm_json_put *)userp;

    size_t curl_size = nmemb * size;
    size_t to_copy = (userdata->len < curl_size) ? userdata->len : curl_size;
    memcpy(buffer, userdata->data, to_copy);
    userdata->len -= to_copy;
    userdata->data += to_copy;

    return to_copy;
}

static size_t module_elasticsearch_put_write_cb(void *buffer, size_t size, size_t nmemb,
    void *userp) {

    bool error;
    char *errorstr;

    errorstr = strstr((char *)buffer, "error");
    if (errorstr != NULL) {
        logger(LOG_INFO, "%s", (char *)buffer);
    }

    return size * nmemb;
}
