#include "module_maxmind.h"

#include <errno.h>
#include <maxminddb.h>
#include <stdlib.h>
#include <string.h>

typedef struct module_maxmind_config {
    bd_cb_set *callbacks;
    bool enabled;
    char *database;
} mod_max_conf;
static mod_max_conf *config;

typedef struct module_maxmind_storage {
    MMDB_s mmdb;
} mod_max_stor;

void *module_maxmind_starting_cb(void *tls) {

    int mmdb_status;
    mod_max_stor *storage;

    storage = (mod_max_stor *)malloc(sizeof(mod_max_stor));
    if (storage == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_maxmind_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    mmdb_status = MMDB_open(config->database, MMDB_MODE_MMAP, &(storage->mmdb));
    if (mmdb_status != MMDB_SUCCESS) {
        fprintf(stderr, "Unable to open maxmind database %s - %s\n",
            config->database, MMDB_strerror(mmdb_status));

        if (MMDB_IO_ERROR == mmdb_status) {
            fprintf(stderr, "\tIO error: %s\n", strerror(errno));
        }

        exit(BD_FILTER_INIT);
    }

    return storage;
}

int module_maxmind_result_cb(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    mod_max_stor *storage = (mod_max_stor *)mls;
    char *ip = NULL;
    int gai_error;
    int mmdb_error;
    MMDB_lookup_result_s mmdb_result;
    MMDB_entry_data_s entry_data;
    int status;
    char buf[100];

    /* try to find a IP address in this result */
    for (int i = 0; i < result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_IP_STRING) {
            // get the IP
            ip = result->results[i].value.data_string;

            if (ip != NULL) {

                mmdb_result = MMDB_lookup_string(&(storage->mmdb), ip, &gai_error, &mmdb_error);
                if (mmdb_result.found_entry) {

                    // get the longitude
                    status = MMDB_get_value(&(mmdb_result.entry), &entry_data, "location",
                        "longitude", NULL);
                    if (status == MMDB_SUCCESS) {
                        if (entry_data.has_data) {
                            // insert longitude into the result set
                            snprintf(buf, sizeof(buf), "%s_longitude", result->results[i].key);
                            bd_result_set_insert_double(result, buf, entry_data.double_value);
                            fprintf(stderr, "Longitude %lf\n", entry_data.double_value);
                        }
                    }

                    // get the latitude
                    status = MMDB_get_value(&(mmdb_result.entry), &entry_data, "location",
                        "latitude", NULL);
                    if (status == MMDB_SUCCESS) {
                        if (entry_data.has_data) {
                            snprintf(buf, sizeof(buf), "%s_latitude", result->results[i].key);
                            bd_result_set_insert_double(result, buf, entry_data.double_value);
                            fprintf(stderr, "Latitude %lf\n", entry_data.double_value);
                        }
                    }
                }
            }
        }
    }
}

int module_maxmind_stopping_cb(void *tls, void *mls) {

    mod_max_stor *storage = (mod_max_stor *)mls;

    MMDB_close(&(storage->mmdb));
    free(storage);

    return 0;
}

int module_maxmind_config_cb(yaml_parser_t *parser, yaml_event_t *event, int *level) {

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
                if (strcmp((char *)event->data.scalar.value, "database") == 0) {
                    consume_event(parser, event, level);
                    config->database = strdup((char *)event->data.scalar.value);
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

        // register starting, result and stopping callbacks
        bd_register_reporter_start_event(config->callbacks, module_maxmind_starting_cb);
        bd_register_reporter_filter_event(config->callbacks, module_maxmind_result_cb);
        bd_register_reporter_stop_event(config->callbacks, module_maxmind_stopping_cb);

        fprintf(stdout, "Enabling Maxmind Plugin\n");

    }

    return 0;
}

int module_maxmind_init(bd_bigdata_t *bigdata) {

    config = (mod_max_conf *)malloc(sizeof(mod_max_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_maxmind_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    config->enabled = 0;
    config->database = NULL;

    // create callback set
    config->callbacks = bd_create_cb_set("maxmind");
    // define configuration callback
    bd_register_config_event(config->callbacks, module_maxmind_config_cb);
    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}
