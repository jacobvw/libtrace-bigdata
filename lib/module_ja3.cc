#include "module_ja3.h"
#include <iostream>

typedef struct module_ja3_config {
    bd_cb_set *callbacks;
    bool enabled;
    char *signatures;
} mod_ja3_conf;
static mod_ja3_conf *config;

typedef struct module_ja3_storage {
    std::map<std::string, std::string> *md5_map;
} mod_ja3_stor;

void *module_ja3_starting(void *tls) {

    mod_ja3_stor *storage;
    FILE *fd;
    yaml_parser_t parser;
    yaml_event_t event;
    std::string user_agent;
    std::string md5;
    bool got_user_agent = 0;
    bool got_md5 = 0;

    storage = (mod_ja3_stor *)malloc(sizeof(mod_ja3_stor));
    if (storage == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_ja3_starting()");
        exit(BD_OUTOFMEMORY);
    }

    storage->md5_map = new std::map<std::string, std::string>;

    /* parse the json md5 to user agent mapping */
    if ((fd = fopen(config->signatures, "r")) == NULL) {
        logger(LOG_ERR, "Failed to open JA3 signature file %s",
            config->signatures);
        exit(1);
    }

    /* init the yaml parser */
    if (!yaml_parser_initialize(&parser)) {
        logger(LOG_ERR, "Failed to initialize yaml parser. func. "
            "module_ja3_starting()");
        exit(1);
    }

    /* set yaml input file */
    yaml_parser_set_input_file(&parser, fd);

    do {
        if (!yaml_parser_parse(&parser, &event)) {
            logger(LOG_ERR, "Parser error %d", parser.error);
            exit(1);
        }

        switch (event.type) {
            case YAML_SCALAR_EVENT: {

                if (strcmp((char *)event.data.scalar.value, "User-Agent") == 0) {
                    yaml_event_delete(&event);
                    yaml_parser_parse(&parser, &event);
                    user_agent = (char *)event.data.scalar.value;
                    got_user_agent = 1;
                }

                if (strcmp((char *)event.data.scalar.value, "md5") == 0) {
                    yaml_event_delete(&event);
                    yaml_parser_parse(&parser, &event);
                    md5 = (char *)event.data.scalar.value;
                    got_md5 = 1;
                }

                break;
            }
            default:
                break;
        }

        /* if we have a User-Agent and md5 insert them into the map */
        if (got_user_agent && got_md5) {
            storage->md5_map->insert({md5, user_agent});
            got_user_agent = 0;
            got_md5 = 0;
        }

        if(event.type != YAML_STREAM_END_EVENT)
            yaml_event_delete(&event);

    } while (event.type != YAML_STREAM_END_EVENT);

    yaml_parser_delete(&parser);
    fclose(fd);

    return storage;

}

int module_ja3_result(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    int i;
    char *ja3_md5;
    mod_ja3_stor *storage;
    std::map<std::string, std::string>::iterator it;

    storage = (mod_ja3_stor *)mls;

    for (i = 0; i < result->num_results; i++) {

        if (result->results[i]->type == BD_TYPE_STRING) {

            if (strcmp(result->results[i]->key, "tls_ja3") == 0) {

                ja3_md5 = result->results[i]->value.data_string;
                it = storage->md5_map->find(ja3_md5);

                if (it != storage->md5_map->end()) {
                    bd_result_set_insert_string(result, "tls_ja3_user_agent",
                        it->second.c_str());
                } else {
                    bd_result_set_insert_string(result, "tls_ja3_user_agent",
                        "unknown");
                }
            }
        }

    }


    return 0;
}

int module_ja3_stopping(void *tls, void *mls) {

    mod_ja3_stor *storage;

    storage = (mod_ja3_stor *)mls;

    delete(storage->md5_map);
    free(storage);

    return 0;
}

int module_ja3_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

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
                if (strcmp((char *)event->data.scalar.value, "signatures") == 0) {
                    consume_event(parser, event, level);
                    config->signatures = strdup((char *)event->data.scalar.value);
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
        bd_register_reporter_start_event(config->callbacks, module_ja3_starting);
        bd_register_reporter_filter_event(config->callbacks, module_ja3_result);
        bd_register_reporter_stop_event(config->callbacks, module_ja3_stopping);

        logger(LOG_INFO, "JA3 Plugin Enabled");
    }

    return 0;
}

int module_ja3_init(bd_bigdata_t *bigdata) {

    config = (mod_ja3_conf *)malloc(sizeof(mod_ja3_conf));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_ja3_init()");
        exit(BD_OUTOFMEMORY);
    }

    config->callbacks = bd_create_cb_set("ja3");
    config->enabled = 0;
    config->signatures = NULL;

    bd_register_config_event(config->callbacks, module_ja3_config);

    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}
