#include "module_cdn_statistics.h"

typedef struct module_cdn_statictics_address {
    char *cdn_name;
    char **addresses;
} mod_cdn_stats_addr_conf_t;

typedef struct module_cdn_statistics_config {
    bool enabled;
    bd_cb_set *callbacks;
    int output_interval;

    mod_cdn_stats_addr_conf_t **cdn;
    int cdn_count;
} mod_cdn_stats_conf_t;

typedef struct module_cdb_statistics_cdn {
    char *cdn_address;
    struct sockaddr *address;
} mod_cdn_stats_cdn_t;

// main processing thread cdns with storage
typedef struct module_cdn_statistics_storage {
    mod_cdn_stats_cdn_t **cdns;
    int cdn_count;
} mod_cdn_stats_stor_t;

static mod_cdn_stats_conf_t *config;

int module_cdn_statisitics_lookup_hostname(const char *hostname) {

}

int module_cdn_statistics_starting() {
    mod_cdn_stats_stor_t *storage = (mod_cdn_stats_stor_t *)malloc(
        sizeof(mod_cdn_stats_stor_t));

    //storage->cdns = NULL;
   // storage->cdn_count = 0;

   // getaddrinfo(NULL, "", &hints, &storage->facebook);

    // for each cdn address provided
    //for (int i = 0; i < config->address_count; i++) {

    //}
}

int module_cdn_statistics_packet() {

}

int module_cdn_statistics_stopping() {

}

int module_cdn_statistics_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {
    int enter_level = *level;
    bool first_pass = 1;


    while (enter_level != *level || first_pass) {
        first_pass = 0;
        switch(event->type) {
            case YAML_SCALAR_EVENT:
                if (strcmp((char *)event->data.scalar.value, "byte_count") == 0) {
                    consume_event(parser, event, level);
                    //config->byte_count = 1;
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "cdns") == 0) {
                    // consume cdns event
                    consume_event(parser, event, level);

                    // consume yaml_mapping_start_event
                    consume_event(parser, event, level);

                     // for each cdn name supplied
                     while (event->type != YAML_MAPPING_END_EVENT) {
                        // next item should be a cdn name
                        fprintf(stderr, "cdn %s\n", (char *)event->data.scalar.value);
                        // consume cdn name event and sequence start event
                        consume_event(parser, event, level);

                        // must be a YAML_SEQUENCE_START_EVENT or error
                        if (event->type != YAML_SEQUENCE_START_EVENT) {
                            fprintf(stderr, "Invalid CDN address sequence\n");
                            exit(1);
                        }
                        consume_event(parser, event, level);

                        // loop over each cdn address
                        while (event->type != YAML_SEQUENCE_END_EVENT) {
                            fprintf(stderr, "\tvalue %s\n", (char *)event->data.scalar.value);
                            consume_event(parser, event, level);
                        }

                        if (event->type == YAML_SEQUENCE_END_EVENT) {
                            consume_event(parser, event, level);
                        }
                    }
                    break;
                }
             default:
                consume_event(parser, event, level);
                break;
        }
    }
}

int module_cdn_statistics_init() {
    // allocate memory for config structure
    config = (mod_cdn_stats_conf_t *)malloc(sizeof(mod_cdn_stats_conf_t));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_cdn_statistics_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    //config->enabled = 0;
    //config->output_interval = 10000;

    config->callbacks = bd_create_cb_set("cdn_statistics");
    config->callbacks->config_cb = (cb_config)module_cdn_statistics_config;
    bd_register_cb_set(config->callbacks);

    return 0;

}
