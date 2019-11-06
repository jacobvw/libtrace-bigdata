#include "module_cdn_statistics.h"
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

typedef struct module_cdn_statictics_address {
    char *name;
    char **address;
    int address_count;
} mod_cdn_stats_addr_conf_t;

typedef struct module_cdn_statistics_config {
    bool enabled;
    bd_cb_set *callbacks;
    int output_interval;

    mod_cdn_stats_addr_conf_t **cdn;
    int cdn_count;
} mod_cdn_stats_conf_t;

typedef struct module_cdb_statistics_cdn {
    char *name;
    char *address;
    struct addrinfo *socket;
} mod_cdn_stats_cdn_t;

// main processing thread cdns with storage
typedef struct module_cdn_statistics_storage {
    mod_cdn_stats_cdn_t **cdn;
    int cdn_count;
} mod_cdn_stats_stor_t;

static mod_cdn_stats_conf_t *config;

struct addrinfo *module_cdn_statistics_lookup_hostname(char *addr) {
    struct addrinfo hints, *res;
    int ret;

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // lookup IPs for each provided DNS name. If lookup fails set to NULL
    if ((ret = getaddrinfo(addr, NULL, &hints, &res)) != 0) {
        return NULL;
    }

    return res;
}

void *module_cdn_statistics_starting(void *tls) {

    mod_cdn_stats_stor_t *storage = (mod_cdn_stats_stor_t *)malloc(
        sizeof(mod_cdn_stats_stor_t));
    if (storage == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_cdn_statsistics_starting()\n");
        exit(BD_OUTOFMEMORY);
    }
    storage->cdn_count = 0;

    // for each cdn
    for (int i = 0; i < config->cdn_count; i++) {
        // for each cdn address
        for (int k = 0; k < config->cdn[i]->address_count; k++) {

             // create structure for this cdn address
             mod_cdn_stats_cdn_t *cdn = (mod_cdn_stats_cdn_t *)malloc(
                 sizeof(mod_cdn_stats_cdn_t));
             if (cdn == NULL) {
                 fprintf(stderr, "Unable to allocate memory. func. "
                     "module_cdn_statistics_starting()\n");
                 exit(BD_OUTOFMEMORY);
             }
             cdn->name = config->cdn[i]->name;
             cdn->address = config->cdn[i]->address[k];
             cdn->socket = module_cdn_statistics_lookup_hostname(cdn->address);
             if (cdn->socket == NULL) {
                 fprintf(stdout, "module cdn statistics: %s %s address resolution failed\n",
                     cdn->name, cdn->address);
             }

             if (storage->cdn_count == 0) {
                 storage->cdn = (mod_cdn_stats_cdn_t **)malloc(sizeof(
                     mod_cdn_stats_cdn_t *));
             } else {
                 storage->cdn = (mod_cdn_stats_cdn_t **)realloc(storage->cdn,
                     (storage->cdn_count + 1) * sizeof(mod_cdn_stats_cdn_t *));
             }

             storage->cdn[storage->cdn_count] = cdn;
             storage->cdn_count += 1;
        }
    }

    return storage;
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

                        if (config->cdn_count == 0) {
                            config->cdn = (mod_cdn_stats_addr_conf_t **)malloc(
                                sizeof(mod_cdn_stats_addr_conf_t *));
                        } else {
                            config->cdn = (mod_cdn_stats_addr_conf_t **)realloc(config->cdn,
                                 (config->cdn_count + 1) * sizeof(mod_cdn_stats_addr_conf_t *));
                        }

                        // create structure for the current cdn
                        mod_cdn_stats_addr_conf_t *cdn = (mod_cdn_stats_addr_conf_t *)
                            malloc(sizeof(mod_cdn_stats_addr_conf_t));
                        cdn->address_count = 0;

                        // next item should be a cdn name
                        cdn->name = strdup((char *)event->data.scalar.value);

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

                            if (cdn->address_count == 0) {
                                cdn->address = (char **)malloc(sizeof(char *));
                            } else {
                                cdn->address = (char **)realloc(cdn->address,
                                    (cdn->address_count + 1) * sizeof(char *));
                            }

                            cdn->address[cdn->address_count] = strdup((char *)event->data.scalar.value);
                            cdn->address_count += 1;

                            consume_event(parser, event, level);
                        }

                        if (event->type == YAML_SEQUENCE_END_EVENT) {
                            consume_event(parser, event, level);
                        }

                        config->cdn[config->cdn_count] = cdn;
                        config->cdn_count += 1;
                    }
                    break;
                }
             default:
                consume_event(parser, event, level);
                break;
        }
    }

    /*
    for (int i = 0; i < config->cdn_count; i++) {

         fprintf(stderr, "cdn name %s\n", config->cdn[i]->cdn_name);

        for (int k = 0; k <config->cdn[i]->address_count; k++) {
             fprintf(stderr, "\tvalue %s\n", config->cdn[i]->address[k]);
         }
    }*/
    if (config->enabled) {
        config->callbacks->start_cb = (cb_start)module_cdn_statistics_starting;
    }
}

int module_cdn_statistics_init(bd_bigdata_t *bigdata) {
    // allocate memory for config structure
    config = (mod_cdn_stats_conf_t *)malloc(sizeof(mod_cdn_stats_conf_t));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_cdn_statistics_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    config->enabled = 0;
    config->output_interval = 10000;
    config->cdn_count = 0;

    config->callbacks = bd_create_cb_set("cdn_statistics");
    config->callbacks->config_cb = (cb_config)module_cdn_statistics_config;

    /* register the callback set */
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}
