static typedef struct module_cdn_statistics_config {
    bool enabled;
    bs_cb_set *callbacks;
    int output_interval;
    char **cdn_addresses;
    int address_count;
} mod_cdn_stats_conf_t;

static typedef struct module_cdb_statistics_cdn {
    char *cdn_address
    struct sockaddr *address
} mod_cdn_stats_cdn_t;

static typedef struct module_cdn_statistics_storage {
    mod_cdn_stats_cdn_t **cdns;
    int cdn_count;
} mod_cdn_stats_stor_t;

static module_cdn_statistics_config config;

int module_cdn_statisitics_lookup_hostname(const char *hostname) {

}

int module cdn_statistics_starting() {
    mod_cdn_stats_stor_t *storage = (mod_cdn_stats_stor_t *)malloc(
        sizeof(mod_cdn_stats_stor_t));

    storage->cdns = NULL;
    storage->cdn_count = 0;

    getaddrinfo(NULL, "", &hints, &storage->facebook);
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
                    config->byte_count = 1;
                    break;
                }
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

    config->enabled = 0;
    config->output_interval = 10000;

    config->callbacks = bd_create_cb_set("cdn_statistics");
    config->callbacks->config_cb = (cb_config)module_cdn_statistics_config;
    bd_register_cb_set(config->callbacks);

    return 0;

}
