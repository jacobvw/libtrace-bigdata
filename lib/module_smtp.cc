#include "module_smtp.h"

typedef struct module_smtp_config {
    bd_cb_set *callbacks;
} mod_smtp_conf;
mod_smtp_conf *config;

typedef struct module_smtp_session {

    bool seen_srv_helo;
    bool seen_cli_helo;
    bool seen_from;
    bool seen_to;
    bool seen_data;

    char *srv_helo;
    char *cli_helo;
    char *from;
    char *to;
    char *data;
} mod_smtp_sess;

typedef struct module_smtp_storage {
    std::map<uint64_t, mod_smtp_sess> *sessions;
} mod_smtp_stor;

void *module_smtp_starting(void *tls) {

    mod_smtp_stor *storage;

    storage = (mod_smtp_stor *)malloc(sizeof(mod_smtp_stor));
    if (storage == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func."
            " module_smtp_starting()");
        exit(BD_OUTOFMEMORY);
    }

    storage->sessions = new std::map<uint64_t, mod_smtp_sess>;

    return storage;
}

int module_smtp_packet(bd_bigdata_t *bigdata, void *mls) {

    logger(LOG_INFO, "port 25 packet\n");
}

int module_smtp_stopping(void *tls, void *mls) {

    mod_smtp_stor *storage;

    storage = (mod_smtp_stor *)mls;

    delete(storage->sessions);
    free(storage);

    return 0;
}

int module_smtp_init(bd_bigdata_t *bigdata) {

    config = (mod_smtp_conf *)malloc(sizeof(mod_smtp_conf));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_smtp_init()");
        exit(BD_OUTOFMEMORY);
    }

    config->callbacks = bd_create_cb_set("smtp");

    bd_register_start_event(config->callbacks,
        (cb_start)module_smtp_starting);
    bd_register_packet_event(config->callbacks,
        (cb_packet)module_smtp_packet);
    bd_register_stop_event(config->callbacks,
        (cb_stop)module_smtp_stopping);

    bd_add_filter_to_cb_set(config->callbacks, "port 25");
}

