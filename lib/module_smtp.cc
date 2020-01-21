#include "module_smtp.h"

#define MAIL 0x4D 0x41 0x49 0x4C
#define EHLO 0x45 0x48 0x4C 0x4F
#define HELO 0x48 0x45 0x4C 0x4F
#define RCPT 0x52 0x43 0x50 0x54
#define DATA 0x44 0x41 0x54 0x41
//#define OK 0x32 0x35 0x30
//#define READY 0x32 0x32 0x30

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

    logger(LOG_INFO, "smtp starting");

    return storage;
}

int module_smtp_packet(bd_bigdata_t *bigdata, void *mls) {

    uint64_t flow_id;
    std::map<uint64_t, mod_smtp_sess>::iterator it;
    mod_smtp_stor *storage;
    mod_smtp_sess session;
    void *layer3;
    char *payload;
    uint8_t proto;
    uint16_t ethertype;
    uint32_t remaining;

    /* ignore packet if it was not assigned to a flow */
    if (bigdata->flow == NULL) {
        return 0;
    }

    layer3 = trace_get_layer3(bigdata->packet, &ethertype, &remaining);
    if (layer3 == NULL) {
        return 0;
    }

    /* get either ip or ipv6 payload */
    if (ethertype == TRACE_ETHERTYPE_IP) {
        payload = (char *)trace_get_payload_from_ip((libtrace_ip_t *)layer3, &proto,
            &remaining);
    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        payload = (char *)trace_get_payload_from_ip6((libtrace_ip6_t *)layer3, &proto,
            &remaining);
    }
    /* no transport payload? */
    if (payload == NULL) {
        return 0;
    }

    payload = (char *)trace_get_payload_from_tcp((libtrace_tcp_t *)payload, &remaining);
    /* no tcp payload */
    if (payload == NULL) {
        return 0;
    }

    storage = (mod_smtp_stor *)mls;
    flow_id = bd_flow_get_id(bigdata->flow);

    /* first lookup any stored smtp state for this flow id */
    it = storage->sessions->find(flow_id);
    /* no stored state is this the first helo message? */
    if (it == storage->sessions->end()) {

        /* message should be a 220 - ready message, if it is
         * insert it into the session map */
        if (payload[0] == 0x32 && payload[1] == 0x32 &&
            payload[2] == 0x30) {

            session.seen_srv_helo = 1;
            session.srv_helo = strndup(payload, remaining);

            storage->sessions->insert({flow_id, session});

            logger(LOG_INFO, "%s", session.srv_helo);
        }

    } else {
        session = it->second;

        /* if message starts with HELO or EHLO this is the
         * clients helo message */
        if ((payload[0] == 0x45 && payload[1] == 0x48 &&
            payload[2] == 0x4C && payload[3] == 0x4F) ||
            (payload[0] == 0x48 && payload[1] == 0x45 &&
            payload[2] == 0x4C && payload[3] == 0x4F)) {

            session.seen_cli_helo = 1;
            session.cli_helo = strndup(payload, remaining);

            logger(LOG_INFO, "%s", session.cli_helo);

        }

        /* 221 - service closing transmission */
        if (payload[0] == 0x32 && payload[1] == 0x32 &&
            payload[2] == 0x31) {

        }

        /* 250 - server supported features? */
        if (payload[0] == 0x32 && payload[1] == 0x35 &&
            payload[2] == 0x30) {

            /* move payload up to return code */
            payload += 4;

            /* 2.1.0 sender ok */
            if (payload[0] == 0x32 && payload[2] == 0x31 &&
                payload[4] == 0x30) {

                logger(LOG_INFO, "SENDER OK");
            }

            /* 2.1.5 rcpt ok */
            if (payload[0] == 0x32 && payload[2] == 0x31 &&
                payload[4] == 0x35) {

                logger(LOG_INFO, "RCPT OK");
            }

            /* 2.6.0 queued for delivery */
            if (payload[0] == 0x32 && payload[2] == 0x36 &&
                payload[4] == 0x30) {

                logger(LOG_INFO, "Queued for delivery");
            }

        }

        /* MAIL FROM */
        if (payload[0] == 0x4D && payload[1] == 0x41 &&
            payload[2] == 0x49 && payload[3] == 0x4C &&
            payload[4] == 0x20 && payload[5] == 0x46 &&
            payload[6] == 0x52 && payload[7] == 0x4F &&
            payload[8] == 0x4D) {

            session.seen_from = 1;
            session.from = strndup(payload, remaining);

            logger(LOG_INFO, "%s", session.from);
        }

        /* RCPT TO */
        if (payload[0] == 0x52 && payload[1] == 0x43 &&
            payload[2] == 0x50 && payload[3] == 0x54 &&
            payload[4] == 0x20 && payload[5] == 0x54 &&
            payload[6] == 0x4F) {

            session.seen_to = 1;
            session.to = strndup(payload, remaining);

            logger(LOG_INFO, "%s", session.to);
        }

        it->second = session;
    }
}

int module_smtp_stopping(void *tls, void *mls) {

    mod_smtp_stor *storage;

    storage = (mod_smtp_stor *)mls;

    delete(storage->sessions);
    free(storage);

    logger(LOG_INFO, "smtp stopping");

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

    bd_register_cb_set(bigdata, config->callbacks);

    logger(LOG_INFO, "here");
}

