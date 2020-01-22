#include "module_smtp.h"
#include <list>
#include <string>

#define MAIL 0x4D 0x41 0x49 0x4C
#define EHLO 0x45 0x48 0x4C 0x4F
#define HELO 0x48 0x45 0x4C 0x4F
#define RCPT 0x52 0x43 0x50 0x54
#define DATA 0x44 0x41 0x54 0x41
//#define OK 0x32 0x35 0x30
//#define READY 0x32 0x32 0x30

typedef struct module_smtp_config {
    bd_cb_set *callbacks;

    bool enabled;
    int timeout_request;
    int timeout_check;
} mod_smtp_conf;
mod_smtp_conf *config;

typedef struct module_smtp_session {

    /* 0 == not seen, 1 == sent, 2 == confirmed */
    int seen_srv_helo;
    int seen_cli_helo;
    int seen_from;
    int seen_to;
    int seen_data;
    int seen_quit;

    char *srv_helo;
    char *cli_helo;
    char *from;
    std::list<char *> to;
    char *data;

    /* used to expire sessions that have not seen
       any packets for the timeout_request value. */
    double last_timestamp;
} mod_smtp_sess;

typedef struct module_smtp_storage {
    std::map<uint64_t, mod_smtp_sess> *sessions;
} mod_smtp_stor;

void module_smtp_generate_result(bd_bigdata_t *bigdata,
    mod_smtp_sess *session, int code);
void module_smtp_free_session(mod_smtp_sess *session);

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
    if (payload == NULL || remaining == 0) {
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

            /* init session state */
            session.seen_srv_helo = 0;
            session.seen_cli_helo = 0;
            session.seen_from = 0;
            session.seen_to = 0;
            session.seen_data = 0;
            session.seen_quit = 0;

            session.seen_srv_helo = 1;
            session.srv_helo = strndup(payload, remaining);

            session.last_timestamp =
                trace_get_seconds(bigdata->packet);

            storage->sessions->insert({flow_id, session});

            logger(LOG_INFO, "%s", session.srv_helo);
        }

    } else {
        session = it->second;

        /* update last seen timestamp for this smtp session */
        session.last_timestamp = trace_get_seconds(bigdata->packet);



        /* 1xx - informational. */

        /* 101 - the serber os unable to connect. */

        /* 111 - connection refused or inability to open an
                 SMTP strea. */


        /* 2xx - success. */

        /* 200 - system status message or help reply. */

        /* 214 - a response to the help command. */

        /* 220 - the server is ready. */

        /* 221 - the server is closing its transmission channel. */
        if (payload[0] == 0x32 && payload[1] == 0x32 &&
            payload[2] == 0x31) {

            /* the final message in the SMTP transaction?? so generate
               a result for this session. */
            module_smtp_generate_result(bigdata, &session, 221);
            /* cleanup memory used by the smtp session */
            module_smtp_free_session(&(it->second));
            storage->sessions->erase(it);
            return 0;
        }

        /* 250 - requested mail action okay completed. */
        if (payload[0] == 0x32 && payload[1] == 0x35 &&
            payload[2] == 0x30) {

           /* this should be a cli helo/ehlo confirmation
            * with extensions supplied if ehlo */
           if (session.seen_cli_helo == 1) {
               session.seen_cli_helo = 2;
               logger(LOG_INFO, "cli helo ok");
           }

           /* this should be a mail from OK message */
           if (session.seen_from == 1) {
               session.seen_from = 2;
               logger(LOG_INFO, "mail from ok");
           }

           /* this should be a rcpt to OK message */
           if (session.seen_to == 1) {
               session.seen_to = 2;
               logger(LOG_INFO, "rcpt to ok");
           }

           /* this should be after data is sent confirming */
           if (session.seen_data == 2) {
               logger(LOG_INFO, "mail queued?");
           }

        }

        /* 251 - user not local will forward. */

        /* 252 - cannot verify the user, but it will try to deliver
                 the message anyway. */

        /* 3xx - redirection */

        /* 354 - start mail input */
        if (payload[0] == 0x33 && payload[1] == 0x35 &&
            payload[2] == 0x34) {

            session.seen_data = 2;
            logger(LOG_INFO, "start mail input");
        }



        /* 4xx - persistent transient failure
                 In most cases when receiving a 4xx error the
                 sending mail server will attempt to retry delivery
                 after a delay, and may repeatedly do so for up to
                 a day or two depending on configuration before
                 reporting to their user that the mail could not be
                 delivered. */

        /* 420 - timeout connection problem. */

        /* 421 - service is unavailable due to a connection problem. */

        /* 422 - the recipient's mailbox has exceeded its storage limit. */

        /* 431 - not enough space on the disk. */

        /* 432 - recipient's incoming mail queue has been stopped. */

        /* 441 - the recipient's server is not responding. */

        /* 442 - the connection was dropped during the transmission. */

        /* 446 - the maximum hop count was exceeded for the message. */

        /* 447 - message timed out because of issues concerning the
                 incoming server. */

        /* 449 - routing error. */

        /* 450 - user's mailbox in unavailable. */

        /* 451 - aborted - local error in processing. */

        /* 452 - to many emails sent or to many recipients. */

        /* 471 - an error of your mail server. */



        /* 5xx - permanent errors
                 These errors will result in the SMTP connection
                 being dropped, and the sending mail server will
                 advise the user that their mail could not be
                 delivered. */

        /* 500 - syntax error */
        
        /* 501 - syntax error in parameters or arguments. */

        /* 503 - bad sequence of commands, or requires auth. */
        if (payload[0] == 0x35 && payload[1] == 0x30 &&
            payload[2] == 0x33) {

        }

        /* 504 - command parameter is not implemented */
        if (payload[0] == 0x35 && payload[1] == 0x30 &&
            payload[2] == 0x34) {


        }
        /* 510 - bad email address */
        if (payload[0] == 0x35 && payload[1] == 0x31 &&
            payload[2] == 0x30) {


        }
        /* 511 - bad email address */
        if (payload[0] == 0x35 && payload[1] == 0x31 &&
            payload[2] == 0x31) {


        }
        /* 512 - host server for the recipient's domain name
                 cannot be found in DNS. */

        /* 513 - address type is incorrect. */

        /* 523 - size of you mail exceeds the server limits. */

        /* 530 - authentication problem. */

        /* 541 - the recipient address rejected your message. */

        /* 550 - non-existent email address. */
        if (payload[0] == 0x35 && payload[1] == 0x35 &&
            payload[2] == 0x30) {

            module_smtp_generate_result(bigdata, &session, 550);
            /* cleanup memory used by the smtp session */
            module_smtp_free_session(&(it->second));
            storage->sessions->erase(it);

            /* error message for a rcpt to */
            if (session.seen_to == 1) {
                session.seen_to = 2;
                logger(LOG_INFO, "rcpt error");
            }
        }

        /* 551 - user not local or invalid address - relay denied. */

        /* 552 - exceeded storage allocation. */

        /* 553 - mailbox name invalid. */
        if (payload[0] == 0x35 && payload[1] == 0x35 &&
            payload[2] == 0x33) {

        }

        /* 554 - transaction has failed. */







        /* HELO or EHLO */
        if ((payload[0] == 0x45 && payload[1] == 0x48 &&
            payload[2] == 0x4C && payload[3] == 0x4F) ||
            (payload[0] == 0x48 && payload[1] == 0x45 &&
            payload[2] == 0x4C && payload[3] == 0x4F)) {

            /* if the client sends a helo back its seen the
             * one from the server */
            session.seen_srv_helo = 2;

            /* indicate the client has sent the helo */
            session.seen_cli_helo = 1;
            session.cli_helo = strndup(payload, remaining);

            logger(LOG_INFO, "%s", session.cli_helo);

        }

        /* MAIL FROM */
        if (payload[0] == 0x4D && payload[1] == 0x41 &&
            payload[2] == 0x49 && payload[3] == 0x4C &&
            payload[4] == 0x20 && payload[5] == 0x46 &&
            payload[6] == 0x52 && payload[7] == 0x4F &&
            payload[8] == 0x4D) {

            /* if a MAIL FROM has been seen erase old one update
             * new one */
            if (session.seen_from) {
                free(session.from);
            }
            session.from = strndup(payload, remaining);
            session.seen_from = 1;

            logger(LOG_INFO, "%s", session.from);
        }

        /* RCPT TO */
        if (payload[0] == 0x52 && payload[1] == 0x43 &&
            payload[2] == 0x50 && payload[3] == 0x54 &&
            payload[4] == 0x20 && payload[5] == 0x54 &&
            payload[6] == 0x4F) {

            session.seen_to = 1;
            char *w = strndup(payload, remaining);
            session.to.push_back(w);

            logger(LOG_INFO, "%s", w);
        }

        /* DATA */
        if (payload[0] == 0x44 && payload[1] == 0x41 &&
            payload[2] == 0x54 && payload[3] == 0x41) {

            session.seen_data = 1;

            logger(LOG_INFO, "seen data");
        }

        /* QUIT */
        if (payload[0] == 0x51 && payload[1] == 0x55 &&
            payload[2] == 0x49 && payload[3] == 0x54) {

            session.seen_quit = 1;
            logger(LOG_INFO, "quit");
        }

        it->second = session;
    }

    return 0;
}

int module_smtp_stopping(void *tls, void *mls) {

    mod_smtp_stor *storage;

    storage = (mod_smtp_stor *)mls;

    delete(storage->sessions);
    free(storage);

    return 0;
}

void module_smtp_generate_result(bd_bigdata_t *bigdata,
    mod_smtp_sess *session, int code) {

    bd_result_set_t *result;
    std::list<char *>::iterator it;
    char buf[100];
    int i = 0;
    struct timeval tv;

    result = bd_result_set_create(bigdata, "smtp");

    bd_result_set_insert_int(result, "return_code", code);

    if (session->seen_cli_helo) {
        bd_result_set_insert_string(result, "cli_helo",
            session->cli_helo);
    }

    if (session->seen_srv_helo) {
        bd_result_set_insert_string(result, "srv_helo",
            session->srv_helo);
    }

    if (session->seen_from) {
        bd_result_set_insert_string(result, "from", session->from);
    }

    if (session->seen_to) {
        /* insert each recipient */
        for (it = session->to.begin(); it != session->to.end(); ++it) {
            snprintf(buf, sizeof(buf), "to_%d", i);
            bd_result_set_insert_string(result, buf, *it);
            i += 1;
        }
    }

    tv = trace_get_timeval(bigdata->packet);
    bd_result_set_insert_timestamp(result, tv.tv_sec);

    bd_result_set_publish(bigdata, result, tv.tv_sec);
}

void module_smtp_free_session(mod_smtp_sess *session) {

    std::list<char *>::iterator it;

    if (session->srv_helo) {
        free(session->srv_helo);
    }

    if (session->seen_cli_helo) {
        free(session->cli_helo);
    }

    if (session->seen_from) {
        free(session->from);
    }

    /* free each rcpt */
    for (it = session->to.begin(); it != session->to.end(); ++it) {
        free(*it);
    }
}

int module_smtp_tick(bd_bigdata_t *bigdata, void *mls, uint64_t tick) {

    fprintf(stderr, "tick\n");

    mod_smtp_stor *storage = (mod_smtp_stor *)mls;

    std::map<uint64_t, mod_smtp_sess>::iterator it;

    for (it = storage->sessions->begin(); it !=
        storage->sessions->end(); ) {

        if (tick >= (it->second.last_timestamp + config->timeout_request)) {
            module_smtp_free_session(&(it->second));
            storage->sessions->erase(it++);
        } else {
            ++it;
        }
    }

    return 0;
}

int module_smtp_config(yaml_parser_t *parser, yaml_event_t *event,
    int *level) {

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
                if (strcmp((char *)event->data.scalar.value, "timeout_request") == 0) {
                    consume_event(parser, event, level);
                    config->timeout_request = atoi((char *)event->data.scalar.value);
                    if (config->timeout_request == 0) {
                        logger(LOG_WARNING, "Invalid timeout_request value. "
                            "module_dns. setting to default 20 seconds");
                        config->timeout_request = 20;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "timeout_check") == 0) {
                    consume_event(parser, event, level);
                    config->timeout_check = atoi((char *)event->data.scalar.value);
                    if (config->timeout_check == 0) {
                        logger(LOG_WARNING, "Invalid timeout_check value. "
                            "module_dns. setting to default 20 seconds");
                        config->timeout_check = 20;
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
        bd_register_start_event(config->callbacks,
            (cb_start)module_smtp_starting);
        bd_register_packet_event(config->callbacks,
            (cb_packet)module_smtp_packet);
        bd_register_stop_event(config->callbacks,
            (cb_stop)module_smtp_stopping);

        bd_register_tick_event(config->callbacks,
            (cb_tick)module_smtp_tick);
        bd_add_tickrate_to_cb_set(config->callbacks,
            config->timeout_check);

        bd_add_filter_to_cb_set(config->callbacks, "port 25");

        logger(LOG_INFO, "SMTP Plugin Enabled");
    }

    return 0;
}

int module_smtp_init(bd_bigdata_t *bigdata) {

    config = (mod_smtp_conf *)malloc(sizeof(mod_smtp_conf));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_smtp_init()");
        exit(BD_OUTOFMEMORY);
    }

    config->enabled = 0;
    config->timeout_request = 60;
    config->timeout_check = 60;

    /* create callback set */
    config->callbacks = bd_create_cb_set("smtp");

    /* register to the config event */
    bd_register_config_event(config->callbacks,
        (cb_config)module_smtp_config);

    /* register the callback set */
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}

