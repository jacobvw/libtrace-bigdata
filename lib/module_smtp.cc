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

            /* init session state */
            session.seen_srv_helo = 0;
            session.seen_cli_helo = 0;
            session.seen_from = 0;
            session.seen_to = 0;
            session.seen_data = 0;
            session.seen_quit = 0;

            session.seen_srv_helo = 1;
            session.srv_helo = strndup(payload, remaining);

            storage->sessions->insert({flow_id, session});

            logger(LOG_INFO, "%s", session.srv_helo);
        }

    } else {
        session = it->second;

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

            if (session.seen_quit == 1) {
                session.seen_quit = 2;
                logger(LOG_INFO, "session closing");
            }
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

        /* 510 - bad email address */

        /* 511 - bad email address */

        /* 512 - host server for the recipient's domain name
                 cannot be found in DNS. */

        /* 513 - address type is incorrect. */

        /* 523 - size of you mail exceeds the server limits. */

        /* 530 - authentication problem. */

        /* 541 - the recipient address rejected your message. */

        /* 550 - non-existent email address. */
        if (payload[0] == 0x35 && payload[1] == 0x35 &&
            payload[2] == 0x30) {

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

    bd_register_cb_set(bigdata, config->callbacks);

}

