#include "module_kafka.h"

#include <librdkafka/rdkafka.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <errno.h>

#include <iostream>
#include <string>

struct module_kafka_conf {
    bd_cb_set *callbacks;
    bool enabled;
    const char *brokers;
    const char *topic;
};
static struct module_kafka_conf *config;

typedef struct module_kafka_options {
    rd_kafka_t *rk;          // producer instance handle
    rd_kafka_conf_t *conf;   // temp configuration object
    rd_kafka_topic_conf_t *topic_conf;
    rd_kafka_topic_t *rkt;
    char errstr[512];
} mod_kafka_opts_t;

static void module_kafka_delivery_cb(rd_kafka_t *rk, void *payload, size_t len,
    rd_kafka_resp_err_t error_code, void *opaque, void *msg_opaque) {

    if (error_code) {
        logger(LOG_DEBUG, "Kafka message delivery failed: %s",
            rd_kafka_err2str(error_code));
    }
}

void *module_kafka_starting(void *tls) {

    mod_kafka_opts_t *opts = (mod_kafka_opts_t *)malloc(
        sizeof(mod_kafka_opts_t));
    if (opts == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func."
            " module_kafka_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    // create client configuration
    opts->conf = rd_kafka_conf_new();
    // create topic configuration
    opts->topic_conf = rd_kafka_topic_conf_new();

    // set message delivery callback function
    rd_kafka_conf_set_dr_cb(opts->conf, module_kafka_delivery_cb);

    // create producer instance
    opts->rk = rd_kafka_new(RD_KAFKA_PRODUCER, opts->conf, opts->errstr,
        sizeof(opts->errstr));
    if (!opts->rk) {
        logger(LOG_CRIT, "Kafka error: Failed to create new producer: %s\n",
            opts->errstr);
        exit(BD_OUTPUT_INIT);
    }

    if (rd_kafka_brokers_add(opts->rk, config->brokers) == 0) {
        logger(LOG_CRIT, "Kafka error: No valid brokers specified\n");
        exit(BD_OUTPUT_INIT);
    }

    opts->rkt = rd_kafka_topic_new(opts->rk, config->topic, opts->topic_conf);

    return opts;
}

int module_kafka_post(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    std::string json;

    // get kafka options
    mod_kafka_opts_t *opts = (mod_kafka_opts_t *)mls;

    // get the json representation of the result
    json = bd_result_set_to_json_string(result);

    // post to kafka
    if(rd_kafka_produce(opts->rkt,
                        RD_KAFKA_PARTITION_UA,
                        RD_KAFKA_MSG_F_COPY,
                        (void *)json.c_str(),
                        json.size(),
                        NULL,
                        0,
                        NULL) == -1) {

        logger(LOG_INFO, "Kafka error: Failed to produce to topic %s\n",
            config->topic);

    }

    // serve the delivery report queue. posibly add this to tick event?
    rd_kafka_poll(opts->rk, 1000);

    return 0;
}

void module_kafka_stopping(void *tls, void *mls) {

    mod_kafka_opts_t *opts = (mod_kafka_opts_t *)mls;

    // check output queue is empty
    if (rd_kafka_outq_len(opts->rk) > 0) {
        logger(LOG_DEBUG, "%d Kafka message(s) were not delivered\n",
            rd_kafka_outq_len(opts->rk));
        rd_kafka_poll(opts->rk, 100);
    }

    // destroy the producer instance
    rd_kafka_destroy(opts->rk);

    // destroy the topic
    rd_kafka_topic_destroy(opts->rkt);

    // Give time for the background threads to cleanup and terminate cleanly
    rd_kafka_wait_destroyed(2000);

    // free the options structure
    free(opts);
}

int module_kafka_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

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
                if (strcmp((char *)event->data.scalar.value, "brokers") == 0) {
                    consume_event(parser, event, level);
                    config->brokers = strdup((char *)event->data.scalar.value);
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "topic") == 0) {
                    consume_event(parser, event, level);
                    config->topic = strdup((char *)event->data.scalar.value);
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
        // Because this is a output module we register
        // against the reporting thread.
        config->callbacks->reporter_start_cb =
            (cb_reporter_start)module_kafka_starting;
        config->callbacks->reporter_output_cb =
            (cb_reporter_output)module_kafka_post;
        config->callbacks->reporter_stop_cb =
            (cb_reporter_stop)module_kafka_stopping;

        logger(LOG_INFO, "Kafka Plugin Enabled\n");
    }

    return 0;
}

int module_kafka_init(bd_bigdata_t *bigdata) {

    config = (struct module_kafka_conf *)malloc(sizeof(
        struct module_kafka_conf));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_kafka_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    config->enabled = 0;
    config->brokers = NULL;
    config->topic = NULL;
    // create callback set
    config->callbacks = bd_create_cb_set("kafka");

    // define config callback function
    config->callbacks->config_cb = (cb_config)module_kafka_config;

    // register the callback set
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}
