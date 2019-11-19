#include "module_kafka.h"

#include <librdkafka/rdkafka.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>

#define KAFKA_BUF_LEN 2000
#define KAFKA_LINE_LEN 4000

static char *result_to_query(bd_result_set *result);

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
    char errstr[512];
} mod_kafka_opts_t;

static void module_kafka_delivery_cb(rd_kafka_t *rk,
    const rd_kafka_message_t *rkmessage, void *opaque) {

    // error occured when posting to kafka
    if (rkmessage->err) {
        fprintf(stderr, "Kafka delivery failed: %s\n",
            rd_kafka_err2str(rkmessage->err));
    }
}

void *module_kafka_starting(void *tls) {

    mod_kafka_opts_t *opts = (mod_kafka_opts_t *)malloc(
        sizeof(mod_kafka_opts_t));
    if (opts == NULL) {
        fprintf(stderr, "Unable to allocate memory. func."
            " module_kafka_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    // create client configuration
    opts->conf = rd_kafka_conf_new();

    // set the bootstrap brokers
    if (rd_kafka_conf_set(opts->conf, "bootstrap.servers", config->brokers,
        opts->errstr, sizeof(opts->errstr)) != RD_KAFKA_CONF_OK) {

        fprintf(stderr, "Kafka error: %s\n", opts->errstr);
        exit(BD_OUTPUT_INIT);
    }

    // set delivery report callback
    rd_kafka_conf_set_dr_msg_cb(opts->conf, module_kafka_delivery_cb);

    // create producer instance
    opts->rk = rd_kafka_new(RD_KAFKA_PRODUCER, opts->conf, opts->errstr,
        sizeof(opts->errstr));
    if (!opts->rk) {
        fprintf(stderr, "Kafka error: Failed to create new producer: %s\n",
            opts->errstr);
        exit(BD_OUTPUT_INIT);
    }

    return opts;
}

int module_kafka_post(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    rd_kafka_resp_err_t err;
    int i;
    int ret;
    bool first_pass = true;
    char *query;

    // get kafka options
    mod_kafka_opts_t *opts = (mod_kafka_opts_t *)mls;

    query = result_to_query(result);

retry:
    // post the result to the kafka topic
    /*err = rd_kafka_producev(opts->rk,
                      RD_KAFKA_V_TOPIC(config->topic),
                      RD_KAFKA_V_MSGFLAGS(RD_KAFKA_MSG_F_FREE),
                      RD_KAFKA_V_VALUE(query, strlen(query)),
                      RD_KAFKA_V_OPAQUE(NULL),
                      RD_KAFKA_V_END);*/

    rd_kafka_topic_t *rkt = rd_kafka_topic_new(opts->rk, config->topic, NULL);
    if(rd_kafka_produce(rkt, 0, RD_KAFKA_MSG_F_FREE, query, strlen(query),
        NULL, 0, NULL) == -1) {

        fprintf(stderr, "Kafka failed to produce to topic %s: %s\n",
            config->topic, rd_kafka_err2str(err));

    }

/*    if (err) {
        fprintf(stderr, "Kafka failed to produce to topic %s: %s\n",
            config->topic, rd_kafka_err2str(err));

        if (err == RD_KAFKA_RESP_ERR__QUEUE_FULL) {
            /* If the internal queue is full, wait for
             * messages to be delivered and then retry.
             * The internal queue represents both
             * messages to be sent and messages that have
             * been sent or failed, awaiting their
             * delivery report callback to be called.
             *
             * The internal queue is limited by the
             * configuration property
             * queue.buffering.max.messages
             */
/*            rd_kafka_poll(opts->rk, 1000);
            goto retry;
        }
*/    }

    // serve the delivery report queue. posibly add this to tick event?
    rd_kafka_poll(opts->rk, 0);

    // libkafka is set to free query when it is done with it
    //free(query);

    return 0;
}

void module_kafka_stopping(void *tls, void *mls) {

    mod_kafka_opts_t *opts = (mod_kafka_opts_t *)mls;

    // wait for any remaining messages to be delivered (10 seconds)
    //rd_kafka_flush(opts->rk, 10*1000);

    // check output queue is empty
    if (rd_kafka_outq_len(opts->rk) > 0) {
        fprintf(stderr, "%d Kafka message(s) were not delivered\n",
            rd_kafka_outq_len(opts->rk));
        rd_kafka_poll(opts->rk, 100);
    }

    // destroy the producer instance
    rd_kafka_destroy(opts->rk);

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

        fprintf(stdout, "Kafka Plugin Enabled\n");
    }

    return 0;
}

int module_kafka_init(bd_bigdata_t *bigdata) {

    config = (struct module_kafka_conf *)malloc(sizeof(
        struct module_kafka_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
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
}

/* Currently a copy of the influxdb query string */
static char *result_to_query(bd_result_set *result) {

    bool first_pass = true;
    char *str;
    char buf[KAFKA_BUF_LEN] = "";

    str = (char *)malloc(KAFKA_LINE_LEN);
    if (str == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. module_influxdb_post()\n");
        exit(BD_OUTOFMEMORY);
    }
    str[0] = '\0';

    // insert measurement/module name
    strcat(str, result->module);
    strcat(str, ",");

    // add tag sets. This is meta data that doesnt change
    strcat(str, "capture_application=libtrace-bigdata");
    for (int i = 0; i < result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_TAG) {
            strcat(str, ",");
            /* if the tag key contains a space */
            if (strstr(result->results[i].key, " ")) {
                // escape all spaces
                char *w = bd_replaceWord(result->results[i].key, " ", "\\ ");
                strcat(str, w);
                free(w);
            } else {
                strcat(str, result->results[i].key);
            }

            strcat(str, "=");

            /* if the tag result contains a space */
            if (strstr(result->results[i].value.data_string, " ")) {
                /* escape all spaces */
                char *w = bd_replaceWord(result->results[i].value.data_string,
                    " ", "\\ ");
                strcat(str, w);
                free(w);
            } else {
                strcat(str, result->results[i].value.data_string);
            }
        }
    }

    // a space is required between tags and values
    strcat(str, " ");

    // add data as field sets. This is data that does change
    for (int i = 0; i < result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_STRING) {
            if (!first_pass) strcat(str, ",");
            strcat(str, result->results[i].key);
            strcat(str, "=\"");
            strcat(str, result->results[i].value.data_string);
            strcat(str, "\"");
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_FLOAT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, KAFKA_BUF_LEN, "%f", result->results[i].value.data_float);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_DOUBLE) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, KAFKA_BUF_LEN, "%lf", result->results[i].value.data_double);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_INT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, KAFKA_BUF_LEN, "%li", result->results[i].value.data_int);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            // influx expects "i" at the end of a int64
            strcat(str, "i");
            first_pass = false;
        // influxdb needs to be compiled with uint64 support. NOTE i at end
        } else if (result->results[i].type == BD_TYPE_UINT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, KAFKA_BUF_LEN, "%lu", result->results[i].value.data_uint);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            // influx expects "u" at the end of a uint64, however most versions dont
            // support it yet unless compiled with a specific flag
            strcat(str, "i");
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_BOOL) {
            if (!first_pass) strcat(str, ",");
            strcat(str, result->results[i].key);
            strcat(str, "=");
            if (result->results[i].value.data_bool) {
                strcat(str, "t");
            } else {
                strcat(str, "f");
            }
            first_pass = false;
        }
    }

    // add the timestamp if it was set
    if (result->timestamp != 0) {
        strcat(str, " ");
        // influx expects timestamp in nanoseconds
        snprintf(buf, KAFKA_BUF_LEN, "%lu", (result->timestamp*1000000)*1000);
        strcat(str, buf);
    }

    return str;
}
