#include "module_influxdb.h"
#include "module_influxdb_core.h"
#include "bigdata.h"

#define INFLUX_BUF_LEN 2000
#define INFLUX_LINE_LEN 4000

struct module_influxdb_conf {
    char *host;
    int port;
    char *db;
    char *usr;
    char *pwd;
};
struct module_influxdb_conf *config;

void *module_influxdb_starting(void *tls);
int module_influxdb_post(void *tls, void *mls, bd_result_set *result);
void *module_influxdb_stopping(void *tls, void *mls);

void *module_influxdb_starting(void *tls) {
    influx_client_t *client = (influx_client_t *)malloc(sizeof(influx_client_t));

    // setup influx connection structure
    client->host = config->host;
    client->port = config->port;
    client->db = config->db;
    client->usr = config->usr;
    client->pwd = config->pwd;

    fprintf(stderr, "%d %s %s\n", config->port, config->host, config->db);

    return client;
}

int module_influxdb_post(void *tls, void *mls, bd_result_set *result) {

    influx_client_t *client = (influx_client_t *)mls;

    int i;
    int ret;
    bool first_pass = true;

    char *str = (char *)malloc(INFLUX_LINE_LEN);
    if (str == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. module_influxdb_post()\n");
        return 1;
    }
    str[0] = '\0';
    char buf[INFLUX_BUF_LEN] = "";

    // construct insert line
    // insert measurement/module name
    strcat(str, result->module);
    strcat(str, ",");

    // add tag sets. This is meta data that doesnt change
    strcat(str, "capture_application=libtrace-bigdata");
    for (i=0; i<result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_TAG) {
            strcat(str, ",");
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, result->results[i].value.data_string);
        }
    }

    // a space is required between tags and values
    strcat(str, " ");

    // add data as field sets. This is data that does change
    for (i=0; i<result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_STRING) {
            if (!first_pass) strcat(str, ",");
            strcat(str, result->results[i].key);
            strcat(str, "=\"");
            strcat(str, result->results[i].value.data_string);
            strcat(str, "\"");
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_FLOAT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, INFLUX_BUF_LEN, "%f", result->results[i].value.data_float);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_DOUBLE) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, INFLUX_BUF_LEN, "%lf", result->results[i].value.data_double);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            first_pass = false;
        } else if (result->results[i].type == BD_TYPE_INT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, INFLUX_BUF_LEN, "%" PRId64, result->results[i].value.data_int);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            // influx expects "i" at the end of a int64
            strcat(str, "i");
            first_pass = false;
        // influxdb needs to be compiled with uint64 support. NOTE i at end
        } else if (result->results[i].type == BD_TYPE_UINT) {
            if (!first_pass) strcat(str, ",");
            snprintf(buf, INFLUX_BUF_LEN, "%" PRIu64, result->results[i].value.data_uint);
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
        snprintf(buf, INFLUX_BUF_LEN, "%lf", result->timestamp);
        strcat(str, buf);
    }

    ret = post_http_send_line(client, str, strlen(str));
    fprintf(stderr, "return code: %d\n", ret);
    return ret;
}

void *module_influxdb_stopping(void *tls, void *mls) {
    influx_client_t *client = (influx_client_t *)mls;

    if (client != NULL) {
        if (client->host != NULL) { free(client->host); }
        if (client->db != NULL) { free(client->db); }
        if (client->pwd != NULL) { free(client->pwd); }
        free(client);
    }
}

int module_influxdb_config(yaml_parser_t *parser, yaml_event_t *event) {
    config = (struct module_influxdb_conf *)malloc(sizeof(
        struct module_influxdb_conf));

    while (event->type != YAML_SCALAR_EVENT) {
        consume_event(parser, event);
    }

    if (strcmp((char *)event->data.scalar.value, "host") == 0) {
        consume_event(parser, event);
        config->host = strdup((char *)event->data.scalar.value);
        consume_event(parser, event);
    }

    if (strcmp((char *)event->data.scalar.value, "port") == 0) {
        char *end;
        consume_event(parser, event);
        config->port = strtol((char *)event->data.scalar.value, &end, 10);
        consume_event(parser, event);
    }

    if (strcmp((char *)event->data.scalar.value, "database") == 0) {
        consume_event(parser, event);
        config->db = strdup((char *)event->data.scalar.value);
        consume_event(parser, event);
    }

    if (strcmp((char *)event->data.scalar.value, "username") == 0) {
        consume_event(parser, event);
        config->usr = strdup((char *)event->data.scalar.value);;
        consume_event(parser, event);
    }

    if (strcmp((char *)event->data.scalar.value, "password") == 0) {
        consume_event(parser, event);
        config->pwd = strdup((char *)event->data.scalar.value);
        consume_event(parser, event);
    }
}

int module_influxdb_init() {

    bd_cb_set *callbacks = bd_create_cb_set("influxdb");

    // Because this is a output only module we register callbacks against
    // the reporter thread.
    callbacks->config_cb = (cb_config)module_influxdb_config;
    callbacks->reporter_start_cb =(cb_reporter_start)module_influxdb_starting;
    callbacks->reporter_output_cb = (cb_reporter_output)module_influxdb_post;
    callbacks->reporter_stop_cb = (cb_reporter_stop)module_influxdb_stopping;

    bd_register_cb_set(callbacks);
}
