#include "module_influxdb.h"
#include "module_influxdb_core.h"
#include "bigdata.h"

#define INFLUX_BUF_LEN 2000
#define INFLUX_LINE_LEN 4000

void *module_influxdb_starting(void *tls);
int module_influxdb_post(void *tls, void *mls, bd_result_set *result);
void *module_influxdb_stopping(void *tls, void *mls);

void *module_influxdb_starting(void *tls) {
    influx_client_t *client = (influx_client_t *)malloc(sizeof(influx_client_t));

    // setup influx connection structure
    client->host = strdup("192.168.20.47");
    client->port = 8086;
    client->db = strdup("libtrace");
    client->usr = strdup("admin");
    client->pwd = strdup("admin");

    return client;
}

int module_influxdb_post(void *tls, void *mls, bd_result_set *result) {

    influx_client_t *client = (influx_client_t *)mls;

    int i;
    int ret;

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
            //strcat(str, "\"");
        }
    }

    // a space is required between tags and values
    strcat(str, " ");

    // add data as field sets. This is data that does change
    for (i=0; i<result->num_results; i++) {
        if (result->results[i].type == BD_TYPE_STRING) {
            strcat(str, result->results[i].key);
            strcat(str, "=\"");
            strcat(str, result->results[i].value.data_string);
            strcat(str, "\"");
        } else if (result->results[i].type == BD_TYPE_FLOAT) {
            snprintf(buf, INFLUX_BUF_LEN, "%f", result->results[i].value.data_float);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
        } else if (result->results[i].type == BD_TYPE_DOUBLE) {
            snprintf(buf, INFLUX_BUF_LEN, "%lf", result->results[i].value.data_double);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
        } else if (result->results[i].type == BD_TYPE_INT) {
            snprintf(buf, INFLUX_BUF_LEN, "%" PRId64, result->results[i].value.data_int);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            // influx expects "i" at the end of a int64
            strcat(str, "i");
        // influxdb needs to be compiled with uint64 support. NOTE i at end
        } else if (result->results[i].type == BD_TYPE_UINT) {
            snprintf(buf, INFLUX_BUF_LEN, "%" PRIu64, result->results[i].value.data_uint);
            strcat(str, result->results[i].key);
            strcat(str, "=");
            strcat(str, buf);
            // influx expects "u" at the end of a uint64, however most version dont
            // support it yet unless compiled with a specific flag
            strcat(str, "i");
        } else if (result->results[i].type == BD_TYPE_BOOL) {
            strcat(str, result->results[i].key);
            strcat(str, "=");
            if (result->results[i].value.data_bool) {
                strcat(str, "t");
            } else {
                strcat(str, "f");
            }
        }

        if (i != result->num_results -1 && result->results[i].type != BD_TYPE_TAG) {
            strcat(str, ",");
        }
    }

    // add the timestamp if it was set
    if (result->timestamp != 0) {
        strcat(str, " ");
        snprintf(buf, INFLUX_BUF_LEN, "%lf", result->timestamp);
        strcat(str, buf);
    }

    ret = post_http_send_line(client, str, strlen(str));

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

int module_influxdb_init() {

    bd_cb_set *callbacks = bd_create_cb_set();

    // Because this is a output only module we register callbacks against
    // the reporter thread.
    callbacks->reporter_start_cb =(cb_reporter_start)module_influxdb_starting;
    callbacks->reporter_output_cb = (cb_reporter_output)module_influxdb_post;
    callbacks->reporter_stop_cb = (cb_reporter_stop)module_influxdb_stopping;

    bd_register_cb_set(callbacks);
}
