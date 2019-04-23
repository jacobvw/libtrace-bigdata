#include "influxdb.h"

void *module_influxdb_starting(void *tls) {
    influx_client_t *client = (influx_client_t *)malloc(sizeof(influx_client_t));

    // setup influx connection structure
    client->host = strdup("127.0.0.1");
    client->port = 8086;
    client->db = strdup("libtrace");
    client->usr = strdup("admin");
    client->pwd = strdup("admin");

    fprintf(stderr, "influx start\n");

    return client;
}

int module_influxdb_post(void *mls, bd_result_set *result) {

    influx_client_t *client = (influx_client_t *)mls;

    fprintf(stderr, "outpuuting to influx\n");

    post_http(client,
        INFLUX_MEAS(result->module),
        INFLUX_F_STR(result->results[0].key, result->results[0].value),
        INFLUX_END);

/*    if ((post_http(client,
        INFLUX_MEAS("flow"),
        INFLUX_F_STR("src_ip", result->src_ip),
        INFLUX_F_STR("dst_ip", result->dst_ip),
        INFLUX_F_INT("src_port", result->src_port),
        INFLUX_F_INT("dst_port", result->dst_port),
        INFLUX_F_STR("protocol", result->proto),
        INFLUX_F_INT("in_packets", result->in_packets),
        INFLUX_F_INT("out_packets", result->out_packets),
        INFLUX_F_INT("in_bytes", result->in_bytes),
        INFLUX_F_INT("out_bytes", result->out_bytes),
        INFLUX_F_INT("start_ts", result->start_ts*1000),
        INFLUX_F_INT("end_ts", result->end_ts*1000),
        INFLUX_END)) != 0) {


        fprintf(stderr, "Failed posting record to influxdb\n");
        return -1;
    }
*/

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

    callbacks->start_cb = (cb_start)module_influxdb_starting;
    callbacks->output_cb = (cb_output)module_influxdb_post;
    callbacks->stop_cb = (cb_stop)module_influxdb_stopping;

    bd_register_cb_set(callbacks);
}
