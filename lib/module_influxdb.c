#include "influxdb.h"

/* prototypes */
int module_influxdb_post(bd_record_t *result);

influx_client_t client;

int module_influxdb_post(bd_record_t *result) {

    if ((post_http(&client,
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
}

int module_influxdb_init() {
    // setup influx connection structure
    client.host = strdup("127.0.0.1");
    client.port = 8086;
    client.db = strdup("libtrace");
    client.usr = strdup("admin");
    client.pwd = strdup("admin");

    // register callback event
    bd_register_event(OUTPUT, (callback)module_influxdb_post, NULL);
}
