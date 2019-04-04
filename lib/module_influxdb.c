influx_client_t client;

    post_http(&client,
        INFLUX_MEAS("foo"),
        INFLUX_TAG("k", "v"),
        INFLUX_TAG("x", "y"),
        INFLUX_F_INT("x", 10),
        INFLUX_F_FLT("y", 10.3, 2),
        INFLUX_F_FLT("z", 10.3456, 2),
        INFLUX_F_BOL("b", 10),
        INFLUX_TS(1512722735522840439),
        INFLUX_END);

int module_influxdb_init() {
    // setup influx connection structure
    client.host = strdup("127.0.0.1");
    client.port = 8086;
    client.db = strdup("libtrace");
    client.usr = strdup("admin");
    client.pwd = strdup("admin");
}

int module_influxdb_post(
