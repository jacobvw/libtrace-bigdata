#include <cassandra.h>
#include <stdio.h>

struct module_cassandra_conf {
    bd_cb_set *callbacks;
    bool enabled;
    char *hostname;
    int port;
    char *database;
    char *username;
    char *password;
}
static struct module_cassandra_conf *config;

struct module_cassandra_storage {
    CassFuture *connect_future;
    CassCluster *cluster;
    CassSession *session;
}

int module_cassandra_connect(struct module_cassandra_storage *cass_conf) {

    // connect to the cluster
    cass_conf->connect_future = cass_session_connect(cass_conf->session, cass_conf->cluster);

    // Connection successful
    if (cass_future_error_code(cass_conf->connect_future) == CASS_OK) {
        return 0;
    } else {
        fprintf(stderr, "Unable to connect to cassandra cluster\n");
        return 1;
}

void *module_cassandra_starting(void *tls) {
    struct module_cassandra_storage *cass_conf = (struct module_cassandra_storage *)
        malloc(sizeof(struct module_cassandra_storage));
    if (cass_conf == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. module_cassandra_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    cass_conf->cluster = cass_cluster_new();
    cass_conf->session = cass_session_new();
    // set the user and password
    cass_cluster_set_credentials(cluster, config->username, config->password);
    // set the cluster hostname
    cass_cluster_set_contact_points(cluster, config->hostname);
    // connect to the cluster
    module_cassandra_connect(cass_conf);

    return (void *)cass_conf;
}

int module_cassandra_post(void *tls, void *mls, bd_result_set *result) {

}

/* Close the connection */
int module_cassandra_stopping(void *tls, void *mls) {
    struct module_cassandra_storage *cass_conf =
        (struct module_cassandra_storage *)mls;

    CassFuture *close_future = cass_session_close(cass_conf->session);
    cass_future_wait(close_future);
    cass_future_free(close_future);
    cass_cluster_free(cass_conf->cluster);

    return 0;
}

int insert(struct module_cassandra_storage *cass_conf, char *query) {

    // Build the query
    CassStatement *statement = cass_statement_new(query, 0);

    // Execute the query
    CassFuture *result_future = cass_session_execute(session, statement);

    // Query successful
    if (cas_future_error_code(result_future) == CAS_OK) {
        const CassResult *result = cass_future_get_result(result_future);



    } else {

    }
}

int module_cassandra_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

    if (config->enabled) {
        config->callbacks->reporter_start_cb = (cb_reporter_start)module_cassandra_starting;
        config->callbacks->reporter_output_cb = (cb_reporter_output)module_cassandra_post;
        config->callbacks->reporter_stop_cb = (cb_reporter_stop)module_cassandra_stopping;
    }

    return 0;
}


int module_cassandra_init() {
    // create the config structure
    config = (struct module_cassandra_conf *)malloc(sizeof(
        struct module_cassandra_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_cassandra_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    // initialise the config structure
    config->enabled = 0;
    config->hostname = NULL;
    config->port = NULL;
    config->database = NULL;
    config->username = NULL;
    config->password = NULL;

    config->callbacks = bd_create_cb_set("cassandra");
    config->callbacks->config_cb = (cb_config)module_cassandra_config;
    bd_register_cb_set(config->callbacks);

    return 0;
}
