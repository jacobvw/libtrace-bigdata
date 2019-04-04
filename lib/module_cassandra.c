#include <cassandra.h>
#include <stdio.h>

CassFuture *connect_future;
CassCluster *cluster;
CassSession *session;

int init() {

}

/* Connect to the supplied hosts
 *
 * Return 1 on success, -1 on failure
 */
int connect(char *hosts) {

    cluster = cass_cluster_new();
    session = cass_session_new();

    cass_cluster_set_contact_pointers(cluster, hosts);

    // Connect to the cluster
    connect_future = cass_session_connect(session, cluster);

    // Connection successful
    if (cass_future_error_code(connect_future) == CASS_OK) {
        return 1;
    } else {
        return 0;
    }
}

/* Close the connection */
int close() {

    CassFuture *close_future = cass_session_close(session);
    cass_future_wait(close_future);
    cass_future_free(close_future);

    return 1;
}

int insert(char *query) {

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



