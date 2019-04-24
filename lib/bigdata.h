#include <stdint.h>
#include <libprotoident.h>
#include <libflowmanager.h>

enum bd_record_type {
    BD_TYPE_STRING,
    BD_TYPE_FLOAT,
    BD_TYPE_DOUBLE,
    BD_TYPE_INT,
    BD_TYPE_BOOL,
    BD_TYPE_UINT
};
union bd_record_value {
    char *data_string;
    float data_float;
    double data_double;
    int64_t data_int;
    uint64_t data_uint;
    bool data_bool;
};
typedef struct bd_result {
    const char *key;
    enum bd_record_type type;
    union bd_record_value value;
} bd_result_t;
typedef struct bd_result_set {
    const char *module;
    bd_result_t *results;
    int num_results;
    int allocated_results;
    double timestamp;
} bd_result_set_t;

typedef void* (*cb_start) (void *tls);
typedef int (*cb_packet) (libtrace_t *trace, libtrace_packet_t *packet,
    Flow *flow, void *tls, void *mls);
typedef int (*cb_stop) (void *tls, void *mls);
typedef int (*cb_output) (void *mls, bd_result_set *result);
typedef int (*cb_flowend) ();
typedef int (*cb_flowstart) ();

typedef struct bigdata_callback_set bd_cb_set;
typedef struct bigdata_callback_set {
    cb_start start_cb;
    cb_packet packet_cb;
    cb_stop stop_cb;
    cb_output output_cb;
    cb_flowend flowend_cb;
    cb_flowstart flowstart_cb;
    void *mls;
    libtrace_filter_t *filter;
    bd_cb_set *next;
} bd_cb_set;

typedef struct bigdata_global {
    pthread_mutex_t lock;
    bd_cb_set *callbacks;
    char *filters[];
    char *metrics[];
    char *where[];
} bd_global_t;

typedef struct bigdata_thread_local {
    FlowManager *flow_manager;
} bd_thread_local_t;

typedef struct bigdata_config {
    const char **foreach;
    unsigned n_foreach;

    const char **metrics;
    unsigned n_metrics;

    //bd_conf_out_t **where;
} bd_conf_t;

typedef struct bigdata_config_output {
    char *module;
    char *host;
    uint16_t port;
    char *username;
    char *password;
} bd_conf_out_t;

/* event prototypes */
bd_cb_set *bd_create_cb_set();
int bd_register_cb_set(bd_cb_set *cbset);
int bd_add_filter_to_cb_set(bd_cb_set *cbset, const char *filter);

/* output result set prototypes */
bd_result_set_t *bd_result_set_create(const char *mod);
int bd_result_set_insert(bd_result_set_t *result_set, const char *key,
    bd_record_type dtype, bd_record_value value);
int bd_result_set_insert_string(bd_result_set_t *result_set, const char *key,
    const char *value);
int bd_result_set_insert_float(bd_result_set_t *result_set, const char *key,
    float value);
int bd_result_set_insert_double(bd_result_set_t *result_set, const char *key,
    double value);
int bd_result_set_insert_int(bd_result_set_t *result_set, const char *key,
    int64_t value);
int bd_result_set_insert_uint(bd_result_set_t *result_set, const char *key,
    uint64_t value);
int bd_result_set_insert_bool(bd_result_set_t *result_set, const char *key,
    bool value);
int bd_result_set_set_timestamp(bd_result_set_t *result_set, double ts);
int bd_result_set_output(bd_result_set_t *record);
int bd_result_set_free(bd_result_set_t *result_set);

/* Flow function prototypes */
Flow *flow_per_packet(libtrace_t *trace, libtrace_packet_t *packet, void *global, void *tls);
int flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts);
int flow_process_metrics(libtrace_packet_t *packet, Flow *flow, double dir, double ts);
int flow_expire(libtrace_t *trace, libtrace_packet_t *packet, void *global, void *tls);
