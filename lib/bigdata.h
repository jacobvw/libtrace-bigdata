#include <stdint.h>
#include <libprotoident.h>
#include <libflowmanager.h>

typedef enum {
    ALL,
    FILTER,
    PROTOCOL,
    FLOW_END,
    FLOW_START,
    OUTPUT,
    STARTING,
    STOPPING,
    NUM_EVENTS, /* used to count number of enum and must be at the end */
} bigdata_event;

typedef int (*callback) (...);

typedef struct event_handlers ltbigdata_event_handlers;
typedef struct event_handlers {
    callback cb;
    libtrace_filter_t *filter;
    ltbigdata_event_handlers *next;
} ltbigdata_event_handlers;

typedef struct bigdata_global {
    pthread_mutex_t lock;
    ltbigdata_event_handlers **listeners;
    char *filters[];
    char *metrics[];
    char *where[];
} bigdata_global_t;

typedef struct bigdata_record {
    char *measurement;
    double start_ts;
    double end_ts;
    char *proto;
    char *src_ip;
    char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t in_packets;
    uint64_t out_packets;
    uint64_t in_bytes;
    uint64_t out_bytes;
    uint8_t init_dir;
    lpi_data_t lpi;
} bd_record_t;

typedef struct bigdata_local {
    FlowManager *flow_manager;
} bigdata_local_t;

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
int bd_register_event(bigdata_event event, callback cb, const char *filter);
int bd_add_event_to_handler(bigdata_event event, ltbigdata_event_handlers *t);

/* Takes a bd_record_t structure and calls all registered output event handlers */
int bd_output_record(bd_record_t *record);

/* Flow function prototypes */
void flow_per_packet(libtrace_t *trace, libtrace_packet_t *packet, void *global, void *local);
void flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts);
void flow_process_metrics(libtrace_packet_t *packet, Flow *flow, double dir, double ts);
void flow_expire(libtrace_t *trace, libtrace_packet_t *packet, void *global, void *local);
