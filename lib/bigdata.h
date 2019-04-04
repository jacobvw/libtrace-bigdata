#include <stdint.h>
#include <libflowmanager.h>

typedef enum {
    ALL,
    FILTER,
    PROTOCOL,
    FLOW_END,
    FLOW_START,
    NUM_EVENTS, /* used to count number of enum and must be at the end */
} bigdata_event;

typedef void (*callback) (libtrace_t *, libtrace_packet_t *, void *tls);

typedef struct event_handlers ltbigdata_event_handlers;
typedef struct event_handlers {
    callback cb;
    libtrace_filter_t *filter;
    ltbigdata_event_handlers *next;
} ltbigdata_event_handlers;

typedef struct bigdata_per_packet_data {
    uint16_t ethertype;
    /* IP only */
    uint8_t ip_protocol;
    char *src_ip;
    char *dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
} bigdata_packet_t;

typedef struct bigdata_global {
    pthread_mutex_t lock;
    ltbigdata_event_handlers **listeners;
} bigdata_global_t;

typedef struct bigdata_local {
    FlowManager *flow_manager;
} bigdata_local_t;


/* event prototypes */
int ltbigdata_register_event(bigdata_event event, callback cb, const char *filter);
