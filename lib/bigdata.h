#ifndef BIGDATA_H
#define BIGDATA_H

// base tickrate
#define BIGDATA_TICKRATE 1000 // milliseconds

// compiler defines
#include "config.h"

// external libraries
#include <libtrace_parallel.h>
#include <libprotoident.h>
#include <libflowmanager.h>
#include <yaml.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

typedef struct bigdata_config bd_conf_t;
typedef struct bigdata_global bd_global_t;
typedef struct bigdata_network bd_network_t;
typedef struct bigdata bd_bigdata_t;
typedef struct bigdata_global bd_global_t;
typedef struct bigdata_callback_set bd_cb_set;
typedef struct bigdata_flow_record bd_flow_record_t;
typedef int (*cb_protocol) (libtrace_t *trace, libtrace_thread_t *thread,
    Flow *flow, libtrace_packet_t *packet, void *tls, void *mls);

// internal libraries
#include "bigdata_parser.h"
#include "bigdata_flow.h"
#include "bigdata_resultset.h"
#include "bigdata_callbacks.h"

// Input Plugins
#include "module_dns.h"
#include "module_http.h"
#include "module_port.h"
#include "module_statistics.h"
#include "module_protocol_statistics.h"
#include "module_cdn_statistics.h"

// Output Plugins
#ifdef HAVE_LIBCURL
    #include "module_influxdb.h"
#endif
#ifdef HAVE_LIBRDKAFKA
    #include "module_kafka.h"
#endif

#define BD_OUTOFMEMORY 1
#define OUTPUT_INIT 2
#define INPUT_INIT 3

typedef struct bigdata {
    libtrace_t *trace;
    libtrace_thread_t *thread;
    libtrace_packet_t *packet;
    Flow *flow;
    bd_global_t *global;
    void *tls;
} bd_bigdata_t;

// configuration structure for application core
typedef struct bigdata_config {
    char *hostname;
    char *interface;
    int processing_threads;
    bool enable_bidirectional_hasher;
    bool local_networks_as_direction;
    bool debug;
    bd_network_t **local_subnets;
    int local_subnets_count;
} bd_conf_t;

typedef struct bigdata_network {
    struct sockaddr_storage address;
    struct sockaddr_storage mask;
} bd_network_t;


// events
typedef void* (*cb_start) (void *tls);
typedef int (*cb_packet) (libtrace_t *trace, libtrace_thread_t *thread,
    Flow *flow, libtrace_packet_t *packet, void *tls, void *mls);
typedef int (*cb_stop) (void *tls, void *mls);


typedef void* (*cb_reporter_start) (void *tls);

typedef int (*cb_reporter_output) (bd_bigdata_t *bigdata, void *mls,
    bd_result_set *result);

typedef int (*cb_reporter_combiner) (bd_bigdata_t *bigdata, void *mls,
    uint64_t tick, void *result);

typedef int (*cb_reporter_stop) (void *tls, void *mls);


typedef int (*cb_flowend) (bd_flow_record_t *flow_record);
typedef int (*cb_flowstart) (bd_flow_record_t *flow_record);

typedef int (*cb_tick) (libtrace_t *trace, libtrace_thread_t *thread,
    void *tls, void *mls, uint64_t tick);

typedef int (*cb_config) (yaml_parser_t *parser, yaml_event_t *event, int *level);

typedef int (*cb_clear) (void *mls);

typedef int (*cb_protocol) (libtrace_t *trace, libtrace_thread_t *thread,
    Flow *flow, libtrace_packet_t *packet, void *tls, void *mls);

typedef struct bigdata_callback_set bd_cb_set;
typedef struct bigdata_callback_set {
    // module ID
    int id;
    char *name;
    // processing thread callbacks
    cb_start start_cb;
    cb_packet packet_cb;
    cb_stop stop_cb;
    // reporter thread callbacks
    cb_reporter_start reporter_start_cb;
    cb_reporter_output reporter_output_cb;
    cb_reporter_combiner reporter_combiner_cb;
    cb_reporter_stop reporter_stop_cb;
    // flow callbacks
    cb_flowstart flowstart_cb;
    cb_flowend flowend_cb;
    // tick timer callbacks
    cb_tick tick_cb;
    size_t tickrate;               // base tickrate
    // filter for the module
    libtrace_filter_t *filter;
    // config callback
    cb_config config_cb;
    // clear callback to clear any counters the module has
    cb_clear clear_cb;
    // protocol callbacks
    cb_protocol protocol_cb[LPI_PROTO_LAST];
    bd_cb_set *next;
} bd_cb_set;

typedef struct bigdata_global {
    pthread_mutex_t lock;
    bd_cb_set *callbacks;
    int callback_count;
    bd_conf_t *config;
} bd_global_t;

// thread local storage for processing threads
typedef struct bigdata_thread_processing_local {
    FlowManager *flow_manager;
    void **mls;                 // array of pointer for module storage

    uint64_t *c_tickrate;       // Each thread must have its own countdown tickrate
                                // for every module.
} bd_thread_local_t;

// thread local storage for reporter thread
typedef struct bigdata_thread_reporter_local {
    void **mls;                 // array of pointers for module storage
} bd_rthread_local_t;

/* event prototypes */
int bd_register_cb_set(bd_cb_set *cbset);

int bd_get_packet_direction(libtrace_packet_t *packet);
int bd_local_ip(struct sockaddr *ip);

/* API functions */
void consume_event(yaml_parser_t *parser, yaml_event_t *event, int *level);


#endif
