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

// internal libraries
#include "bigdata_common.h"
#include "bigdata_resultset.h"
#include "bigdata_callbacks.h"
#include "bigdata_parser.h"
#include "bigdata_flow.h"

// Input Plugins
#include "module_dns.h"
#include "module_statistics.h"
#include "module_protocol_statistics.h"
#include "module_cdn_statistics.h"
#include "module_flow_statistics.h"

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
#define BD_INVALID_CONFIG 4
#define BD_MALFORMED_CONF 5
#define BD_YAML_ERROR 6
#define BD_STARTUP_ERROR 7
#define BD_INVALID_PARAMS 8

typedef enum {
    BD_EVENT_STARTING,
    BD_EVENT_PACKET,
    BD_EVENT_PROTOCOL,
    BD_EVENT_PROTOCOL_UPDATED,
    BD_EVENT_TICK,
    BD_EVENT_FLOWSTART,
    BD_EVENT_FLOWEND,
    BD_EVENT_STOPPING,
    BD_EVENT_REPORTER_STARTING,
    BD_EVENT_OUTPUT,
    BD_EVENT_COMBINE,
    BD_EVENT_REPORTER_STOPPING,
} bd_event_t;

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

/* Global configuration structure */
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


/* private function */
static bd_bigdata_t *init_bigdata(bd_bigdata_t *bigdata, libtrace_t *trace, libtrace_thread_t *thread,
    libtrace_packet_t *packet, Flow *flow, bd_global_t *global, void *tls);
static void init_modules(bd_bigdata_t *bigdata);
static void libtrace_cleanup(libtrace_t *trace, libtrace_callback_set_t *processing,
    libtrace_callback_set_t *reporter);

#endif
