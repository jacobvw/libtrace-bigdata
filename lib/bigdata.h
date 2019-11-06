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


/* API functions */

/* Get the direction the packet is travelling. If configuration
 * option local_networks_as_direction is enabled this will be used
 * to check the packets direction, if not enabled trace_get_direction()
 * from Libtrace is used.
 *
 * @param	The packet to check the direction for
 * @returns	0 if the packet is outbound
 *		1 if the packet is inbound
 */
int bd_get_packet_direction(libtrace_packet_t *packet);

/* Checks if the supplied IP address is part of one of the local networks
 *
 * @param	sockaddr structure for the IP to check
 * @returns	1 if the IP is a local IP
 *      	0 if the IP is not a local IP
 *         	-1 if the supplied IP is not IP4 or IP6
 */
int bd_local_ip(struct sockaddr *ip);

/* Get the Libtrace trace file.
 *
 * @param	bigdata structure
 * @returns	Libtrace trace file
 */
libtrace_t *bd_get_trace(bd_bigdata_t *bigdata);

/* Get the Libtrace thread.
 *
 * @param	bigdata structure
 * @returns	Libtrace thread
 */
libtrace_thread_t *bd_get_thread(bd_bigdata_t *bigdata);

/* Get the Libflowmanager flow.
 *
 * @param	bigdata strucure
 * @returns	Libflowmanager flow
 */
Flow *bd_get_flow(bd_bigdata_t *bigdata);

/* Get the Libtrace packet.
 *
 * @params	bigdata structure
 * @returns	Libtrace packet
 */
libtrace_packet_t *bd_get_packet(bd_bigdata_t *bigdata);

#endif
