#ifndef BIGDATA_CALLBACKS_H
#define BIGDATA_CALLBACKS_H

#include "bigdata.h"

/* configuration event prototype */
typedef int (*cb_config) (yaml_parser_t *parser, yaml_event_t *event, int *level);

/* packet processing processing event prototypes - packet processing thread */
typedef void* (*cb_start) (void *tls);
typedef int (*cb_packet) (bd_bigdata_t *bigdata, void *mls);
typedef int (*cb_tick) (bd_bigdata_t *bigdata, void *mls, uint64_t tick);
typedef int (*cb_stop) (void *tls, void *mls);
typedef int (*cb_clear) (void *mls);

/*protocol event prototypes - packet processing thread */
typedef int (*cb_protocol) (bd_bigdata_t *bigdata, void *mls);
typedef int (*cb_protocol_updated) (bd_bigdata_t *bigdata, void *mls, lpi_protocol_t old_protocol,
    lpi_protocol_t new_protocol);
typedef int (*cb_category) (bd_bigdata_t *bigdata, void *mls);

/* result event prototypes - Reporter thread */
typedef void* (*cb_reporter_start) (void *tls);
typedef int (*cb_reporter_filter) (bd_bigdata_t *bigdata, void *mls, bd_result_set *result);
typedef int (*cb_reporter_output) (bd_bigdata_t *bigdata, void *mls, bd_result_set *result);
typedef int (*cb_reporter_combiner) (bd_bigdata_t *bigdata, void *mls, uint64_t tick, void *result);
typedef int (*cb_reporter_stop) (void *tls, void *mls);

/* flow event prototypes - packet processing thread */
typedef int (*cb_flowstart) (bd_bigdata_t *bigdata, void *mls, bd_flow_record_t *flow_record);
typedef int (*cb_flowend) (bd_bigdata_t *bigdata, void *mls, bd_flow_record_t *flow_record);

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
    cb_reporter_filter reporter_filter_cb;
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
    cb_protocol_updated protocol_updated_cb;
    cb_category category_cb[LPI_CATEGORY_LAST];
    bd_cb_set *next;
} bd_cb_set;

/* PRIVATE FUNCTION */
/* callback triggering functions */
int bd_callback_trigger_output(bd_bigdata_t *bigdata, bd_result_set_t *result);
int bd_callback_trigger_combiner(bd_bigdata_t *bigdata, bd_result_set_wrap_t *res);
int bd_callback_trigger_protocol(bd_bigdata_t *bigdata, lpi_protocol_t protocol);
int bd_callback_trigger_packet(bd_bigdata_t *bigdata);
int bd_callback_trigger_tick(bd_bigdata_t *bigdata, uint64_t tick);
int bd_callback_trigger_flowstart(bd_bigdata_t *bigdata);
int bd_callback_trigger_flowend(bd_bigdata_t *bigdata);
int bd_callback_trigger_protocol_updated(bd_bigdata_t *bigdata, lpi_protocol_t oldproto,
    lpi_protocol_t newproto);
int bd_callback_trigger_starting(bd_bigdata_t *bigdata);
int bd_callback_trigger_stopping(bd_bigdata_t *bigdata);
int bd_callback_trigger_reporter_starting(bd_bigdata_t *bigdata);
int bd_callback_trigger_reporter_filter(bd_bigdata_t *bigdata, bd_result_set_t *result);
int bd_callback_trigger_reporter_stopping(bd_bigdata_t *bigdata);
int bd_callback_trigger_category(bd_bigdata_t *bigdata, lpi_category_t category);

/* API FUNCTIONS */

/* callback set creation functions */

/* Create a callback set.
 *
 * @param	Plugin name
 * @returns	bd_cb_set callback set
 * 		NULL on error
 */
bd_cb_set *bd_create_cb_set(const char *module_name);

/* Registers a callback set against the application core.
 *
 * @param	bigdata - bigdata structure
 *		cbset - callback set created via bd_create_cb_set()
 * @returns	ID for the plugin
 *		-1 on error
 */
int bd_register_cb_set(bd_bigdata_t *bigdata, bd_cb_set *cbset);

/* Add BPF filter to the packet event within the callback set.
 *
 * @param	cbset - Callback set
 * 		filter - BPF filter
 * @returns	0 on success
 * 		-1 on error
 */
int bd_add_filter_to_cb_set(bd_cb_set *cbset, const char *filter);

/* Add tick interval to the tick event within the callback set.
 *
 * @param	cbset - Callback set
 * 		tickrate - Tick interval in seconds
 * @returns	0 on success
 * 		-1 on error
 */
int bd_add_tickrate_to_cb_set(bd_cb_set *cbset, size_t tickrate);

/* Register a callback function to the config event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_config_event(bd_cb_set *cbset, cb_config callback);

/* Register a callback function to the packet processing thread start event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_start_event(bd_cb_set *cbset, cb_start callback);

/* Register a callback function to the packet event.
 *
 * @params	cbset - Callback set
 * 		callback - The callback function
 * @returns	0 on success
 * 		-1 on error
 */
int bd_register_packet_event(bd_cb_set *cbset, cb_packet callback);

/* Register a callback function to the tick event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_tick_event(bd_cb_set *cbset, cb_tick callback);

/* Register a callback function to the packet processing thread stop event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_stop_event(bd_cb_set *cbset, cb_stop callback);

/* Register a callback function to the clear event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_clear_event(bd_cb_set *cbset, cb_clear callback);

/* Register a callback function to the protocol event.
 * See https://github.com/wanduow/libprotoident/blob/master/lib/libprotoident.h
 * for the supported protocols.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * 		protocol - The Libprotoident protocol
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_protocol_event(bd_cb_set *cbset, cb_protocol callback, lpi_protocol_t protocol);

/* Register a callback function to the protocol updated event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_protocol_updated_event(bd_cb_set *cbset, cb_protocol_updated callback);

/* Register a callback function to the catefory event.
 * See https://github.com/wanduow/libprotoident/blob/master/lib/libprotoident.h
 * for the supported categories.
 *
 * @params	cbset - Callback set
 *		callback - The callback function
 *		category - The Libprotoident category
 * @returns	0 on success
 *		-1 on error
 */
int bd_register_category_event(bd_cb_set *cbset, cb_category callback, lpi_category_t category);

/* Register a callback function to the reporter start event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_reporter_start_event(bd_cb_set *cbset, cb_reporter_start callback);

/* Register a callback function to the reporter output event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_reporter_output_event(bd_cb_set *cbset, cb_reporter_output callback);

/* Register a callback function to the combiner event
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_reporter_combiner_event(bd_cb_set *cbset, cb_reporter_combiner callback);

/* Register a callback function to the reporter stop event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_reporter_stop_event(bd_cb_set *cbset, cb_reporter_stop callback);

/* Register a callback function to the flowstart event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_flowstart_event(bd_cb_set *cbset, cb_flowstart callback);

/* Register a callback function to the flowend event.
 *
 * @params      cbset - Callback set
 *              callback - The callback function
 * @returns     0 on success
 *              -1 on error
 */
int bd_register_flowend_event(bd_cb_set *cbset, cb_flowend callback);

/* Register a callback funtion to the result filter event.
 *
 * @params	cbset - Callback set
 *		callback - The callback function
 * @returns	0 on success
 *		-1 on error
 */
int bd_register_reporter_filter_event(bd_cb_set *cbset, cb_reporter_filter callback);

#endif
