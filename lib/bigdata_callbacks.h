#ifndef BIGDATA_CALLBACKS_H
#define BIGDATA_CALLBACKS_H

#include "bigdata.h"

/* callback set creation functions */

/* Create a callback set.
 *
 * @param	Plugin name
 * @returns	bd_cb_set callback set
 * 		NULL on error
 */
bd_cb_set *bd_create_cb_set(const char *module_name);

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


/* callback registering functions */

/* Register a callback function to the packet event.
 *
 * @params	cbset - Callback set
 * 		callback - The callback function
 * @returns	0 on success
 * 		-1 on error
 */
int bd_register_packet_event(bd_cb_set *cbset, cb_packet callback);

/* Register a callback function to a protocol event.
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

#endif
