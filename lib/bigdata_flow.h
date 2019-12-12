
#ifndef BIGDATA_FLOW_H
#define BIGDATA_FLOW_H

#include "bigdata.h"

/* Flow record structure */
typedef struct bigdata_flow_record {
    double start_ts;
    double ttfb;			/* time to first byte */
    double end_ts;
    struct sockaddr_storage src_ip;
    struct sockaddr_storage dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint64_t in_packets;
    uint64_t out_packets;
    uint64_t in_bytes;
    uint64_t out_bytes;
    uint8_t init_dir;
    lpi_data_t lpi;
    lpi_module_t *lpi_module;
} bd_flow_record_t;

/* private functions */
int flow_expire(bd_bigdata_t *bigdata);
Flow *flow_per_packet(bd_bigdata_t *bigdata);

/* Get the number of incoming packets seen for the current packets flow.
 *
 * @params	flow - Libflowmanager flow
 * @returns	number of incoming packets.
 */
uint64_t bd_flow_get_in_packets(Flow *flow);

/* Get the number of outgoing packets seen for the current packets flow.
 *
 * @params	flow - Libflowmanager flow.
 * @returns	number of outgoing packets.
 */
uint64_t bd_flow_get_out_packets(Flow *flow);

/* Get the number of incoming bytes seen for the current packets flow.
 *
 * @params      flow - Libflowmanager flow.
 * @returns     number of incoming bytes.
 */
uint64_t bd_flow_get_in_bytes(Flow *flow);

/* Get the number of outgoing bytes seen for the current packets flow.
 *
 * @params      flow - Libflowmanager flow.
 * @returns     number of outgoing bytes.
 */
uint64_t bd_flow_get_out_bytes(Flow *flow);

/* Get the initial direction of the current packets flow. E.g. the direction
 * of the first SYN packet.
 *
 * @params	flow - Libflowmanager flow.
 * @returns	0 if the flow is outbound (originated internally).
 * 		1 if the flow is inbound (originated externally).
 *		-1 on error.
 */
int bd_flow_get_direction(Flow *flow);

/* Get the initial source IP address for the current packets flow.
 *
 * @params	flow - Libflowmanager flow.
 * 		src - sockaddr_storage structure to put result into.
 * @returns	pointer to sockaddr_storage structure containing result on success.
 *		NULL on error.
 */
struct sockaddr_storage *bd_flow_get_source_ip(Flow *flow, struct sockaddr_storage *src);

/* Get the initial destination IP address for the current packets flow.
 *
 * @params      flow - Libflowmanager flow.
 *              src - sockaddr_storage structure to put result into.
 * @returns     pointer to sockaddr_storage structure containing result on success.
 *              NULL on error.
 */
struct sockaddr_storage *bd_flow_get_destination_ip(Flow *flow, struct sockaddr_storage *dst);

/* Get the protocol for the current packets flow.
 *
 * @params	bigdata - bigdata structure.
 * @returns	lpi_protocol_t protocol on success.
 *		LPI_PROTO_UNKNOWN if protocol is unknown or on error.
 */
lpi_protocol_t bd_flow_get_protocol(Flow *flow);

/* Get the protocol category for the current packets flow.
 *
 * @params	bigdata - bigdata structure.
 * @returns	lpi_category_t category on success.
 *		LPI_CATEGORY_UNKNOWN if category is unknown or on error.
 */
lpi_category_t bd_flow_get_category(Flow *flow);

/* Get the lpi_module for the current packets flow.
 *
 * @params	Bigdata - bigdata structure.
 * @returns	pointer to lpi_module_t on success.
 *		NULL pointer on error.
 */
lpi_module_t *bd_flow_get_lpi_module(Flow *flow);

/* Get the Flowmanager for the current packet processing thread.
 *
 * @params	bigdata - bigdata structure.
 * @returns	pointer to the Flowmanager on success.
 * 		NULL pointer on error.
 */
FlowManager *bd_flow_get_flowmanager(bd_bigdata_t *bigdata);

/* Get the flow for the current packet.
 *
 * @params	bigdata - bigdata structure.
 * @returns	pointer to Libflowmanager flow on success.
 * 		NULL pointer on error.
 */
Flow *bd_flow_get(bd_bigdata_t *bigdata);

/* Get the flow record for the current packets flow.
 *
 * @params 	bigdata - bigdata structure.
 * @returns	pointer to the flow record on success.
 * 		NULL pointer on error.
 */
bd_flow_record_t *bd_flow_get_record(Flow *flow);

/* Get the duration for the current packets flow.
 *
 * @params	bigdata - bigdata structure.
 * @returns	the duration of the current flow on success.
 */
double bd_flow_get_duration(Flow *flow);

/* Get the unique ID associated with the current packets flow
 *
 * @params 	bigdata - bigdata structure.
 * @returns	id associated with the flow on success.
 * 		0 on error.
 */
uint64_t bd_flow_get_id(Flow *flow);

/* Gets the flows destination ip address as a string.
 * Note: This is the destination IP from the first SYN packet seen for this flow.
 *
 * @params	flow - The flow.
 *		space - allocated space for the result, be aware of IPv6 addresses.
 *		spacelen - the size of space available for the result.
 * @returns	Pointer to the begining of IP address on success.
 *		NULL on error.
 */
char *bd_flow_get_destination_ip_string(Flow *flow, char *space, int spacelen);

/* Gets the flows souce ip address as a string.
 * Note: This is the souce IP from the first SYN packet seen for this flow.
 *
 * @params      flow - The flow.
 *              space - allocated space for the result, be aware of IPv6 addresses.
 *              spacelen - the size of space available for the result.
 * @returns     Pointer to the begining of IP address on success.
 *              NULL on error.
 */
char *bd_flow_get_source_ip_string(Flow *flow, char *space, int spacelen);

/* Returns a timeval structure containing the time the flow started.
 *
 * @params	flow - The flow.
 * @returns	struct timeval filled with the flows start time on success.
 * 		struct timeval with tv_sec and tv_usec set to -1 on error.
 */
struct timeval bd_flow_get_start_timeval(Flow *flow);

/* Returns the millisecond timestamp for when the flow started.
 *
 * @params	flow - The flow.
 * @returns	the flows start time on success.
 *		0 on error.
 */
uint64_t bd_flow_get_start_time_milliseconds(Flow *flow);

/* Returns a timeval structure containing the time the flow ended. If the flow is
 * has not yet finished this will return the timestamp for the last seen packet
 * for the flow.
 *
 * @params      flow - The flow.
 * @returns     struct timeval filled with the flows end time on success.
 *              struct timeval with tv_sec and tv_usec set to -1 on error.
 */
struct timeval bd_flow_get_end_timeval(Flow *flow);

/* Returns the millisecond timestamp for when the flow ended. If the flow is
 * has not yet finished this will return the timestamp for the last seen packet
 * for the flow.
 *
 * @params      flow - The flow.
 * @returns     the flows end time on success.
 *              0 on error.
 */
uint64_t bd_flow_get_end_time_milliseconds(Flow *flow);

/* Returns the time to first byte for the supplied flow
 *
 * @params	flow - The flow.
 * @returns	the time to first byte for the flow on success.
 *		0 on error.
 */
double bd_flow_get_time_to_first_byte(Flow *flow);

#endif
