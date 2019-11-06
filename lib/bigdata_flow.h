
#ifndef BIGDATA_FLOW_H
#define BIGDATA_FLOW_H

#include "bigdata.h"

/* Flow record structure */
typedef struct bigdata_flow_record {
    double start_ts;
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
static int flow_init_metrics(libtrace_packet_t *packet, Flow *flow, uint8_t dir, double ts);
static int flow_process_metrics(libtrace_t *trace, libtrace_thread_t *thread, libtrace_packet_t *packet,
    Flow *flow, void *global, void *tls, double dir, double ts);

int flow_expire(libtrace_t *trace, libtrace_thread_t *thread,libtrace_packet_t *packet,
    void *global, void *tls);
Flow *flow_per_packet(libtrace_t *trace, libtrace_thread_t *thread,
    libtrace_packet_t *packet, void *global, void *tls);

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
 * @returns	Libprotoident protocol on success.
 *		LPI_PROTO_UNKNOWN on error
 */
lpi_protocol_t bd_flow_get_protocol(bd_bigdata_t *bigdata);

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
bd_flow_record_t *bd_flow_get_record(bd_bigdata_t *bigdata);

/* Get the duration for the current packets flow.
 *
 * @params	bigdata - bigdata structure.
 * @returns	the duration of the current flow on success.
 */
double bd_flow_get_duration(bd_bigdata_t *bigdata);

/* Get the unique ID associated with the current packets flow
 *
 * @params 	bigdata - bigdata structure.
 * @returns	id associated with the flow on success.
 * 		0 on error.
 */
uint64_t bd_flow_get_id(bd_bigdata_t *bigdata);

#endif
