#ifndef BIGDATA_COMMON_H
#define BIGDATA_COMMON_H

#include "bigdata.h"

/* API functions */

/* Get the direction the packet is travelling. If configuration
 * option local_networks_as_direction is enabled this will be used
 * to check the packets direction, if not enabled trace_get_direction()
 * from Libtrace is used.
 *
 * @param       The packet to check the direction for
 * @returns     0 if the packet is outbound
 *              1 if the packet is inbound
 */
int bd_get_packet_direction(bd_bigdata_t *bigdata);

/* Checks if the supplied IP address is part of one of the local networks
 *
 * @param       sockaddr structure for the IP to check
 * @returns     1 if the IP is a local IP
 *              0 if the IP is not a local IP
 *              -1 if the supplied IP is not IP4 or IP6
 */
int bd_local_ip(bd_bigdata_t *bigdata, struct sockaddr *ip);

/* Get the Libtrace trace file.
 *
 * @param       bigdata structure
 * @returns     Libtrace trace file
 */
libtrace_t *bd_get_trace(bd_bigdata_t *bigdata);

/* Get the Libtrace thread.
 *
 * @param       bigdata structure
 * @returns     Libtrace thread
 */
libtrace_thread_t *bd_get_thread(bd_bigdata_t *bigdata);

/* Get the Libflowmanager flow.
 *
 * @param       bigdata strucure
 * @returns     Libflowmanager flow
 */
Flow *bd_get_flow(bd_bigdata_t *bigdata);

/* Get the Libtrace packet.
 *
 * @params      bigdata structure
 * @returns     Libtrace packet
 */
libtrace_packet_t *bd_get_packet(bd_bigdata_t *bigdata);

/** Replaces all occurances of a substring within a string with another substring.
 *
 * @params	s - the main string
 *		oldsubstr - the substring to remove.
 *		newsubstr - the substring to replace oldsubstr with.
 * @returns	a new malloc'd string with all occurances of oldsubstr replaced with
 *		newsubstr.
 */
char *bd_replaceWord(const char *s, const char *oldsubstr, const char *newsubstr);

#endif
