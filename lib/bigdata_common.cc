#include "bigdata_common.h"

static int network_get_direction(bd_bigdata_t *bigdata);
static int port_get_direction(libtrace_packet_t *packet);

int bd_get_packet_direction(bd_bigdata_t *bigdata) {

    int dir;
    libtrace_packet_t *packet = bigdata->packet;
    bd_global_t *global = bigdata->global;
    bd_cache_t *cache = &(bigdata->cache);

    if (packet == NULL) {
        logger(LOG_DEBUG, "NULL packet. func. bd_get_packet_direction()\n");
        return -1;
    }

    /* if a cached value exists for this packet */
    if (cache->packet_direction != -1) {
        return cache->packet_direction;
    }


    switch (global->config->dir_method) {
        case DIR_METHOD_TRACE:
            dir = trace_get_direction(bigdata->packet);
            break;
        case DIR_METHOD_NETWORK:
            dir = network_get_direction(bigdata);
            break;
        case DIR_METHOD_PORT:
            dir = port_get_direction(bigdata->packet);
            break;
    }

    /* cache the direction for this packet */
    cache->packet_direction = dir;

    return dir;
}

static int network_get_direction(bd_bigdata_t *bigdata) {

    libtrace_packet_t *packet = bigdata->packet;
    bd_global_t *global = bigdata->global;

    struct sockaddr_storage src_addr, dst_addr;
    struct sockaddr *src_ip, *dst_ip;

    src_ip = trace_get_source_address(packet, (struct sockaddr *)&src_addr);
    dst_ip = trace_get_destination_address(packet, (struct sockaddr *)&dst_addr);

    for (int i=0; i < global->config->local_subnets_count; i++) {
        bd_network_t *network = global->config->local_subnets[i];

        struct sockaddr *address = (struct sockaddr *)&(network->address);
        struct sockaddr *mask = (struct sockaddr *)&(network->mask);

        // ensure both addresses are of the same family
        if (address->sa_family == src_ip->sa_family) {

            if (src_ip->sa_family == AF_INET) {
                // IPv4
                struct sockaddr_in *packet_in = (struct sockaddr_in *)src_ip;
                struct sockaddr_in *network_in = (struct sockaddr_in *)address;
                struct sockaddr_in *mask_in = (struct sockaddr_in *)mask;

                struct in_addr *packet_addr = (struct in_addr *)&(packet_in->sin_addr);
                struct in_addr *network_addr = (struct in_addr *)&(network_in->sin_addr);
                struct in_addr *mask_addr = (struct in_addr *)&(mask_in->sin_addr);

                // check source
                if ((packet_addr->s_addr & mask_addr->s_addr) == network_addr->s_addr) {
                    return 0;
                }

                packet_in = (struct sockaddr_in *)dst_ip;
                packet_addr = (struct in_addr *)&(packet_in->sin_addr);

                // check destination
                if ((packet_addr->s_addr & mask_addr->s_addr) == network_addr->s_addr) {
                    return 1;
                }
            }

            if (src_ip->sa_family == AF_INET6) {
                // IPv6
                struct sockaddr_in6 *packet_in = (struct sockaddr_in6 *)src_ip;
                struct sockaddr_in6 *network_in = (struct sockaddr_in6 *)address;
                struct sockaddr_in6 *mask_in = (struct sockaddr_in6 *)mask;

                struct in6_addr *packet_addr = (struct in6_addr *)&(packet_in->sin6_addr);
                struct in6_addr *network_addr = (struct in6_addr *)&(network_in->sin6_addr);
                struct in6_addr *mask_addr = (struct in6_addr *)&(mask_in->sin6_addr);

                uint8_t tmp[16];
                bool match = 1;

                // check source
                for (int i = 0; i < 16; i++) {
                    tmp[i] = packet_addr->s6_addr[i] & mask_addr->s6_addr[i];
                    if (tmp[i] != network_addr->s6_addr[i]) {
                        match = 0;
                    }
                }
                if (match) {
                    return 0;
                }

                packet_in = (struct sockaddr_in6 *)dst_ip;
                packet_addr = (struct in6_addr *)&(packet_in->sin6_addr);
                match = 1;

                // check destination
                for (int i = 0; i < 16; i++) {
                    tmp[i] = packet_addr->s6_addr[i] & mask_addr->s6_addr[i];
                    if (tmp[i] != network_addr->s6_addr[i]) {
                        match = 0;
                    }
                }
                if (match) {
                    return 1;
                }

            }
        }
    }

    /* if we got this far the source or destination ip was not found within the packet.
     * return -1 to indicate an error */
    return -1;
}

// returns 1 is ip is local, else 0
int bd_local_ip(bd_bigdata_t *bigdata, struct sockaddr *ip) {

    bd_global_t *global = bigdata->global;
    bd_cache_t *cache = &(bigdata->cache);

    /* If a cached value exists for this packet */
    if (cache->ip_local != -1) {
        return cache->ip_local;
    }

    // iterate over all local ips
    for (int i=0; i < global->config->local_subnets_count; i++) {
        bd_network_t *network = global->config->local_subnets[i];

        struct sockaddr *address = (struct sockaddr *)&(network->address);
        struct sockaddr *mask = (struct sockaddr *)&(network->mask);

        if (address->sa_family == ip->sa_family) {
            if (ip->sa_family != AF_INET && ip->sa_family != AF_INET6) {
                cache->ip_local = -1;
                return cache->ip_local;
            }

            if (ip->sa_family == AF_INET) {
                struct sockaddr_in *ip_in = (struct sockaddr_in *)ip;
                struct sockaddr_in *network_in = (struct sockaddr_in *)address;
                struct sockaddr_in *mask_in = (struct sockaddr_in *)mask;

                struct in_addr *ip_addr = (struct in_addr *)&(ip_in->sin_addr);
                struct in_addr *network_addr = (struct in_addr *)&(network_in->sin_addr);
                struct in_addr *mask_addr = (struct in_addr *)&(mask_in->sin_addr);

                // check if the supplied ip is within the current network
                if ((ip_addr->s_addr & mask_addr->s_addr) == network_addr->s_addr) {
                    cache->ip_local = 1;
                    return cache->ip_local;
                }
            }

            if (ip->sa_family == AF_INET6) {
                struct sockaddr_in6 *ip_in = (struct sockaddr_in6 *)ip;
                struct sockaddr_in6 *network_in = (struct sockaddr_in6 *)address;
                struct sockaddr_in6 *mask_in = (struct sockaddr_in6 *)mask;

                struct in6_addr *ip_addr = (struct in6_addr *)&(ip_in->sin6_addr);
                struct in6_addr *network_addr = (struct in6_addr *)&(network_in->sin6_addr);
                struct in6_addr *mask_addr = (struct in6_addr *)&(mask_in->sin6_addr);

                uint8_t tmp[16];
                bool match = 1;
                for (int i = 0; i < 16; i++) {
                    tmp[i] = ip_addr->s6_addr[i] & mask_addr->s6_addr[i];
                    if (tmp[i] != network_addr->s6_addr[i]) {
                        match = 0;
                    }
                }
                if (match) {
                    cache->ip_local = 1;
                    return cache->ip_local;
                }
            }
        }
    }

    // got this far, no match
    cache->ip_local = 0;
    return cache->ip_local;
}

libtrace_t *bd_get_trace(bd_bigdata_t *bigdata) {
    return bigdata->trace;
}

libtrace_thread_t *bd_get_thread(bd_bigdata_t *bigdata) {
    return bigdata->thread;
}

libtrace_packet_t *bd_get_packet(bd_bigdata_t *bigdata) {
    return bigdata->packet;
}

char *bd_replaceWord(const char *s, const char *oldsubstr, const char *newsubstr) {
    char *result;
    int i, cnt = 0;
    int newWlen = strlen(newsubstr);
    int oldWlen = strlen(oldsubstr);

    // Counting the number of times old word
    // occur in the string
    for (i = 0; s[i] != '\0'; i++) {
        if (strstr(&s[i], oldsubstr) == &s[i]) {
            cnt++;

            // Jumping to index after the old word.
            i += oldWlen - 1;
        }
    }

    // Making new string of enough length
    result = (char *)malloc(i + cnt * (newWlen - oldWlen) + 1);

    i = 0;
    while (*s) {
        // compare the substring with the result
        if (strstr(s, oldsubstr) == s) {
            strcpy(&result[i], newsubstr);
            i += newWlen;
            s += oldWlen;
        } else {
            result[i++] = *s++;
        }
    }

    result[i] = '\0';
    return result;
}

/*
 * Copyright (c) 2011 The University of Waikato, Hamilton, New Zealand.
 * Author: Shane Alcock
 *
 * With contributions from:
 *      Aaron Murrihy
 *      Donald Neal
 *
 * All rights reserved.
 *
 * This code has been developed by the University of Waikato WAND
 * research group. For further information please see http://www.wand.net.nz/
 *
 * libprotoident is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * libprotoident is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with libprotoident; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * $Id$
 */

static int port_get_direction(libtrace_packet_t *packet) {
	uint16_t src_port;
        uint16_t dst_port;
	int dir = 2;
	void *l3;
	uint16_t ethertype;
	uint32_t rem;
	libtrace_ip_t *ip = NULL;
	libtrace_ip6_t *ip6 = NULL;
	uint8_t proto;

	src_port = trace_get_source_port(packet);
        dst_port = trace_get_destination_port(packet);

	l3 = trace_get_layer3(packet, &ethertype, &rem);
		
	if (ethertype == TRACE_ETHERTYPE_IP && rem >= sizeof(libtrace_ip_t)) {
		ip = (libtrace_ip_t *)l3;
		proto = ip->ip_p;
	}
	if (ethertype == TRACE_ETHERTYPE_IPV6 && rem >= sizeof(libtrace_ip6_t)) 	{
		ip6 = (libtrace_ip6_t *)l3;
		proto = ip6->nxt;
	}


        if (src_port == dst_port) {

		if (l3 == NULL || rem == 0)
			return dir;

		if (ip) {
	                if (ip->ip_src.s_addr < ip->ip_dst.s_addr)
        	                dir = 0;
        	        else
        	                dir = 1;
		}

		if (ip6) {
			if (memcmp(&(ip6->ip_src), &(ip6->ip_dst), 
						sizeof(struct in6_addr)) < 0) {
				dir = 0;
			} else {
				dir = 1;
			}
		}

        } else {
                if (trace_get_server_port(proto, src_port, dst_port) 
					== USE_SOURCE) {
                        dir = 0;
		} else {
                        dir = 1;
		}
        }

	return dir;
}
