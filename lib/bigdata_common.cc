#include "bigdata_common.h"

int bd_get_packet_direction(bd_bigdata_t *bigdata) {

    libtrace_packet_t *packet = bigdata->packet;
    bd_global_t *global = bigdata->global;

    if (packet == NULL) {
        fprintf(stderr, "NULL packet. func. bd_get_packet_direction()\n");
        return -1;
    }

    if (global->config->local_networks_as_direction) {
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
                    if (match) { return 0; }

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
                    if (match) { return 1; }

                }
            }
        }
    }

    return trace_get_direction(packet);

}

// returns 1 is ip is local, else 0
int bd_local_ip(bd_bigdata_t *bigdata, struct sockaddr *ip) {

    bd_global_t *global = bigdata->global;

    // iterate over all local ips
    for (int i=0; i < global->config->local_subnets_count; i++) {
        bd_network_t *network = global->config->local_subnets[i];

        struct sockaddr *address = (struct sockaddr *)&(network->address);
        struct sockaddr *mask = (struct sockaddr *)&(network->mask);

        if (address->sa_family == ip->sa_family) {
            if (ip->sa_family != AF_INET && ip->sa_family != AF_INET6) {
                return -1;
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
                    return 1;
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
                if (match) { return 1; }
            }
        }
    }

    // got this far, no match
    return 0;
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
    int newWlen = strlen(newW);
    int oldWlen = strlen(oldW);

    // Counting the number of times old word
    // occur in the string
    for (i = 0; s[i] != '\0'; i++) {
        if (strstr(&s[i], oldW) == &s[i]) {
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
        if (strstr(s, oldW) == s) {
            strcpy(&result[i], newW);
            i += newWlen;
            s += oldWlen;
        } else {
            result[i++] = *s++;
        }
    }

    result[i] = '\0';
    return result;
}
