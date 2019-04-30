#ifndef BIGDATA_FLOW_H
#define BIGDATA_FLOW_H

#include "bigdata.h"

Flow *flow_per_packet(libtrace_t *trace, libtrace_thread_t *thread,
    libtrace_packet_t *packet, void *global, void *tls);

int flow_expire(libtrace_t *trace, libtrace_thread_t *thread,libtrace_packet_t *packet,
    void *global, void *tls);

#endif
