#include "module_http.h"
#include "bigdata.h"

int module_http_packet(libtrace_t *trace, libtrace_packet_t *packet, Flow *flow,
    void *tls, void *mls);

int module_http_packet(libtrace_t *trace, libtrace_packet_t *packet, Flow *flow,
    void *tls, void *mls) {

    fprintf(stderr, "HTTP packet\n");
    return 1;
}

int module_http_init() {
    bd_cb_set *callbacks = bd_create_cb_set();

    callbacks->packet_cb = (cb_packet)module_http_packet;

    bd_add_filter_to_cb_set(callbacks, "port 80");

    bd_register_cb_set(callbacks);
}
