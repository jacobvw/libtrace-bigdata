#include "module_port.h"
#include "bigdata.h"

typedef struct module_port_stats {
    uint64_t packets = 0;
    uint64_t bytes = 0;
} mod_port_stat_t;

typedef struct module_port_storage {
    mod_port_stat_t source_port[65535];
    mod_port_stat_t dest_port[65535];
} mod_port_t;

void *module_port_starting(void *tls);
int module_port_packet(libtrace_t *trace, libtrace_packet_t *packet, Flow *flow, void *tls, void *mls);
void *module_port_ending(void *tls, void *mls);

void *module_port_starting(void *tls) {
    mod_port_t *storage = (mod_port_t *)malloc(sizeof(mod_port_t));

    return storage;
}

int module_port_packet(libtrace_t *trace, libtrace_packet_t *packet, Flow *flow, void *tls, void *mls) {

    uint16_t ethertype;
    uint32_t remaining;

    mod_port_t *storage = (mod_port_t *)mls;

    uint16_t source_port = trace_get_source_port(packet);
    uint16_t dest_port = trace_get_destination_port(packet);
    int direction = trace_get_direction(packet);
    void *payload = trace_get_layer3(packet, &ethertype, &remaining);

    // packet does not contain source or dest ports
    if (!source_port || !dest_port) {
        return -1;
    }

    // dir = 1 means inbound packet
    if (direction) {
        storage->dest_port[dest_port].packets += 1;
        storage->dest_port[dest_port].bytes += remaining;
        fprintf(stderr, "IN: source port %u dest port %u packets %lu bytes %lu\n", source_port, dest_port, storage->dest_port[dest_port].packets,
            storage->dest_port[dest_port].bytes);
    } else {
        storage->source_port[source_port].packets += 1;
        storage->source_port[source_port].bytes += remaining;
        fprintf(stderr, "OUT: source port %u dest port %u packets %lu bytes %lu\n", source_port, dest_port, storage->source_port[source_port].packets,
            storage->source_port[source_port].bytes);
    }
}

void *module_port_ending(void *tls, void *mls) {
    mod_port_t *data = (mod_port_t *)mls;
    if (data != NULL) {
        free(data);
    }
}

int module_port_init() {

    bd_cb_set *callbacks = bd_create_cb_set();

    callbacks->start_cb = (cb_start)module_port_starting;
    callbacks->packet_cb = (cb_packet)module_port_packet;
    callbacks->stop_cb = (cb_stop)module_port_ending;

    bd_register_cb_set(callbacks);

}
