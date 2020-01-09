#include <module_observed_packet.h>

/* this structure is used hold configuration related items for the plugin. */
struct module_observed_packets_config {
    bd_cb_set *callbacks;	/* the callback set contains all the callback functions/events for the plugin.
                                 * this is effectivly the configuration of the plugin.
                                 */
    bool enabled;
}

/* structure to keep track of the number of packets observed. */
struct module_observed_packets_storage {
    uint64_t packets;
}

/* This is the packet processing threads starting function. This function is used
 * to initialise any storage required by the packet processing threads for this plugin.
 */
void *module_observed_packets_starting(void *tls) {

    /* declare and allocate memory for the packet counter */
    struct module_observed_packets_storage *storage;
    storage = (struct module_observed_packets_storage *)malloc(sizeof(
        struct module_observed_packets_storage));

    /* initialise the number of seen packets */
    storage->packets = 0;

    /* this structure must be returned by the starting function. It will now be accessable
     * within other packet processing threads function via the mls parameter.
     */
    return storage;
}

/* This function will be processed by the packet processing thread and will be called for
 * every packet received.
 */
int module_observed_packets_packet(bd_bigdata_t bigdata, void *tls, void *mls) {

    
}
