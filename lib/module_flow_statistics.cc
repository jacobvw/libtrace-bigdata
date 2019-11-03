#include "bigdata.h"
#include "module_flow_statistics.h"

/* configuration structure for the plugin */
struct module_flow_statistics_config {
    bd_cb_set *callbacks;
    bool enabled;
    bool protocol[LPI_PROTO_LAST];
};
/* global varible used to read from module configuration */
static struct module_flow_statistics_config *config;

int module_flow_statistics_protocol_updated(bd_bigdata_t *bigdata, void *mls, lpi_protocol_t oldproto,
    lpi_protocol_t newproto) {

    if (config->protocol[newproto]) {

        /* This is done here because the flowstart event does not yet
         * have the correct protocol with only the first packet
         */
        bd_result_set_t *res = bd_result_set_create("flow_statistics");
        bd_result_set_insert_uint(res, "flow_id", bigdata->flow->id.get_id_num());
        bd_result_set_insert_tag(res, "protocol", lpi_print(newproto));
        bd_result_set_insert_string(res, "type", "flow_start");

        char *src_ip = (char *)malloc(INET6_ADDRSTRLEN);
        src_ip = trace_get_source_address_string(bigdata->packet, src_ip, INET6_ADDRSTRLEN);
        bd_result_set_insert_string(res, "src_ip", src_ip);

        char *dst_ip = (char *)malloc(INET6_ADDRSTRLEN);
        dst_ip = trace_get_destination_address_string(bigdata->packet, dst_ip, INET6_ADDRSTRLEN);
        bd_result_set_insert_string(res, "dst_ip", dst_ip);

        bd_result_set_publish(bigdata, res, 0);

        free(src_ip);
        free(dst_ip);
    }
}

int module_flow_statistics_flowend(bd_bigdata_t *bigdata, void *mls, bd_flow_record_t *flow_record) {

}

/* define the configuration function */
int module_flow_statistics_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

    /* parse the plugins configuration from the configuration file. Currently this
     * plugin only supports the enabled parameter
     */
    int enter_level = *level;
    bool first_pass = 1;

    while (enter_level != *level || first_pass) {
        first_pass = 0;
        switch(event->type) {
            case YAML_SCALAR_EVENT:
                if (strcmp((char *)event->data.scalar.value, "enabled") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "t") == 0) {

                        config->enabled = 1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "protocols") == 0) {
                    /* consume protocols event */
                    consume_event(parser, event, level);

                    /* must be a yaml_sequence_start_event or conf is malformed */
                    if (event->type != YAML_SEQUENCE_START_EVENT) {
                        fprintf(stderr, "Malformed configuration: Section flow_statistics/protocols\n");
                        exit(BD_MALFORMED_CONF);
                    }

                    // consume yaml_mapping_start event
                    consume_event(parser, event, level);

                    // for each protocol supplied
                    while (event->type != YAML_SEQUENCE_END_EVENT) {

                        /* somehow convert libprotoident event string to enum? */

                        /* consume the event */
                        consume_event(parser, event, level);
                    }

                    /* consume the final sequence end event */
                    if (event->type == YAML_SEQUENCE_END_EVENT) {
                        consume_event(parser, event, level);
                    }

                    break;

                }
            default:
                consume_event(parser, event, level);
                break;
        }
    }

    /* if the plugin was enabled define its callback functions for each event */
    if (config->enabled) {

        config->callbacks->protocol_updated_cb = (cb_protocol_updated)
            module_flow_statistics_protocol_updated;

        config->callbacks->flowend_cb = (cb_flowend)module_flow_statistics_flowend;

        fprintf(stdout, "Flow Statistics Plugin Enabled\n");
    }
}


/* define the initialisation function for the plugin, This is called by the application
 * core on startup */
int module_flow_statistics_init() {

    /* create storage for the plugins conf structure */
    config = (struct module_flow_statistics_config *)malloc(sizeof(struct
        module_flow_statistics_config));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_flow_statistics_init()\n");
        exit(BD_OUTOFMEMORY);
    }


    /* init the config structure */
    config->enabled = 0;
    /* initialise all protocols to false */
    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        config->protocol[i] = 0;
    }

    /* create callback set used to map callback functions to each event */
    config->callbacks = bd_create_cb_set("flow_statistics");

    /* define a configuration function for the plugin */
    config->callbacks->config_cb = (cb_config)module_flow_statistics_config;

    /* register the callback set against the application core */
    bd_register_cb_set(config->callbacks);
}
