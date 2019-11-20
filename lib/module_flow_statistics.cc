#include "module_flow_statistics.h"

/* configuration structure for the plugin */
struct module_flow_statistics_config {
    bd_cb_set *callbacks;
    bool enabled;
    int output_interval;
    bool protocol[LPI_PROTO_LAST];
};
/* global varible used to read from module configuration */
static struct module_flow_statistics_config *config;

struct module_flow_statistics_flow {
    bd_bigdata_t *bigdata;
    module_flow_statistics_config *c;
};

/* function to apply to each flow */
int module_flow_statistics_foreach_flow(Flow *flow, void *data) {

    char ip_tmp[INET6_ADDRSTRLEN];

    /* gain access to the flow record */
    bd_flow_record_t *flow_rec = (bd_flow_record_t *)flow->extension;

    /* gain access to the configuration structure */
    struct module_flow_statistics_flow *f = (struct module_flow_statistics_flow *)
        data;

    /* ensure lpi_module is not NULL */
    if (flow_rec->lpi_module != NULL) {
        /* check the protocol is a wanted one */
        if (f->c->protocol[flow_rec->lpi_module->protocol]) {

            bd_result_set_t *res = bd_result_set_create("flow_statistics");
            bd_result_set_insert_uint(res, "flow_id", flow->id.get_id_num());
            bd_result_set_insert_tag(res, "protocol", lpi_print(flow_rec->lpi_module->protocol));
            bd_result_set_insert_tag(res, "type", "flow_interval");

            bd_result_set_insert_double(res, "start_ts", flow_rec->start_ts);
            bd_result_set_insert_double(res, "duration", flow_rec->end_ts - flow_rec->start_ts);

            bd_flow_get_source_ip_string(flow, ip_tmp, INET6_ADDRSTRLEN);
            bd_result_set_insert_string(res, "source_ip", ip_tmp);
            bd_flow_get_destination_ip_string(flow, ip_tmp, INET6_ADDRSTRLEN);
            bd_result_set_insert_string(res, "destination_ip", ip_tmp);

            bd_result_set_insert_int(res, "src_port", flow_rec->src_port);
            bd_result_set_insert_int(res, "dst_port", flow_rec->dst_port);
            bd_result_set_insert_uint(res, "in_bytes", flow_rec->in_bytes);
            bd_result_set_insert_uint(res, "out_bytes", flow_rec->out_bytes);

            bd_result_set_publish(f->bigdata, res, 0);
        }
    }

    return 1;
}

int module_flow_statistics_tick(bd_bigdata_t *bigdata, void *mls, uint64_t tick) {

    struct module_flow_statistics_flow f;
    f.bigdata = bigdata;
    f.c = config;

    FlowManager *fm = bd_flow_get_flowmanager(bigdata);

    if (fm->foreachFlow(module_flow_statistics_foreach_flow, &f) == -1) {
        fprintf(stderr, "Error applying foreach flow funcion. func. "
            "module_flow_statistics_tick()\n");
    }

    return 0;
}

int module_flow_statistics_protocol_updated(bd_bigdata_t *bigdata, void *mls, lpi_protocol_t oldproto,
    lpi_protocol_t newproto) {

    bd_flow_record_t *flow_rec;
    char ip_tmp[INET6_ADDRSTRLEN];

    if (config->protocol[newproto]) {

        flow_rec = bd_flow_get_record(bigdata->flow);

        /* This is done here because the flowstart event does not yet
         * have the correct protocol with only the first packet
         */
        bd_result_set_t *res = bd_result_set_create("flow_statistics");
        bd_result_set_insert_uint(res, "flow_id", bigdata->flow->id.get_id_num());
        bd_result_set_insert_tag(res, "protocol", lpi_print(newproto));
        bd_result_set_insert_string(res, "type", "flow_start");

        bd_result_set_insert_double(res, "start_ts", flow_rec->start_ts);
        bd_result_set_insert_double(res, "duration", flow_rec->end_ts - flow_rec->start_ts);

        bd_flow_get_source_ip_string(bigdata->flow, ip_tmp, INET6_ADDRSTRLEN);
        bd_result_set_insert_string(res, "source_ip", ip_tmp);
        bd_flow_get_destination_ip_string(bigdata->flow, ip_tmp, INET6_ADDRSTRLEN);
        bd_result_set_insert_string(res, "destination_ip", ip_tmp);

        bd_result_set_insert_int(res, "src_port", flow_rec->src_port);
        bd_result_set_insert_int(res, "dst_port", flow_rec->dst_port);
        bd_result_set_insert_uint(res, "in_bytes", flow_rec->in_bytes);
        bd_result_set_insert_uint(res, "out_bytes", flow_rec->out_bytes);

        bd_result_set_publish(bigdata, res, 0);
    }

    return 0;
}

int module_flow_statistics_flowend(bd_bigdata_t *bigdata, void *mls, bd_flow_record_t *flow_record) {

    char ip_tmp[INET6_ADDRSTRLEN];

    if(config->protocol[bd_flow_get_protocol(bigdata->flow)]) {
        bd_result_set_t *res = bd_result_set_create("flow_statistics");
        bd_result_set_insert_uint(res, "flow_id", bigdata->flow->id.get_id_num());
        bd_result_set_insert_tag(res, "protocol", lpi_print(bd_flow_get_protocol(bigdata->flow)));
        bd_result_set_insert_string(res, "type", "flow_end");

        bd_result_set_insert_double(res, "start_ts", flow_record->start_ts);
        bd_result_set_insert_double(res, "duration", flow_record->end_ts - flow_record->start_ts);
        bd_result_set_insert_double(res, "end_ts", flow_record->end_ts);

        bd_flow_get_source_ip_string(bigdata->flow, ip_tmp, INET6_ADDRSTRLEN);
        bd_result_set_insert_string(res, "source_ip", ip_tmp);
        bd_flow_get_destination_ip_string(bigdata->flow, ip_tmp, INET6_ADDRSTRLEN);
        bd_result_set_insert_string(res, "destination_ip", ip_tmp);


        bd_result_set_insert_int(res, "src_port", flow_record->src_port);
        bd_result_set_insert_int(res, "dst_port", flow_record->dst_port);
        bd_result_set_insert_uint(res, "in_bytes", flow_record->in_bytes);
        bd_result_set_insert_uint(res, "out_bytes", flow_record->out_bytes);

        bd_result_set_publish(bigdata, res, 0);
    }

    return 0;
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

                        fprintf(stdout, "Flow Statistics Plugin Enabled\n");
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "output_interval") == 0) {
                    consume_event(parser, event, level);
                    config->output_interval = atoi((char *)event->data.scalar.value);
                    if (config->output_interval != 0) {
                        bd_add_tickrate_to_cb_set(config->callbacks, config->output_interval);
                    } else {
                        fprintf(stderr, "Invalid output_interval value. "
                            "module_flow_statistics. Disabling module\n");
                        config->enabled = 0;
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

                        /* try to convert the protocol string supplied into a
                         * lpi_protocol_t. Enable the protocol if found */
                        lpi_protocol_t protocol;
                        protocol = lpi_get_protocol_by_name((char *)event->data.scalar.value);
                        if (protocol != LPI_PROTO_LAST) {
                            if (config->enabled) {
                                fprintf(stderr, "\tEnabling Protocol: %s\n",
                                    (char *)event->data.scalar.value);
                            }
                            config->protocol[protocol] = 1;
                        } else {
                            if (config->enabled) {
                                fprintf(stderr, "\tCould Not Find Protocol: %s\n",
                                    (char *)event->data.scalar.value);
                            }
                        }

                        /* consume the event */
                        consume_event(parser, event, level);
                    }

                    /* consume the final sequence end event */
                    if (event->type == YAML_SEQUENCE_END_EVENT) {
                        consume_event(parser, event, level);
                    }

                    break;

                }
                consume_event(parser, event, level);
                break;
            default:
                consume_event(parser, event, level);
                break;
        }
    }

    /* if the plugin was enabled define its callback functions for each event */
    if (config->enabled) {

        config->callbacks->protocol_updated_cb = (cb_protocol_updated)
            module_flow_statistics_protocol_updated;
        config->callbacks->tick_cb = (cb_tick)module_flow_statistics_tick;
        config->callbacks->flowend_cb = (cb_flowend)module_flow_statistics_flowend;

    }

    return 0;
}


/* define the initialisation function for the plugin, This is called by the application
 * core on startup */
int module_flow_statistics_init(bd_bigdata_t *bigdata) {

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
    config->output_interval = 0;
    /* initialise all protocols to false */
    for (int i = 0; i < LPI_PROTO_LAST; i++) {
        config->protocol[i] = 0;
    }

    /* create callback set used to map callback functions to each event */
    config->callbacks = bd_create_cb_set("flow_statistics");

    /* define a configuration function for the plugin */
    config->callbacks->config_cb = (cb_config)module_flow_statistics_config;

    /* register the callback set against the application core */
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}
