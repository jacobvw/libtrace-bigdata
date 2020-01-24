#include "module_flow_statistics.h"
#include <map>

/* configuration structure for the plugin */
struct module_flow_statistics_config {
    bd_cb_set *callbacks;
    bool enabled;
    int output_interval;
    bool monitor_all;
    bool protocol[LPI_PROTO_LAST];
    bool category[LPI_CATEGORY_LAST];
    bool export_tls;
};
/* global varible used to read from module configuration */
static struct module_flow_statistics_config *config;

typedef struct module_flow_statistics_stats {
    uint64_t in_bytes;
    uint64_t out_bytes;
} mod_flow_stats;

struct module_flow_statistics_flow {
    bd_bigdata_t *bigdata;
    module_flow_statistics_config *c;
    uint64_t tick;
    std::map<uint64_t, mod_flow_stats> *flow_stats;
};

typedef struct module_flow_statistics_storage {
    std::map<uint64_t, mod_flow_stats> *flow_stats;
} mod_flow_stats_stor;

void *module_flow_statistics_starting(void *tls) {

    mod_flow_stats_stor *storage;

    storage = (mod_flow_stats_stor *)malloc(sizeof(mod_flow_stats_stor));
    if (storage == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_flow_statistics_starting()");
        exit(BD_OUTOFMEMORY);
    }

    storage->flow_stats = new std::map<uint64_t, mod_flow_stats>;

    return storage;
}

/* function to apply to each flow */
int module_flow_statistics_foreach_flow(Flow *flow, void *data) {

    char ip_tmp[INET6_ADDRSTRLEN];
    std::map<uint64_t, mod_flow_stats>::iterator it;
    mod_flow_stats stats;

    /* gain access to the flow record */
    bd_flow_record_t *flow_rec = (bd_flow_record_t *)flow->extension;

    /* gain access to the configuration structure */
    struct module_flow_statistics_flow *f = (struct module_flow_statistics_flow *)
        data;

    /* ensure lpi_module is not NULL */
    if (flow_rec->lpi_module != NULL) {
        /* check the protocol or category is a wanted one */
        if (f->c->protocol[flow_rec->lpi_module->protocol] ||
            f->c->category[flow_rec->lpi_module->category]) {

           /* get the stats data */
            it = f->flow_stats->find(flow_rec->flow_id);
            if (it == f->flow_stats->end()) {

            } else {
                stats = it->second;

                /* clear stats */
                it->second.in_bytes = 0;
                it->second.out_bytes = 0;
            }

            bd_result_set_t *res = bd_result_set_create(f->bigdata, "flow_statistics");
            bd_result_set_insert_uint(res, "flow_id", flow->id.get_id_num());
            bd_result_set_insert_tag(res, "protocol", lpi_print(flow_rec->lpi_module->protocol));
            bd_result_set_insert_tag(res, "category", lpi_print_category(bd_flow_get_category(flow)));
            bd_result_set_insert_tag(res, "type", "flow_interval");

            bd_result_set_insert_uint(res, "start_ts", bd_flow_get_start_time_milliseconds(flow));
            bd_result_set_insert_double(res, "duration", flow_rec->end_ts - flow_rec->start_ts);
            bd_result_set_insert_double(res, "ttfb", flow_rec->ttfb);

            bd_flow_get_source_ip_string(flow, ip_tmp, INET6_ADDRSTRLEN);
            bd_result_set_insert_ip_string(res, "source_ip", ip_tmp);
            bd_flow_get_destination_ip_string(flow, ip_tmp, INET6_ADDRSTRLEN);
            bd_result_set_insert_ip_string(res, "destination_ip", ip_tmp);

            bd_result_set_insert_int(res, "src_port", flow_rec->src_port);
            bd_result_set_insert_int(res, "dst_port", flow_rec->dst_port);

            bd_result_set_insert_uint(res, "in_bytes", stats.in_bytes);
            bd_result_set_insert_uint(res, "out_bytes", stats.out_bytes);
            bd_result_set_insert_uint(res, "in_bytes_total", flow_rec->in_bytes);
            bd_result_set_insert_uint(res, "out_bytes_total", flow_rec->out_bytes);

            /* include tls info if this is an encrypted flow if enabled */
            if (f->c->export_tls &&
                flow_rec->lpi_module->protocol == LPI_PROTO_SSL) {
                bd_result_set_insert_string(res, "client_ja3_md5",
                    bd_tls_get_client_ja3_md5(flow_rec));
                bd_result_set_insert_string(res, "server_ja3_md5",
                    bd_tls_get_server_ja3_md5(flow_rec));
            }

            bd_result_set_insert_timestamp(res, f->tick);

            bd_result_set_publish(f->bigdata, res, 0);
        }
    }

    return 1;
}

int module_flow_statistics_packet(bd_bigdata_t *bigdata, void *mls) {

    if (bigdata->flow == NULL) {
        return 0;
    }

    lpi_protocol_t protocol;
    lpi_category_t category;
    std::map<uint64_t, mod_flow_stats>::iterator it;
    mod_flow_stats_stor *storage;
    mod_flow_stats stats;
    uint64_t flow_id;

    protocol = bd_flow_get_protocol(bigdata->flow);
    category = bd_flow_get_category(bigdata->flow);
    storage = (mod_flow_stats_stor *)mls;

    /* only search for the flow record is its a category/protocol we
     * are interested in. */
    if (config->protocol[protocol] || config->category[category]) {

        if (bd_get_packet_direction(bigdata) == 0) {
            stats.in_bytes = 0;
            stats.out_bytes = trace_get_payload_length(bigdata->packet);
        } else {
            stats.in_bytes = trace_get_payload_length(bigdata->packet);
            stats.out_bytes = 0;
        }

        flow_id = bd_flow_get_id(bigdata->flow);
        it = storage->flow_stats->find(flow_id);
        if (it == storage->flow_stats->end()) {
            stats.in_bytes = 0;
            stats.out_bytes = 0;
            storage->flow_stats->insert({flow_id, stats});
        } else {
            it->second.in_bytes += stats.in_bytes;
            it->second.out_bytes += stats.out_bytes;

        }
    }

    return 0;
}

int module_flow_statistics_tick(bd_bigdata_t *bigdata, void *mls, uint64_t tick) {

    mod_flow_stats_stor *storage;

    storage = (mod_flow_stats_stor *)mls;

    struct module_flow_statistics_flow f;
    f.bigdata = bigdata;
    f.c = config;
    f.tick = tick;
    f.flow_stats = storage->flow_stats;

    FlowManager *fm = bd_flow_get_flowmanager(bigdata);

    if (fm->foreachFlow(module_flow_statistics_foreach_flow, &f) == -1) {
        logger(LOG_DEBUG, "Error applying foreach flow funcion. func. "
            "module_flow_statistics_tick()");
    }

    return 0;
}

int module_flow_statistics_protocol_updated(bd_bigdata_t *bigdata, void *mls, lpi_protocol_t oldproto,
    lpi_protocol_t newproto) {

    bd_flow_record_t *flow_rec;
    char ip_tmp[INET6_ADDRSTRLEN];
    struct timeval tv;

    flow_rec = bd_flow_get_record(bigdata->flow);

    // if the new protocol or category is set to output
    if (config->protocol[newproto] ||
        config->category[flow_rec->lpi_module->category]) {

        /* This is done here because the flowstart event does not yet
         * have the correct protocol with only the first packet
         */
        bd_result_set_t *res = bd_result_set_create(bigdata, "flow_statistics");
        bd_result_set_insert_uint(res, "flow_id", bigdata->flow->id.get_id_num());
        bd_result_set_insert_tag(res, "protocol", lpi_print(newproto));
        bd_result_set_insert_tag(res, "category", lpi_print_category(
            bd_flow_get_category(bigdata->flow)));
        bd_result_set_insert_tag(res, "type", "flow_start");

        bd_result_set_insert_uint(res, "start_ts",
           bd_flow_get_start_time_milliseconds(bigdata->flow));
        bd_result_set_insert_double(res, "duration", flow_rec->end_ts - flow_rec->start_ts);
        bd_result_set_insert_double(res, "ttfb", flow_rec->ttfb);

        bd_flow_get_source_ip_string(bigdata->flow, ip_tmp, INET6_ADDRSTRLEN);
        bd_result_set_insert_ip_string(res, "source_ip", ip_tmp);
        bd_flow_get_destination_ip_string(bigdata->flow, ip_tmp, INET6_ADDRSTRLEN);
        bd_result_set_insert_ip_string(res, "destination_ip", ip_tmp);

        bd_result_set_insert_int(res, "src_port", flow_rec->src_port);
        bd_result_set_insert_int(res, "dst_port", flow_rec->dst_port);

        bd_result_set_insert_uint(res, "in_bytes", flow_rec->in_bytes);
        bd_result_set_insert_uint(res, "out_bytes", flow_rec->out_bytes);
        bd_result_set_insert_uint(res, "in_bytes_total", flow_rec->in_bytes);
        bd_result_set_insert_uint(res, "out_bytes_total", flow_rec->out_bytes);

        /* include tls info if this is an encrypted flow if enabled */
        if (config->export_tls && newproto == LPI_PROTO_SSL) {

            bd_result_set_insert_string(res, "client_ja3_md5",
                bd_tls_get_client_ja3_md5(flow_rec));
            bd_result_set_insert_string(res, "server_ja3_md5",
                bd_tls_get_server_ja3_md5(flow_rec));
        }

        // set the timestamp for the result
        tv = trace_get_timeval(bigdata->packet);
        bd_result_set_insert_timestamp(res, tv.tv_sec);

        bd_result_set_publish(bigdata, res, 0);
    }

    return 0;
}

int module_flow_statistics_flowend(bd_bigdata_t *bigdata, void *mls, bd_flow_record_t *flow_record) {

    char ip_tmp[INET6_ADDRSTRLEN];
    std::map<uint64_t, mod_flow_stats>::iterator it;
    mod_flow_stats_stor *storage;
    mod_flow_stats stats;

    storage = (mod_flow_stats_stor *)mls;

    if(config->protocol[flow_record->lpi_module->protocol] ||
       config->protocol[flow_record->lpi_module->category] ||
       config->monitor_all) {

        /* get the stats data */
        it = storage->flow_stats->find(flow_record->flow_id);
        if (it == storage->flow_stats->end()) {
            /* something went wrong here but just populate stats with 0
             * to prevent a crash */
            stats.in_bytes = 0;
            stats.out_bytes = 0;
        } else {
            stats = it->second;
            /* remove this from the stats since the flow has ended */
            storage->flow_stats->erase(flow_record->flow_id);
        }

        bd_result_set_t *res = bd_result_set_create(bigdata, "flow_statistics");
        bd_result_set_insert_uint(res, "flow_id", bigdata->flow->id.get_id_num());
        bd_result_set_insert_tag(res, "protocol", lpi_print(bd_flow_get_protocol(bigdata->flow)));
        bd_result_set_insert_tag(res, "category", lpi_print_category(
            bd_flow_get_category(bigdata->flow)));
        bd_result_set_insert_tag(res, "type", "flow_end");

        bd_result_set_insert_uint(res, "start_ts",
            bd_flow_get_start_time_milliseconds(bigdata->flow));
        bd_result_set_insert_double(res, "duration", flow_record->end_ts - flow_record->start_ts);
        bd_result_set_insert_double(res, "ttfb", flow_record->ttfb);
        bd_result_set_insert_uint(res, "end_ts",
            bd_flow_get_end_time_milliseconds(bigdata->flow));

        bd_flow_get_source_ip_string(bigdata->flow, ip_tmp, INET6_ADDRSTRLEN);
        bd_result_set_insert_ip_string(res, "source_ip", ip_tmp);
        bd_flow_get_destination_ip_string(bigdata->flow, ip_tmp, INET6_ADDRSTRLEN);
        bd_result_set_insert_ip_string(res, "destination_ip", ip_tmp);


        bd_result_set_insert_int(res, "src_port", flow_record->src_port);
        bd_result_set_insert_int(res, "dst_port", flow_record->dst_port);

        bd_result_set_insert_uint(res, "in_bytes", stats.in_bytes);
        bd_result_set_insert_uint(res, "out_bytes", stats.out_bytes);
        bd_result_set_insert_uint(res, "in_bytes_total", flow_record->in_bytes);
        bd_result_set_insert_uint(res, "out_bytes_total", flow_record->out_bytes);

        /* include tls info if this is an encrypted flow if enabled */
        if (config->export_tls &&
            flow_record->lpi_module->protocol == LPI_PROTO_SSL) {

            bd_result_set_insert_string(res, "client_ja3_md5",
                bd_tls_get_client_ja3_md5(flow_record));
            bd_result_set_insert_string(res, "server_ja3_md5",
                bd_tls_get_server_ja3_md5(flow_record));
        }

        /* Makes most sense to insert the timestamp from when the flow ended here??
           Because the packet received in this function is not for the current flow */
        bd_result_set_insert_timestamp(res, flow_record->end_ts);

        bd_result_set_publish(bigdata, res, 0);
    }

    return 0;
}

int module_flow_statistics_stopping(void *tls, void *mls) {

    mod_flow_stats_stor *storage;

    storage = (mod_flow_stats_stor *)mls;

    delete(storage->flow_stats);
    free(storage);

    return 0;
}

/* define the configuration function */
int module_flow_statistics_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

    /* parse the plugins configuration from the configuration file. */
    int enter_level = *level;
    bool first_pass = 1;
    int i;

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

                        logger(LOG_INFO, "Flow Statistics Plugin Enabled");
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "export_tls") == 0) {
                    consume_event(parser, event, level);
                    if (strcmp((char *)event->data.scalar.value, "1") == 0 ||
                        strcmp((char *)event->data.scalar.value, "yes") == 0 ||
                        strcmp((char *)event->data.scalar.value, "true") == 0 ||
                        strcmp((char *)event->data.scalar.value, "t") == 0) {

                        config->export_tls = 1;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "output_interval") == 0) {
                    consume_event(parser, event, level);
                    config->output_interval = atoi((char *)event->data.scalar.value);
                    if (config->output_interval != 0) {
                        bd_add_tickrate_to_cb_set(config->callbacks, config->output_interval);
                    } else {
                        logger(LOG_WARNING, "Invalid output_interval value. "
                            "module_flow_statistics. Disabling module");
                        config->enabled = 0;
                    }
                    break;
                }
                if (strcmp((char *)event->data.scalar.value, "protocols") == 0) {
                    /* consume protocols event */
                    consume_event(parser, event, level);

                    /* must be a yaml_sequence_start_event or conf is malformed */
                    if (event->type != YAML_SEQUENCE_START_EVENT) {
                        logger(LOG_ERR, "Malformed configuration: Section flow_statistics/protocols");
                        exit(BD_MALFORMED_CONF);
                    }

                    // consume yaml_mapping_start event
                    consume_event(parser, event, level);

                    // for each protocol supplied
                    while (event->type != YAML_SEQUENCE_END_EVENT) {

                        // check if this option is ALL, if so enabled all protocols
                        if (strcmp("ALL", (char *)event->data.scalar.value) == 0) {
                            for (i = 0; i < LPI_PROTO_LAST; i++) {
                                config->protocol[i] = 1;
                            }
                            config->monitor_all = 1;
                            logger(LOG_INFO, "Flow statistics - Enabling ALL protocols");
                        }

                        /* only need to enable indidual protocols if all is not set */
                        if (!config->monitor_all) {
                            /* try to convert the protocol string supplied into a
                             * lpi_protocol_t. Enable the protocol if found */
                            lpi_protocol_t protocol;
                            protocol = lpi_get_protocol_by_name((char *)event->data.scalar.value);
                            if (protocol != LPI_PROTO_UNKNOWN) {
                                if (config->enabled) {
                                    logger(LOG_INFO, "Flow statistics - Enabling protocol: %s",
                                        (char *)event->data.scalar.value);
                                }
                                config->protocol[protocol] = 1;
                            } else {
                                if (config->enabled) {
                                    logger(LOG_WARNING, "Flow statistics - Could not find "
                                        "protocol: %s", (char *)event->data.scalar.value);
                                }
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
                if (strcmp((char *)event->data.scalar.value, "protocol_categories") == 0) {
                    /* consume protocols event */
                    consume_event(parser, event, level);

                    /* must be a yaml_sequence_start_event or conf is malformed */
                    if (event->type != YAML_SEQUENCE_START_EVENT) {
                        logger(LOG_ERR, "Malformed configuration: Section "
                            "flow_statistics/categories");
                        exit(BD_MALFORMED_CONF);
                    }

                    // consume yaml_mapping_start event
                    consume_event(parser, event, level);

                    // for each protocol supplied
                    while (event->type != YAML_SEQUENCE_END_EVENT) {

                        // check if this option is ALL, if so enabled all protocols
                        if (strcmp("ALL", (char *)event->data.scalar.value) == 0) {
                            for (i = 0; i < LPI_CATEGORY_LAST; i++) {
                                config->category[i] = 1;
                            }
                            config->monitor_all = 1;
                            logger(LOG_INFO, "Flow statistics - Enabling ALL categories");
                        }

                        /* Only need to enable seperate categories if all is not set */
                        if (!config->monitor_all) {
                            /* try to convert the category string supplied into a
                             * lpi_category_t. Enable the category if found */
                            lpi_category_t category;
                            category = lpi_get_category_by_name((char *)event->data.scalar.value);
                            if (category != LPI_CATEGORY_UNKNOWN) {
                                if (config->enabled) {
                                    logger(LOG_INFO, "Flow statistics - Enabling category: %s",
                                        (char *)event->data.scalar.value);
                                }
                                config->category[category] = 1;
                            } else {
                                if (config->enabled) {
                                    logger(LOG_WARNING, "Flow statistics - Could not find "
                                        "category: %s", (char *)event->data.scalar.value);
                                }
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

        bd_register_start_event(config->callbacks, (cb_start)
            module_flow_statistics_starting);
        bd_register_packet_event(config->callbacks, (cb_packet)
            module_flow_statistics_packet);
        config->callbacks->protocol_updated_cb = (cb_protocol_updated)
            module_flow_statistics_protocol_updated;
        config->callbacks->tick_cb = (cb_tick)module_flow_statistics_tick;
        config->callbacks->flowend_cb = (cb_flowend)module_flow_statistics_flowend;
        bd_register_stop_event(config->callbacks, (cb_stop)
            module_flow_statistics_stopping);
    }

    return 0;
}


/* define the initialisation function for the plugin, This is called by the application
 * core on startup */
int module_flow_statistics_init(bd_bigdata_t *bigdata) {

    int i;

    /* create storage for the plugins conf structure */
    config = (struct module_flow_statistics_config *)malloc(sizeof(struct
        module_flow_statistics_config));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_flow_statistics_init()");
        exit(BD_OUTOFMEMORY);
    }


    /* init the config structure */
    config->enabled = 0;
    config->output_interval = 0;
    config->monitor_all = 0;
    /* initialise all protocols to false */
    for (i = 0; i < LPI_PROTO_LAST; i++) {
        config->protocol[i] = 0;
    }
    /* initialise all categories to false */
    for (i = 0; i < LPI_CATEGORY_LAST; i++) {
        config->category[i] = 0;
    }
    config->export_tls = 0;

    /* create callback set used to map callback functions to each event */
    config->callbacks = bd_create_cb_set("flow_statistics");

    /* define a configuration function for the plugin */
    config->callbacks->config_cb = (cb_config)module_flow_statistics_config;

    /* register the callback set against the application core */
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}
