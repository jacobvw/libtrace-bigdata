#include "bigdata.h"
#include "bigdata_parser.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

bd_network_t *get_local_network(char *network_string) {

	char delim[] = "/";
	/* Split the network address and mask portion of the string */
	char *network = strtok(network_string, delim);
	char *mask = strtok(NULL, delim);

	/* Check the subnet mask is valid */
	if(atoi(mask) == 0 || atoi(mask) > 32 || atoi(mask) < 0) {
		return NULL;
        }

        // create result structure
        bd_network_t *local = (bd_network_t *)malloc(sizeof(bd_network_t));
        if (local == NULL) {
            fprintf(stderr, "Unable to allocate memory. func get_local_network()\n");
            exit(BD_OUTOFMEMORY);
        }

        /* right shift so netmask is in network byte order */
        local->mask = 0xffffffff << (32 - atoi(mask));

        struct in_addr addr;
        /* Convert address string into uint32_t and check its valid */
        if(inet_aton(network, &addr) == 0) {
                free(local);
        	return NULL;
        }
        /* Ensure its saved in network byte order */
        local->network = htonl(addr.s_addr);

	return local;
}

void update_level(yaml_event_t *event, int *level) {
    switch(event->type) {
        case YAML_STREAM_START_EVENT: *level += 1; break;
        case YAML_STREAM_END_EVENT: *level -= 1; break;
        case YAML_DOCUMENT_START_EVENT: *level += 1; break;
        case YAML_DOCUMENT_END_EVENT: *level -= 1; break;
        case YAML_SEQUENCE_START_EVENT: *level += 1; break;
        case YAML_SEQUENCE_END_EVENT: *level -= 1; break;
        case YAML_MAPPING_START_EVENT: *level += 1; break;
        case YAML_MAPPING_END_EVENT: *level -= 1; break;
        case YAML_SCALAR_EVENT: break;
        case YAML_ALIAS_EVENT: break;
    }
}

void consume_event(yaml_parser_t *parser, yaml_event_t *event, int *level) {
    yaml_event_delete(event);
    if (!yaml_parser_parse(parser, event)) {
        printf("Parser error %d\n", parser->error);
        exit(EXIT_FAILURE);
    }
    update_level(event, level);
}

bd_conf_t *parse_config(char *filename, bd_global_t *g_data) {
    FILE *fd = NULL;
    yaml_parser_t parser;
    yaml_event_t event;

    bd_conf_t *conf = (bd_conf_t *)malloc(sizeof(bd_conf_t));
    conf->interface = NULL;
    conf->processing_threads = 0;
    conf->local_networks_as_direction = 0;
    conf->local_subnets = NULL;
    conf->local_subnets_count = 0;
    conf->enable_bidirectional_hasher = 1;
    conf->debug = 0;

    int level = 0;

    // try open the config file1
    if ((fd = fopen(filename, "r")) == NULL) {
        fprintf(stderr, "Failed to open config file %s\n", filename);
	return NULL;
    }

    /* Initialize parser */
    if(!yaml_parser_initialize(&parser))
        fputs("Failed to initialize parser!\n", stderr);
    if(fd == NULL)
        fputs("Failed to open file!\n", stderr);

    /* Set input file */
    yaml_parser_set_input_file(&parser, fd);

    // get the first event
    if (!yaml_parser_parse(&parser, &event)) {
        printf("Parser error %d\n", parser.error);
        exit(EXIT_FAILURE);
    }
    // update conf depth level
    update_level(&event, &level);

    /* START new code */
    do {

        switch(event.type) {

            /* Stream start/end */
            case YAML_STREAM_START_EVENT: consume_event(&parser, &event, &level); break;
            case YAML_STREAM_END_EVENT: break;

            /* Block delimeters */
            case YAML_DOCUMENT_START_EVENT: consume_event(&parser, &event, &level); break;
            case YAML_DOCUMENT_END_EVENT: consume_event(&parser, &event, &level); break;
            case YAML_SEQUENCE_START_EVENT: consume_event(&parser, &event, &level); break;
            case YAML_SEQUENCE_END_EVENT: consume_event(&parser, &event, &level); break;
            case YAML_MAPPING_START_EVENT: consume_event(&parser, &event, &level); break;
            case YAML_MAPPING_END_EVENT: consume_event(&parser, &event, &level); break;

            /* Data */
            case YAML_ALIAS_EVENT: consume_event(&parser, &event, &level); break;
            case YAML_SCALAR_EVENT:
                if (strcmp((char *)event.data.scalar.value, "hostname") == 0) {
                    consume_event(&parser, &event, &level);
                    // should now be a YAML_SCALAR_EVENT containing a hostname,
                    //  if not config is incorrect.
                    if (event.type != YAML_SCALAR_EVENT) {
                        return NULL;
                    }
                    conf->hostname = strdup((char *)event.data.scalar.value);
                    // consume the event
                    consume_event(&parser, &event, &level);
                    break;
                }
                if (strcmp((char *)event.data.scalar.value, "interface") == 0) {
                    // consume the first event which contains the value interfaces
                    consume_event(&parser, &event, &level);
                    // should now be a YAML_SCALAR_EVENT containing a interface name,
                    //  if not config is incorrect.
                    if (event.type != YAML_SCALAR_EVENT) {
                        return NULL;
                    }
                    conf->interface = strdup((char *)event.data.scalar.value);
                    // consume the event
                    consume_event(&parser, &event, &level);
                    break;
                }

                if (strcmp((char *)event.data.scalar.value, "threads") == 0) {
                    // consume the first event which contains the value interfaces
                    consume_event(&parser, &event, &level);
                    // should now be a YAML_SCALAR_EVENT containing a interface name,
                    //  if not config is incorrect.
                    if (event.type != YAML_SCALAR_EVENT) {
                        return NULL;
                    }
                    conf->processing_threads = atoi((char *)event.data.scalar.value);
                    // consume the event
                    consume_event(&parser, &event, &level);
                    break;
                }

                if (strcmp((char *)event.data.scalar.value, "local_networks_as_direction") == 0) {
                    // consume the first event which contains the key
                    consume_event(&parser, &event, &level);
                    if (event.type != YAML_SCALAR_EVENT) {
                        return NULL;
                    }
                    if (strcmp((char *)event.data.scalar.value, "1") == 0 ||
                        strcmp((char *)event.data.scalar.value, "true") == 0 ||
                        strcmp((char *)event.data.scalar.value, "yes") == 0) {

                        conf->local_networks_as_direction = 1;
                    } else {
                        conf->local_networks_as_direction = 0;
                    }
                    break;
                }

                if (strcmp((char *)event.data.scalar.value, "local_networks") == 0) {
                    consume_event(&parser, &event, &level);
                    if (event.type != YAML_SEQUENCE_START_EVENT) {
                        return NULL;
                    }
                    consume_event(&parser, &event, &level);
                    while (event.type == YAML_SCALAR_EVENT) {
                        if (conf->local_subnets_count == 0) {
                            conf->local_subnets =
                                (bd_network_t **)malloc(sizeof(bd_network_t *));
                        } else {
                            conf->local_subnets =
                                (bd_network_t **)realloc(conf->local_subnets,
                                    (conf->local_subnets_count + 1) * sizeof(bd_network_t *));
                        }
                        conf->local_subnets[conf->local_subnets_count] =
                            get_local_network((char *)event.data.scalar.value);

                        conf->local_subnets_count++;
                        consume_event(&parser, &event, &level);
                    }
                    break;
                }

                if (strcmp((char *)event.data.scalar.value, "enable_bidirectional_hasher") == 0) {
                    // consume the first event which contains the value enable_bidirectional_hasher
                    consume_event(&parser, &event, &level);
                    // should now be a YAML_SCALAR_EVENT,
                    //  if not config is incorrect.
                    if (event.type != YAML_SCALAR_EVENT) {
                        return NULL;
                    }
                    if (strcmp((char *)event.data.scalar.value, "1") == 0 ||
                        strcmp((char *)event.data.scalar.value, "true") == 0 ||
                        strcmp((char *)event.data.scalar.value, "yes") == 0) {

                        conf->enable_bidirectional_hasher = 1;
                    } else {
                        conf->enable_bidirectional_hasher = 0;
                    }
                    // consume the event
                    consume_event(&parser, &event, &level);
                    break;
                }

                if (strcmp((char *)event.data.scalar.value, "debug") == 0) {
                    // consume the first event which contains the value debug
                    consume_event(&parser, &event, &level);
                    // should now be a YAML_SCALAR_EVENT,
                    //  if not config is incorrect.
                    if (event.type != YAML_SCALAR_EVENT) {
                        return NULL;
                    }
                    if (strcmp((char *)event.data.scalar.value, "1") == 0 ||
                        strcmp((char *)event.data.scalar.value, "true") == 0 ||
                        strcmp((char *)event.data.scalar.value, "yes") == 0) {

                        conf->debug = 1;
                    } else {
                        conf->debug = 0;
                    }
                    // consume the event
                    consume_event(&parser, &event, &level);
                    break;
                }

                // capture/output modules config
                if (strcmp((char *)event.data.scalar.value, "foreach") == 0 ||
                    strcmp((char *)event.data.scalar.value, "where") == 0) {

                    int enter_level = level;
                    bool first_pass = 1;
                    // consume event, will be either foreach or where
                    consume_event(&parser, &event, &level);

                    while (level != enter_level || first_pass) {
                        first_pass = 0;
                        bool found_module = 0;


                        if (event.type == YAML_SCALAR_EVENT) {
                            // iterate over callbacks triggering config events
                            bd_cb_set *cbs = g_data->callbacks;
                            for (; cbs != NULL; cbs = cbs->next) {
                                if (cbs->config_cb != NULL) {
                                    if (strcmp((char *)event.data.scalar.value, cbs->name) == 0) {
                                        found_module = 1;

                                        // hand the parser and event to required module.
                                        // the module must ensure it only consumes its own events.
                                        int mod_enter_level = level;
                                        cbs->config_cb(&parser, &event, &level);
                                        if (mod_enter_level != level) {
                                            fprintf(stderr, "Module %s did not consume all its "
                                                "events\n", cbs->name);
                                            exit(0);
                                        }

                                        // module has been found so break out of the for loop
                                        break;
                                    }
                                }
                            }
                        }

                        if (!found_module) {
                            consume_event(&parser, &event, &level);
                        }
                    }

                    break;
                }

                // consume the event if it does not match anything defined
                consume_event(&parser, &event, &level);
                break;
            }

    } while(event.type != YAML_STREAM_END_EVENT);

    /* Cleanup */
    yaml_parser_delete(&parser);
    fclose(fd);

    return conf;
}
