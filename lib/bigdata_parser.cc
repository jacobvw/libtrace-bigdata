#include "bigdata.h"
#include "bigdata_parser.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

static bd_network_t *get_local_network(char *network_string) {

	char delim[] = "/";
        char buf[INET6_ADDRSTRLEN];

	/* Split the network address and mask portion of the string */
	char *address = strtok(network_string, delim);
	char *mask = strtok(NULL, delim);

        // create result structure
        bd_network_t *network = (bd_network_t *)malloc(sizeof(bd_network_t));
        if (network == NULL) {
            fprintf(stderr, "Unable to allocate memory. func get_local_network()\n");
            exit(BD_OUTOFMEMORY);
        }

        // try to determine if the address supplied is ipv4 or ipv6
        if (inet_pton(AF_INET, address, buf)) {
            // IPv4
            /* Check the subnet mask is valid */
            if(atoi(mask) == 0 || atoi(mask) > 32 || atoi(mask) < 0) {
                fprintf(stderr, "Invalid mask %s for network address %s\n",
                    mask, address);
                free(network);
                return NULL;
            }

            struct sockaddr_in *addr = (struct sockaddr_in *)&(network->address);
            struct sockaddr_in *msk = (struct sockaddr_in *)&(network->mask);

            // convert ip4 string to sockaddr
            inet_pton(AF_INET, address, &(addr->sin_addr));
            addr->sin_family = AF_INET;

            // convert ip4 mask to sockaddr
            uint32_t subnet_mask = 0xffffffff << (32 - atoi(mask));
            snprintf(buf, INET_ADDRSTRLEN, "%d.%d.%d.%d",
                (subnet_mask & 0xff000000) >> 24,
                (subnet_mask & 0x00ff0000) >> 16,
                (subnet_mask & 0x0000ff00) >> 8,
                (subnet_mask & 0x000000ff));
            inet_pton(AF_INET, buf, &(msk->sin_addr));
            msk->sin_family = AF_INET;

        } else if (inet_pton(AF_INET6, address, buf)) {
            // IPv6
            /* Check the subnet mask is valid */
            if(atoi(mask) == 0 || atoi(mask) > 128 || atoi(mask) < 0) {
                fprintf(stderr, "Invalid mask %s for network address %s\n",
                    mask, address);
                free(network);
                return NULL;
            }

            struct sockaddr_in6 *addr = (struct sockaddr_in6 *)&(network->address);
            struct sockaddr_in6 *msk = (struct sockaddr_in6 *)&(network->mask);

            // convert ipv6 string to sockaddr
            inet_pton(AF_INET6, address, &(addr->sin6_addr));
            addr->sin6_family = AF_INET6;

            // convert ip6 mask to sockaddr
            uint8_t mask_size = atoi(mask);
            uint8_t subnet_mask[16];
            for (int i = 0; i < 16; i++) {
                subnet_mask[i] = 0;
                if (mask_size >= 8) {
                    subnet_mask[i] = 0xff;
                    mask_size -= 8;
                } else if (mask_size > 0) {
                    subnet_mask[i] = 0xff << (8 - mask_size);
                    mask_size = 0;
                }
            }
            snprintf(buf, INET6_ADDRSTRLEN, "%02x%02x:%02x%02x:%02x%02x:%02x%02x"
                ":%02x%02x:%02x%02x:%02x%02x:%02x%02x",
                subnet_mask[0], subnet_mask[1], subnet_mask[2], subnet_mask[3],
                subnet_mask[4], subnet_mask[5], subnet_mask[6], subnet_mask[7],
                subnet_mask[8], subnet_mask[9], subnet_mask[10], subnet_mask[11],
                subnet_mask[12], subnet_mask[13], subnet_mask[14], subnet_mask[15]);
            inet_pton(AF_INET6, buf, &(msk->sin6_addr));
            msk->sin6_family = AF_INET6;

        } else {
            fprintf(stderr, "Address %s is not a valid IPv4 or IPv6 address\n", address);
            free(network);
            network = NULL;
        }

	return network;
}

void print_event(yaml_event_t *event, int *level) {
    switch(event->type) {
        case YAML_STREAM_START_EVENT: fprintf(stderr, "YAML_STREAM_START_EVENT %d\n", *level); break;
        case YAML_STREAM_END_EVENT: fprintf(stderr, "YAML_STREAM_END_EVENT %d\n", *level); break;
        case YAML_DOCUMENT_START_EVENT: fprintf(stderr, "YAML_DOCUMENT_START_EVENT %d\n", *level); break;
        case YAML_DOCUMENT_END_EVENT: fprintf(stderr, "YAML_DOCUMENT_END_EVENT %d\n", *level); break;
        case YAML_SEQUENCE_START_EVENT: fprintf(stderr, "YAML_SEQUENCE_START_EVENT %d\n", *level); break;
        case YAML_SEQUENCE_END_EVENT: fprintf(stderr, "YAML_SEQUENCE_END_EVENT %d\n", *level); break;
        case YAML_MAPPING_START_EVENT: fprintf(stderr, "YAML_MAPPING_START_EVENT %d\n", *level); break;
        case YAML_MAPPING_END_EVENT: fprintf(stderr, "YAML_MAPPING_END_EVENT %d\n", *level); break;
        case YAML_SCALAR_EVENT: fprintf(stderr, "YAML_SCALAR_EVENT %d\n", *level); break;
        case YAML_ALIAS_EVENT: fprintf(stderr, "YAML_ALIAS_EVENT %d\n", *level); break;
        case YAML_NO_EVENT: fprintf(stderr, "YAML_NO_EVENT %d\n", *level); break;
    }
}

static void update_level(yaml_event_t *event, int *level) {
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
        case YAML_NO_EVENT: break;
    }
}

int consume_event(yaml_parser_t *parser, yaml_event_t *event, int *level) {
    yaml_event_delete(event);
    if (!yaml_parser_parse(parser, event)) {
        printf("Parser error %d\n", parser->error);
        exit(EXIT_FAILURE);
    }
    update_level(event, level);
    return *level;
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
    if(!yaml_parser_initialize(&parser)) {
        fprintf(stderr, "Failed to initialize parser!\n");
        return NULL;
    }
    if(fd == NULL){
        fprintf(stderr, "Failed to open file!\n");
        return NULL;
    }

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

            case YAML_NO_EVENT: break;

            /* Data */
            case YAML_ALIAS_EVENT: consume_event(&parser, &event, &level); break;
            case YAML_SCALAR_EVENT:
                if (strcmp((char *)event.data.scalar.value, "hostname") == 0) {
                    consume_event(&parser, &event, &level);
                    // should now be a YAML_SCALAR_EVENT containing a hostname,
                    //  if not config is incorrect.
                    if (event.type != YAML_SCALAR_EVENT) {
                        fprintf(stderr, "Config error: Expected hostname\n");
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
                        fprintf(stderr, "Config error: Expected interface\n");
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
                        fprintf(stderr, "Config error: Expected number of threads\n");
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
                        fprintf(stderr, "Config error: Expected boolean after local_networks_"
                            "as_direction\n");
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
                        fprintf(stderr, "Config error: Expected network address/es after "
                            "local_networks.\n");
                        return NULL;
                    }
                    consume_event(&parser, &event, &level);
                    while (event.type == YAML_SCALAR_EVENT) {

                        bd_network_t *tmp_network = get_local_network(
                            (char *)event.data.scalar.value);

                        if (tmp_network != NULL) {
                            if (conf->local_subnets_count == 0) {
                                conf->local_subnets =
                                    (bd_network_t **)malloc(sizeof(bd_network_t *));
                            } else {
                                conf->local_subnets =
                                    (bd_network_t **)realloc(conf->local_subnets,
                                        (conf->local_subnets_count + 1) * sizeof(bd_network_t *));
                            }

                            conf->local_subnets[conf->local_subnets_count] = tmp_network;

                            conf->local_subnets_count++;
                        }

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
                        fprintf(stderr, "Config error: Expected boolean after "
                            "enable_bidirectional_hasher\n");
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
                        fprintf(stderr, "Config error: Expected boolean after "
                            "debug\n");
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
                    strcmp((char *)event.data.scalar.value, "where") == 0 ||
                    strcmp((char *)event.data.scalar.value, "filter") == 0) {

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
                                            exit(BD_INVALID_CONFIG);
                                        }

                                        // module has been found so break out of the for loop
                                        break;
                                    }
                                }
                            }
                        }

                        /* Module not found, bypassing its configuration */
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
