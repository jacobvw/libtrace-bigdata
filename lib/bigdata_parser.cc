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

void consume_event(yaml_parser_t *parser, yaml_event_t *event) {
    yaml_event_delete(event);
    if (!yaml_parser_parse(parser, event)) {
        printf("Parser error %d\n", parser->error);
        exit(EXIT_FAILURE);
    }
}

bd_conf_t *parse_config(char *filename, bd_global_t *g_data) {
    FILE *fd;
    yaml_parser_t parser;
    yaml_event_t event;

    bd_conf_t *conf = (bd_conf_t *)malloc(sizeof(bd_conf_t));
    conf->interface = NULL;
    conf->local_networks_as_direction = 0;
    conf->local_subnets = NULL;
    conf->local_subnets_count = 0;

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

    /* START new code */
    do {
        if (!yaml_parser_parse(&parser, &event)) {
            printf("Parser error %d\n", parser.error);
            exit(EXIT_FAILURE);
        }

        switch(event.type) {
            case YAML_NO_EVENT: puts("No event!"); break;

            /* Stream start/end */
            case YAML_STREAM_START_EVENT:   puts("STREAM START");          break;
            case YAML_STREAM_END_EVENT:     puts("STREAM END");            break;

            /* Block delimeters */
            case YAML_DOCUMENT_START_EVENT: puts("<b>Start Document</b>"); break;
            case YAML_DOCUMENT_END_EVENT:   puts("<b>End Document</b>");   break;
            case YAML_SEQUENCE_START_EVENT: puts("<b>Start Sequence</b>"); break;
            case YAML_SEQUENCE_END_EVENT:   puts("<b>End Sequence</b>");   break;
            case YAML_MAPPING_START_EVENT:  puts("<b>Start Mapping</b>");  break;
            case YAML_MAPPING_END_EVENT:    puts("<b>End Mapping</b>");    break;

            /* Data */
            case YAML_ALIAS_EVENT:
                printf("Got alias (anchor %s)\n", event.data.alias.anchor);
                break;
            case YAML_SCALAR_EVENT:
                if (strcmp((char *)event.data.scalar.value, "interface") == 0) {
                    // consume the first event which contains the value interfaces
                    consume_event(&parser, &event);
                    // should now be a YAML_SCALAR_EVENT containing a interface name,
                    //  if not config is incorrect.
                    if (event.type != YAML_SCALAR_EVENT) {
                        return NULL;
                    }
                    conf->interface = strdup((char *)event.data.scalar.value);
                    // consume the event
                    consume_event(&parser, &event);
                    break;
                }

                if (strcmp((char *)event.data.scalar.value, "local_networks_as_direction") == 0) {
                    // consume the first event which contains the key
                    consume_event(&parser, &event);
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
                    consume_event(&parser, &event);
                    if (event.type != YAML_SEQUENCE_START_EVENT) {
                        return NULL;
                    }
                    consume_event(&parser, &event);
                    while (event.type == YAML_SCALAR_EVENT) {
                        if (conf->local_subnets_count == 0) {
                            conf->local_subnets =
                                (bd_network_t **)malloc(sizeof(bd_network_t *));
                        } else {
                            conf->local_subnets =
                                (bd_network_t **)calloc(conf->local_subnets_count,
                                    sizeof(bd_network_t *));
                        }
                        conf->local_subnets[conf->local_subnets_count] =
                            get_local_network((char *)event.data.scalar.value);

                        conf->local_subnets_count++;
                        consume_event(&parser, &event);
                    }
                    break;
                }

                // capture/output modules config
                if (strcmp((char *)event.data.scalar.value, "foreach") == 0 ||
                    strcmp((char *)event.data.scalar.value, "where") == 0) {

                    // consume event, will be either foreach or where
                    consume_event(&parser, &event);

                    // if the next event is not a mapping event something is wrong
                    if (event.type != YAML_MAPPING_START_EVENT) { return NULL; }
                    // consume the mapping event
                    consume_event(&parser, &event);

                    // should now be a YAML_SCALAR_EVENT containing a module name,
                    // if not something is wrong.
                    if (event.type != YAML_SCALAR_EVENT) { return NULL; }

                    // iterate over callbacks triggering config events
                    bd_cb_set *cbs = g_data->callbacks;
                    for (; cbs != NULL; cbs = cbs->next) {
                        if (cbs->config_cb != NULL) {
                            if (strcmp((char *)event.data.scalar.value, cbs->name) == 0) {
                                // consume the first event which is the module name
                                consume_event(&parser, &event);

                                // hand the parser and event to required module.
                                // the module must ensure it only consumes its own events.
                                cbs->config_cb(&parser, &event);
                            }
                        }
                    }
                    break;
                }

                printf("Got scalar (value %s)\n", event.data.scalar.value);
                break;
        }

        if (event.type != YAML_STREAM_END_EVENT) { yaml_event_delete(&event); }
    } while(event.type != YAML_STREAM_END_EVENT);

    /* Cleanup */
    yaml_parser_delete(&parser);
    fclose(fd);

    return conf;
}
