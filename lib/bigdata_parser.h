#ifndef BIGDATA_PARSER_H
#define BIGDATA_PARSER_H

#include "bigdata.h"

/* Parses and applies the given configuration file.
 *
 * @params	filename - the path/filename for the configuration file.
 *		g_data - pointer to the global structure.
 * @returns	pointer to the global configuration structure.
 */
bd_conf_t *parse_config(char *filename, bd_global_t *g_data);

/* Consume a yaml event and prepare the next one for processing.
 *
 * @params	parser - pointer to the yaml parser.
 * 		event - pointer to the yaml event.
 *		level - pointer to the current indentaion level.
 * @returns	the current indentation level on success.
 *		application exits with BD_YAML_ERROR on error.
 */
int consume_event(yaml_parser_t *parser, yaml_event_t *event, int *level);

/* Print the current yaml event type and indentation level.
 *
 * @params	event - pointer to the yaml event;
 *		level - pointer to the current indentation level.
 */
void print_event(yaml_event_t *event, int *level);

#endif
