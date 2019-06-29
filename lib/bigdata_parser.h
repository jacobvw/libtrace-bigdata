#ifndef BIGDATA_PARSER_H
#define BIGDATA_PARSER_H

#include "bigdata.h"

bd_conf_t *parse_config(char *filename, bd_global_t *g_data);
void consume_event(yaml_parser_t *parser, yaml_event_t *event);

#endif
