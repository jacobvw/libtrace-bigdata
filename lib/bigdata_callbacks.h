#ifndef BIGDATA_CALLBACKS_H
#define BIGDATA_CALLBACKS_H

#include "bigdata.h"

int bd_callback_trigger_output(bd_bigdata_t *bigdata, bd_result_set_t *result);
int bd_callback_trigger_combiner(bd_bigdata_t *bigdata, bd_result_set_wrap_t *res);
int bd_callback_trigger_protocol(bd_bigdata_t *bigdata, lpi_protocol_t protocol);

int bd_register_protocol_event(bd_cb_set *cbset, cb_protocol callback, lpi_protocol_t protocol);

#endif
