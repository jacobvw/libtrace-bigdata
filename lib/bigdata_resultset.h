#ifndef BIGDATA_RESULTSET_H
#define BIGDATA_RESULTSET_H

#include "bigdata.h"

#define RESULT_SET_INIT_SIZE 20
#define RESULT_SET_INC_SIZE 10

enum bd_record_type {
    BD_TYPE_STRING,
    BD_TYPE_FLOAT,
    BD_TYPE_DOUBLE,
    BD_TYPE_INT,
    BD_TYPE_BOOL,
    BD_TYPE_UINT,
    BD_TYPE_TAG
};
union bd_record_value {
    char *data_string;
    float data_float;
    double data_double;
    int64_t data_int;
    uint64_t data_uint;
    bool data_bool;
};
typedef struct bd_result {
    const char *key;
    enum bd_record_type type;
    union bd_record_value value;
} bd_result_t;
typedef struct bd_result_set {
    const char *module;
    bd_result_t *results;
    int num_results;
    int allocated_results;
    uint64_t timestamp;
} bd_result_set_t;

#endif
