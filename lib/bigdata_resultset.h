#ifndef BIGDATA_RESULTSET_H
#define BIGDATA_RESULTSET_H

#include "bigdata.h"

#define RESULT_SET_INIT_SIZE 20
#define RESULT_SET_INC_SIZE 10

enum bd_result_type {
    BD_RESULT_COMBINE,
    BD_RESULT_PUBLISH
};

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

typedef struct bd_result_set_wrapper {
    void *value;
    bd_result_type type;
    int module_id;
    uint64_t key;
} bd_result_set_wrap_t;

/* output result set prototypes */
bd_result_set_t *bd_result_set_create(const char *mod);

int bd_result_set_insert(bd_result_set_t *result_set, const char *key,
    bd_record_type dtype, bd_record_value value);

int bd_result_set_insert_string(bd_result_set_t *result_set, const char *key,
    const char *value);

int bd_result_set_insert_float(bd_result_set_t *result_set, const char *key,
    float value);

int bd_result_set_insert_double(bd_result_set_t *result_set, const char *key,
    double value);

int bd_result_set_insert_int(bd_result_set_t *result_set, const char *key,
    int64_t value);

int bd_result_set_insert_uint(bd_result_set_t *result_set, const char *key,
    uint64_t value);

int bd_result_set_insert_bool(bd_result_set_t *result_set, const char *key,
    bool value);

int bd_result_set_insert_timestamp(bd_result_set_t *result_set, uint64_t timestamp);

int bd_result_set_insert_tag(bd_result_set_t *result_set, const char *tag,
    const char *value);

int bd_result_set_publish(bd_bigdata_t *bigdata, bd_result_set_t *result, uint64_t key);

int bd_result_combine(bd_bigdata_t *bigdata, void *result, uint64_t key, int module_id);

int bd_result_set_free(bd_result_set_t *result_set);

int bd_result_set_wrap_free(bd_result_set_wrap_t *r);

#endif
