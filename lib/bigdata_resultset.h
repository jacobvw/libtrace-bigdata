#ifndef BIGDATA_RESULTSET_H
#define BIGDATA_RESULTSET_H

#include "bigdata.h"

#define RESULT_SET_INIT_SIZE 20
#define RESULT_SET_INC_SIZE 10

#define JSON_BUF_LEN 2000
#define JSON_LINE_LEN 4000

/* ENUM to identify between a result to combine or a result to publish */
enum bd_result_type {
    BD_RESULT_COMBINE,
    BD_RESULT_PUBLISH
};

/* ENUM to identify the type of value stored within the result */
enum bd_record_type {
    BD_TYPE_STRING,
    BD_TYPE_FLOAT,
    BD_TYPE_DOUBLE,
    BD_TYPE_INT,
    BD_TYPE_BOOL,
    BD_TYPE_UINT,
    BD_TYPE_TAG
};

/* Union of values for each result */
union bd_record_value {
    char *data_string;
    float data_float;
    double data_double;
    int64_t data_int;
    uint64_t data_uint;
    bool data_bool;
};

/* Structure to hold each result */
typedef struct bd_result {
    char *key;
    enum bd_record_type type;
    union bd_record_value value;
} bd_result_t;

/* Structure to hold a set of results */
typedef struct bd_result_set {
    const char *module;
    bd_result_t *results;
    int num_results;
    int allocated_results;
    uint64_t timestamp;
    /* The free lock allows output plugins to prevent the application core
     * from free'ing the result. Used to when output plugins wish to batch
     * process results */
    int free_lock;
} bd_result_set_t;

/* Structure to hold a result set or opauqe structure and identify if
 * it needs to be combined or published */
typedef struct bd_result_set_wrapper {
    void *value;
    bd_result_type type;
    int module_id;
    uint64_t key;
} bd_result_set_wrap_t;

/* private functions */
int bd_result_set_insert(bd_result_set_t *result_set, char *key,
    bd_record_type dtype, bd_record_value value);


/* Create a result set.
 *
 * @param	bigdata - bigdata structure
 *		mod - the name of the plugin.
 * @returns	pointer to a result set structure on success.
 * 		NULL pointer on error.
 */
bd_result_set_t *bd_result_set_create(bd_bigdata_t *bigdata, const char *mod);

/* Inserts a string into a result set.
 *
 * @param	result_set - the result set.
 *		key - the key for the result.
 *		value - the result.
 * @returns	0 on success.
 *		-1 on error.
 */
int bd_result_set_insert_string(bd_result_set_t *result_set, char const *key,
    const char *value);

/* Inserts a float into a result set.
 *
 * @param       result_set - the result set.
 *              key - the key for the result.
 *              value - the result.
 * @returns     0 on success.
 *              -1 on error.
 */
int bd_result_set_insert_float(bd_result_set_t *result_set, char const *key,
    float value);

/* Inserts a double into a result set.
 *
 * @param       result_set - the result set.
 *              key - the key for the result.
 *              value - the result.
 * @returns     0 on success.
 *              -1 on error.
 */
int bd_result_set_insert_double(bd_result_set_t *result_set, char const *key,
    double value);

/* Inserts a int into a result set.
 *
 * @param       result_set - the result set.
 *              key - the key for the result.
 *              value - the result.
 * @returns     0 on success.
 *              -1 on error.
 */
int bd_result_set_insert_int(bd_result_set_t *result_set, char const *key,
    int64_t value);

/* Inserts a unsigned int into a result set.
 *
 * @param       result_set - the result set.
 *              key - the key for the result.
 *              value - the result.
 * @returns     0 on success.
 *              -1 on error.
 */
int bd_result_set_insert_uint(bd_result_set_t *result_set, char const *key,
    uint64_t value);

/* Inserts a boolean into a result set.
 *
 * @param       result_set - the result set.
 *              key - the key for the result.
 *              value - the result.
 * @returns     0 on success.
 *              -1 on error.
 */
int bd_result_set_insert_bool(bd_result_set_t *result_set, char const *key,
    bool value);

/* Sets the timestamp for the result set
 *
 * @param       result_set - the result set.
 *              timestamp - timestamp in seconds for the result.
 * @returns     0 on success.
 *              -1 on error.
 */
int bd_result_set_insert_timestamp(bd_result_set_t *result_set, uint64_t timestamp);

/* Inserts a string tag into a result set. This is used for metadata associated
 * with the result.
 *
 * @param       result_set - the result set.
 *              tag - the key for the result.
 *              value - the result.
 * @returns     0 on success.
 *              -1 on error.
 */
int bd_result_set_insert_tag(bd_result_set_t *result_set, char const *tag,
    const char *value);

/* Locks the result set to prevent the application core from free'ing it. This
 * then must be unlocked when finished with the result.
 *
 * @param	result_set - the result set.
 * @returns	0 on success.
 *		-1 on error.
 */
int bd_result_set_lock(bd_result_set_t *result_set);

/* Unlocks the result set to which was previously locked with bd_result_set_lock.
 * If no more locks are present on the result the result set will be free'd
 *
 * @param       result_set - the result set.
 * @returns     0 on success.
 *              -1 on error.
 */
int bd_result_set_unlock(bd_result_set_t *result_set);

/* Publishes a result set to any output plugins for exporting.
 *
 * @params	bigdata - bigdata structure.
 *		result - the result set.
 *		key - the key associated with the result.
 * @returns	0 on success.
 *		-1 on error.
 */
int bd_result_set_publish(bd_bigdata_t *bigdata, bd_result_set_t *result, uint64_t key);

/* Publishes a opaque partial result generated by a plugin to the plugins combining
 * function. This is generally a pointer to a plugins own defined structure and must be
 * free'd by the plugin once the result has been combined.
 *
 * @params	bigdata - bigdata structure.
 *		result - the result.
 *		key - the key associated with the result.
 *		module_id - the plugin ID for the plugin publishing the result.
 * @returns	0 on success.
 *		-1 on error.
 */
int bd_result_combine(bd_bigdata_t *bigdata, void *result, uint64_t key, int module_id);

/* free's the memory allocated by bd_result_set_create() for a result set.
 * Note: If the result set is published via bd_result_set_publish() the application
 * handles free'ing it up. Generally this function should not be called by any plugins.
 *
 * @params	result_set - the result set.
 * @returns	0 on success.
 *		-1 on error.
 */
int bd_result_set_free(bd_result_set_t *result_set);

/* free's the memory allocated by a result set wrapper. Generally this function
 * should not be called by any plugins.
 *
 * @params	r - the result set wrapper.
 * @returns	0 on success.
 *		-1 on error.
 */
int bd_result_set_wrap_free(bd_result_set_wrap_t *r);

/* Converts the result_set into its JSON string representation.
 *
 * @params	result_set - the result_set.
 * @returns	malloc'd JSON string which must be free'd when done with on success.
 *		NULL pointer on error.
 */
std::string bd_result_set_to_json_string(bd_result_set_t *result);

#endif
