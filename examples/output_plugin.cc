#include "bigdata.h"

struct module_MODULENAME_config {
    bd_cb_set *callbacks;
    bool enabled;
    /* define any additional configuration options needed for the plugin */
};
static struct module_MODULENAME_config *config;

struct module_MODULENAME_storage {
    /* define any storage needed for the plugin */
};

/* this function is used to allocate any storage needed by the plugin */
void *module_MODULENAME_reporter_starting(void *tls) {
    struct module_MODULENAME_storage *stor = (struct module_MODULENAME_storage *)
        malloc(sizeof(struct module_MODULENAME_storage));

    /* initialise any module storage if using a REST API this could be initialising
     * curl
     */

    return stor;
}

/* this function will be passed result set structures which are ready for output.
 * Each output plugin needs to convert the generic result structure into their own
 * native format for storage
 */
int module_MODULENAME_post(bd_bigdata_t *bigdata, void *mls, bd_result_set *result) {

    /* gain access to module storage */
    struct module_MODULENAME_storage *stor = (struct module_MODULENAME_storage *)mls;

    /* This is where you convert the result set into the output plugin native
     * format. Check the InfluxDB or Kafka plugins for some examples of working
     * solutions
     */

    /* now execute the converted result on the output plugins storage/output interface */

    /* return 0 is all went well */
    return 0;
}

/* this function is used to free any storage used by the plugin */
void *module_MODULENAME_reporter_stopping(void *tls, void *mls) {

    /* gain access to the module storage */
    struct module_MODULENAME_storage *stor = (struct module_MODULENAME_storage *)mls;

    /* free memory allocated */
    free(stor);
}

/* Used for any plugin configuration parsing from the configuration YAML file */
int module_MODULENAME_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

    int enter_level = *level;
    bool first_pass = 1;

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
                    }
                    break;
                }
                /* This is where you can read custom configuration data which may
                 * include hostname, username, password etc for the storage application
                 */
            default:
                consume_event(parser, event, level);
                break;

        }
    }

    if (config->enabled) {
        // Because this is a output plugin we register callbacks against
        // the reporter thread.
        config->callbacks->reporter_start_cb =(cb_reporter_start)
            module_MODULENAME_reporter_starting;
        config->callbacks->reporter_output_cb = (cb_reporter_output)
            module_MODULENAME_post;
        config->callbacks->reporter_stop_cb = (cb_reporter_stop)
            module_MODULENAME_reporter_stopping;

        fprintf(stdout, "MODULENAME Plugin Enabled\n");
    }
}

/* init function called by the application core when starting up */
int module_MODULENAME_init() {

    config = (struct module_MODULENAME_confif *)malloc(sizeof(
        struct module_MODULENAME_config));

    /* init config structure */
    config->enabled = 0;

    // create callback set
    config->callbacks = bd_create_cb_set("MODULENAME");

    // define config callback
    config->callbacks->config_cb = (cb_config)module_MODULENAME_config;

    // register the callback set
    bd_register_cb_set(config->callbacks);
}
