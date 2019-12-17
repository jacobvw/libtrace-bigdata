#include "module_http.h"

#include <unordered_map>

struct module_http_conf {
    bd_cb_set *callbacks;
    bool enabled;
};
static struct module_http_conf *config;

typedef struct module_http_header {
    char *name;
    char *value;
} mod_http_header;

typedef struct module_http_requests {
    char *method;
    char *path;
    int version;
    mod_http_header headers[100];
    size_t num_headers;
} mod_http_req;

typedef struct module_http_storage {
    std::unordered_map<uint64_t, mod_http_req *> *requests;
} mod_http_stor;

void *module_http_starting(void *tls) {

    mod_http_stor *storage = (mod_http_stor *)malloc(sizeof(
        mod_http_stor));
    if (storage == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_http_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    storage->requests = new std::unordered_map<uint64_t, mod_http_req *>;

    return storage;
}

int module_http_packet(bd_bigdata_t *bigdata, void *mls) {

    uint16_t ethertype;
    uint8_t proto;
    uint32_t remaining;
    void *layer3;
    void *payload;
    char *buf;
    mod_http_req *request;
    mod_http_stor *storage;
    uint64_t flow_id;

    storage = (mod_http_stor *)mls;
    payload = NULL;
    flow_id = bd_flow_get_id(bigdata->flow);

    layer3 = trace_get_layer3(bigdata->packet, &ethertype, &remaining);
    /* got layer3? */
    if (layer3 == NULL) {
        return 0;
    }

    if (ethertype == TRACE_ETHERTYPE_IP) {
        payload = trace_get_payload_from_ip((libtrace_ip_t *)layer3, &proto,
            &remaining);
    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        payload = trace_get_payload_from_ip6((libtrace_ip6_t *)layer3, &proto,
            &remaining);
    }

    /* got payload? */
    if (payload == NULL) {
        return 0;
    }

    /* get tcp payload */
    payload = trace_get_payload_from_tcp((libtrace_tcp_t *)payload, &remaining);

    /* got tcp? */
    if (payload == NULL) { return 0; }

    buf = (char *)payload;

    int minor_version;
    size_t prevlen = 0, num_headers = 100;
    struct phr_header headers[100];

    /* request types */
    if (memcmp(buf, "GET", 3) == 0 ||
        memcmp(buf, "HEAD", 4) == 0 ||
        memcmp(buf, "POST", 4) == 0 ||
        memcmp(buf, "PUT", 3) == 0 ||
        memcmp(buf, "DELETE", 6) == 0 ||
        memcmp(buf, "CONNECT", 7) == 0 ||
        memcmp(buf, "OPTIONS", 7) == 0 ||
        memcmp(buf, "TRACE", 5) == 0 ||
        memcmp(buf, "PATCH", 5) == 0) {

        int request_size;
        const char *method, *path;
        size_t method_len, path_len;

        request_size = phr_parse_request(buf, remaining, &method, &method_len, &path,
            &path_len, &minor_version, headers, &num_headers, prevlen);

        if (request_size) {

            /* create the request structure */
            request = (mod_http_req *)malloc(sizeof(mod_http_req));
            if (request == NULL) {
                fprintf(stderr, "Unable to allocate memory. func. module_http_packet()\n");
                exit(BD_OUTOFMEMORY);
            }
            request->method = strndup(method, method_len);
            request->path = strndup(path, path_len);
            request->version = minor_version;
            /* copy over the headers */
            for (int i = 0; i != num_headers; ++i) {
                request->headers[i].name = strndup(headers[i].name, (int)headers[i].name_len);
                request->headers[i].value = strndup(headers[i].value, (int)headers[i].value_len);
            }
            request->num_headers = num_headers;

            /* insert the request into the request map with the flow id as the key */
            storage->requests->insert({flow_id, request});
        }
    }

    /* response types */
    if (memcmp(buf, "HTTP/", 5) == 0) {
        int response_size, status;
        const char *msg;
        size_t msg_len;

        /* lookup request for this flow id */
        auto search = storage->requests->find(flow_id);
        if (search != storage->requests->end()) {

            /* set request to original request */
            request = (mod_http_req *)search->second;

            /* parse response */
            response_size = phr_parse_response(buf, remaining, &minor_version, &status,
                &msg, &msg_len, headers, &num_headers, prevlen);


            /* create a result set */
            //bd_result_set_t *result_set = bd_result_set_create(bigdata, "http");

            //bd_result_set_insert_tag(result_set, "http_method", request->method);
            //bd_result_set_insert_string(result_set, "http_path", request->path);
            //bd_result_set_insert_int(result_set, "http_response_code", status);

            fprintf(stderr, "got %s request to %s\n", request->method, request->path);
            for (int i = 0; i != request->num_headers; ++i) {
                printf("%s: %s\n", request->headers[i].name, request->headers[i].value);
                free(request->headers[i].name);
                free(request->headers[i].value);
            }



            /* remove from request from map */
            storage->requests->erase(flow_id);
            free(request->method);
            free(request->path);
            free(request);
        }
    }
}

int module_http_stopping(void *tls, void *mls) {

}

int module_http_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

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
                consume_event(parser, event, level);
                break;
            default:
                consume_event(parser, event, level);
                break;
        }
    }

    if (config->enabled) {
        bd_register_start_event(config->callbacks, (cb_start)module_http_starting);
        bd_register_packet_event(config->callbacks, (cb_packet)module_http_packet);
        bd_add_filter_to_cb_set(config->callbacks, "port 80");
        bd_register_stop_event(config->callbacks, (cb_stop)module_http_stopping);

        fprintf(stderr, "HTTP plugin enabled\n");
    }
}

int module_http_init(bd_bigdata_t *bigdata) {

    config = (struct module_http_conf *)malloc(sizeof(
        struct module_http_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_http_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    config->callbacks = bd_create_cb_set("http");
    config->enabled = 0;

    /* register for the config event */
    bd_register_config_event(config->callbacks, (cb_config)module_http_config);

    /* register the callback set */
    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}
