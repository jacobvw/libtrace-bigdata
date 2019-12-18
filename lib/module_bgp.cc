#include "module_bgp.h"

/* https://tools.ietf.org/html/rfc4271#section-4 */

#define MODULE_BGP_TYPE_OPEN 0x01
#define MODULE_BGP_TYPE_UPDATE 0x02
#define MODULE_BGP_TYPE_NOTIFICATION 0x03
#define MOUDLE_BGP_TYPE_KEEPALIVE 0x04
#define MODULE_BGP_TYPE_OPEN_CONFIRM 0x05

#define MODULE_BGP_LINK_TYPE_INTERNAL 0x00
#define MODULE_BGP_LINK_TYPE_UP 0x01
#define MODULE_BGP_LINK_TYPE_DOWN 0x02
#define MODULE_BGP_LINK_TYPE_HLINK 0x03

#define MODULE_BGP_UPDATE_DIRECTION_UP 0x01
#define MODULE_BGP_UPDATE_DIRECTION_DOWN 0x02
#define MODULE_BGP_UPDATE_DIRECTION_HLINK 0x03
#define MODULE_BGP_UPDATE_DIRECTION_EGPLINK 0x04
#define MODULE_BGP_UPDATE_DIRECTION_INCOMPLETE 0x05

struct module_bgp_conf {
    bd_cb_set *callbacks;
    bool enabled;
};
static struct module_bgp_conf *config;

/* note: open and keepalive messages are the header (below) without any data */
struct module_bgp_header {
    uint8_t marker[16];     /* syncronisation marker, should be filled with 1's */
    uint16_t length;        /* length of entire bgp packet */
    uint8_t type;           /* type of BGP message, OPEN, UPDATE, NOTIFICATION etc */
} PACKED;

struct module_bgp_open {
    uint8_t version;
    uint16_t autonomous_system;
    uint16_t hold_time;
    uint32_t bgp_identifier;
    uint8_t opt_len;
    /* varible length authentication data */
} PACKED;
struct module_bgp_open_opt {
    uint8_t param_type;
    uint8_t param_len;
} PACKED;

struct module_bgp_update {
    uint16_t withdrawn_routes;
} PACKED;

struct module_bgp_notification {
    uint16_t opcode;
} PACKED;


int module_bgp_packet(bd_bigdata_t *bigdata, void *mls) {

    void *layer3;
    char *payload, *pos;
    uint8_t proto;
    uint16_t ethertype;
    uint32_t remaining;

    struct module_bgp_header *bgp_header;

    payload = NULL;
    layer3 = trace_get_layer3(bigdata->packet, &ethertype, &remaining);
    if (layer3 == NULL) {
        return 0;
    }

    /* get either ip or ipv6 payload */
    if (ethertype == TRACE_ETHERTYPE_IP) {
        payload = (char *)trace_get_payload_from_ip((libtrace_ip_t *)layer3, &proto,
            &remaining);
    } else if (ethertype == TRACE_ETHERTYPE_IPV6) {
        payload = (char *)trace_get_payload_from_ip6((libtrace_ip6_t *)layer3, &proto,
            &remaining);
    }

    /* no payload? */
    if (payload == NULL) {
        return 0;
    }

    payload = (char *)trace_get_payload_from_tcp((libtrace_tcp_t *)payload, &remaining);

    /* no tcp payload, BGP runs over TCP */
    if (payload == NULL) {
        return 0;
    }

    pos = payload;
    bgp_header = (struct module_bgp_header *)payload;

    /* filter out BGP packets with a invalid marker. All bgp packets should have 16bytes of 0xff */
    for (int i = 0; i < 16; i++ ) {
        if (bgp_header->marker[i] != 0xFF) {
            return 0;
        }
    }

    /* advance pos past the BGP header */
    pos = (payload + sizeof(struct module_bgp_header));

    struct module_bgp_open *open;
    struct module_bgp_open_opt *opt;
    uint8_t opt_len;

    switch (bgp_header->type) {
        case MODULE_BGP_TYPE_OPEN:
            open = (struct module_bgp_open *)pos;

            fprintf(stderr, "Open message\n");
            fprintf(stderr, "version: %u\n", open->version);
            fprintf(stderr, "AS number: %u\n", ntohs(open->autonomous_system));
            fprintf(stderr, "Hold time: %u\n", ntohs(open->hold_time));
            fprintf(stderr, "BGP identifier: %u\n", ntohl(open->bgp_identifier));
            fprintf(stderr, "Options length: %u\n", open->opt_len);

            /* set counter for len of optional parameters */
            opt_len = open->opt_len;

            /* advance pos over the open header to the optional parameters */
            pos += sizeof(struct module_bgp_open);

            /* this field is zero when no optional params are present */
            while (opt_len > 0) {
                opt = (struct module_bgp_open_opt *)pos;
                fprintf(stderr, "Option param %u\n", opt->param_type);
                fprintf(stderr, "Option param length %u\n", opt->param_len);

                /* jump over the rest of this param to the next option */
                pos += sizeof(struct module_bgp_open_opt) + opt->param_len;

                /* reduce the option len counter */
                opt_len -= sizeof(struct module_bgp_open_opt) + opt->param_len;
            }

            break;
        case MODULE_BGP_TYPE_UPDATE:
            fprintf(stderr, "got bgp update\n");
            break;
        case MODULE_BGP_TYPE_NOTIFICATION:
            fprintf(stderr, "got bgp notification\n");
            break;
        case MOUDLE_BGP_TYPE_KEEPALIVE:
            fprintf(stderr, "got bgp keepalive\n");
            break;
        case MODULE_BGP_TYPE_OPEN_CONFIRM:
            fprintf(stderr, "got GBP PACKET\n");
            break;
        default:
            /* unknown type */
            return 0;
    }
    fprintf(stderr, "\n");
}

int module_bgp_config(yaml_parser_t *parser, yaml_event_t *event, int *level) {

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

        bd_register_packet_event(config->callbacks, (cb_packet)module_bgp_packet);
        bd_add_filter_to_cb_set(config->callbacks, "port 179");
    }
}

int module_bgp_init(bd_bigdata_t *bigdata) {

    config = (module_bgp_conf *)malloc(sizeof(struct module_bgp_conf));
    if (config == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_bgp_init()\n");
        exit(BD_OUTOFMEMORY);
    }

    config->callbacks = bd_create_cb_set("bgp");
    config->enabled = 0;

    bd_register_config_event(config->callbacks, (cb_config)module_bgp_config);

    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}
