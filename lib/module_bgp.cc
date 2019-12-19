#include "module_bgp.h"
#include <stdio.h>

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

#define MODULE_BGP_PATH_ATTR_ORIGIN 0x01
#define MOUDLE_BGP_PATH_ATTR_ASPATH 0x02
#define MODULE_BGP_PATH_ATTR_NEXTHOP 0x03
#define MODULE_BGP_PATH_ATTR_MULTIEXITDISC 0x04
#define MODULE_BGP_PATH_ATTR_LOCALPREF 0x05
#define MODULE_BGP_PATH_ATTR_ATOMICAGGREGATE 0x06
#define MODULE_BGP_PATH_ATTR_AGGREGATOR 0x07


#define MODULE_BGP_NOTIFICATION_ERROR_HEADER 0x01
#define MODULE_BGP_NOTIFICATION_ERROR_OPEN 0x02
#define MODULE_BGP_NOTIFICATION_ERROR_UPDATE 0x03
#define MODULE_BGP_NOTIFICATION_ERRPR_HOLD 0x04
#define MODULE_BGP_NOTIFICATION_ERROR_FINITE 0x05
#define MODULE_BGP_NOTIFICATION_ERROR_CEASE 0x06

static const char *module_bgp_get_path_attr_type_string(uint8_t type);
static const char *module_bgp_type_string(uint8_t type);
static const char *module_bgp_capability_string(uint8_t type);
static const char *module_bgp_notification_error_string(uint8_t type);
static const char *module_bgp_notification_subcode_error_string(uint8_t error,
    uint8_t subcode);

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

/* open message */
struct module_bgp_open {
    uint8_t version;
    uint16_t autonomous_system;
    uint16_t hold_time;
    uint32_t bgp_identifier;
    uint8_t opt_len;
} PACKED;
struct module_bgp_open_opt {
    uint8_t param_type;
    uint8_t param_len;
} PACKED;

/* update message */
struct module_bgp_update_withdrawn {
    uint16_t withdrawn_len;
    /* varible withdrawn routes field here */
} PACKED;
struct module_bgp_update_withdrawn_route {
    uint8_t len;
    /* varible prefix field here. length depends on above len */
} PACKED;
struct module_bgp_update_attribute {
    uint16_t attribute_len;
} PACKED;
struct module_bgp_update_attribute_path {
    uint8_t attr_flags;
    uint8_t attr_type;
    uint8_t len;
    /* varible prefix field here. length depends on above len*/
} PACKED;
struct module_bgp_update_nlri {
    uint8_t len;
    /* varible prefix here, length depends on len above */
} PACKED;

/* notification message */
struct module_bgp_notification {
    uint8_t error_code;
    uint8_t error_subcode;
    /* contains varible data field, can be determined by
    data_len = header->length - sizeof(module_bgp_header) - sizeof(module_bgp_notification) */
} PACKED;


int module_bgp_packet(bd_bigdata_t *bigdata, void *mls) {

    void *layer3;
    char *payload, *pos;
    uint8_t proto;
    uint16_t ethertype;
    uint32_t remaining;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    char *source_ip, *destination_ip;
    int counter;
    char buf[100];

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

    /* get source/destination IPs */
    source_ip = trace_get_source_address_string(bigdata->packet, src_ip, INET6_ADDRSTRLEN);
    destination_ip = trace_get_destination_address_string(bigdata->packet, dst_ip, INET6_ADDRSTRLEN);

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
    struct module_bgp_notification *noti;
    struct module_bgp_update_withdrawn *withdrawn;
    struct module_bgp_update_withdrawn_route *w_route;
    struct module_bgp_update_attribute *attribute;
    struct module_bgp_update_attribute_path *a_path;
    struct module_bgp_update_nlri *nlri;
    uint8_t opt_len;
    int i;

    uint16_t withdrawn_len;
    uint16_t attribute_len;
    uint16_t nlri_len;

    uint32_t ident;

    /* create result structure */
    bd_result_set_t *result = bd_result_set_create(bigdata, "bgp");
    bd_result_set_insert_ip_string(result, "source_ip", source_ip);
    bd_result_set_insert_ip_string(result, "destination_ip", destination_ip);
    bd_result_set_insert_uint(result, "flow_id", bd_flow_get_id(bigdata->flow));
    bd_result_set_insert_tag(result, "type", module_bgp_type_string(bgp_header->type));

    switch (bgp_header->type) {
        case MODULE_BGP_TYPE_OPEN:
            open = (struct module_bgp_open *)pos;

            bd_result_set_insert_int(result, "version", open->version);
            bd_result_set_insert_int(result, "as_number", ntohs(open->autonomous_system));
            bd_result_set_insert_int(result, "hold_time", ntohs(open->hold_time));

            ident = ntohl(open->bgp_identifier);
            snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ((ident & 0xff000000) >> 24),
                                                  ((ident & 0x00ff0000) >> 16),
                                                  ((ident & 0x0000ff00) >> 8),
                                                  (ident & 0x000000ff));
            bd_result_set_insert_string(result, "bgp_identifier", buf);


            /* set counter for len of optional parameters */
            opt_len = open->opt_len;
            /* advance pos over the open header to the optional parameters */
            pos += sizeof(struct module_bgp_open);


            counter = 0;
            /* this field is zero when no optional params are present */
            while (opt_len > 0) {
                opt = (struct module_bgp_open_opt *)pos;

                snprintf(buf, sizeof(buf), "option_%d", counter);
                bd_result_set_insert_int(result, buf, opt->param_type);
                snprintf(buf, sizeof(buf), "option_%d_string", counter);
                bd_result_set_insert_string(result, buf, module_bgp_capability_string(opt->param_type));

                snprintf(buf, sizeof(buf), "option_%d_length", counter);
                bd_result_set_insert_int(result, buf, opt->param_len);

                /* TODO convert each option and insert into result */

                /* jump over the rest of this param to the next option */
                pos += sizeof(struct module_bgp_open_opt) + opt->param_len;

                /* reduce the option len counter */
                opt_len -= sizeof(struct module_bgp_open_opt) + opt->param_len;
                counter += 1;
            }

            break;
        case MODULE_BGP_TYPE_UPDATE:
            /* jump over BGP header to the update header */
            withdrawn = (struct module_bgp_update_withdrawn *)pos;

            bd_result_set_insert_int(result, "withdrawn_route_length", ntohs(withdrawn->withdrawn_len));

            /* advance pos over withdrawn routes len */
            pos += sizeof(struct module_bgp_update_withdrawn);
            withdrawn_len = ntohs(withdrawn->withdrawn_len);
            counter = 0;
            while (withdrawn_len > 0) {
                w_route = (struct module_bgp_update_withdrawn_route *)pos;

                /* advance pos past the withdrawn prefix length */
                pos += sizeof(struct module_bgp_update_withdrawn_route);

                snprintf(buf, sizeof(buf), "withdrawn_route_%d_length", counter);
                bd_result_set_insert_int(result, buf, w_route->len);

                snprintf(buf, sizeof(buf), "withdrawn_route_%d_prefix", counter);
                /* TODO convert withdrawn prefix and insert into result */

                //fprintf(stderr, "Withdrawn prefix: ");
                //for (int i = 0; i < w_route->len; i++) {
                //    fprintf(stderr, "%02x ", pos[i] & 0xff);
                //}
                //fprintf(stderr, "\n");

                /* reduce withdrawn length */
                withdrawn_len -= (w_route->len + sizeof(struct module_bgp_update_withdrawn_route));
                /* advance pos to the next withdrawn route or to path attribute length */
                pos += w_route->len;
                counter += 1;
            }

            attribute = (struct module_bgp_update_attribute *)pos;

            bd_result_set_insert_int(result, "path_attribute_length", ntohs(attribute->attribute_len));

            /* advance pos over attribute len */
            pos += sizeof(struct module_bgp_update_attribute);
            attribute_len = ntohs(attribute->attribute_len);
            counter = 0;
            while (attribute_len > 0) {
                a_path = (struct module_bgp_update_attribute_path *)pos;

                //fprintf(stderr, "Path attribute flags %u\n", a_path->attr_flags);
                //fprintf(stderr, "Path attribute type %s\n", module_bgp_get_path_attr_type_string(a_path->attr_type));
                //fprintf(stderr, "Path attribute length %u\n", a_path->len);

                snprintf(buf, sizeof(buf), "path_attribute_%d_flags", counter);
                bd_result_set_insert_int(result, buf, a_path->attr_flags); /* expand this out into each flag */

                snprintf(buf, sizeof(buf), "path_attribute_%d_type", counter);
                bd_result_set_insert_string(result, buf, module_bgp_get_path_attr_type_string(a_path->attr_type));

                /* move past the current path attribute header */
                pos += sizeof(struct module_bgp_update_attribute_path);

                //fprintf(stderr, "Path attribute prefix: ");
                //for (int i = 0; i < a_path->len; i++) {
                //    fprintf(stderr, "%02x ", pos[i] & 0xff);
                //}
                //fprintf(stderr, "\n");
                /* TODO convert this into the correct format and insert into result */

                attribute_len -= (a_path->len + sizeof(struct module_bgp_update_attribute_path));
                pos += a_path->len;
                counter += 1;
            }

            /* does this packet have network layer reachability information? */
            nlri_len = ntohs(bgp_header->length) - 23 -
                ntohs(withdrawn->withdrawn_len) - ntohs(attribute->attribute_len);
            counter = 0;
            while (nlri_len > 0) {
                nlri = (struct module_bgp_update_nlri *)pos;

                snprintf(buf, sizeof(buf), "nlri_%d_length", counter);
                bd_result_set_insert_int(result, buf, nlri->len);

                /* move forward to the varible length data */
                pos += sizeof(struct module_bgp_update_nlri);

                //uint16_t bytes = ((nlri->len+8-1)/8);
                //fprintf(stderr, "NLRI prefix: ");
                //for (int i = 0; i < bytes; i++) {
                //    fprintf(stderr, "%02x ", pos[i] & 0xff);
                //}
                //fprintf(stderr, "\n");
                /* TODO convert this into the correct format and insert into result */

                nlri_len -= (sizeof(struct module_bgp_update_nlri) + ((nlri->len+8-1)/8));
                pos += nlri->len;
                counter += 1;
            }

            break;
        case MODULE_BGP_TYPE_NOTIFICATION:
            noti = (struct module_bgp_notification *)pos;

            bd_result_set_insert_string(result, "error_code_string",
                module_bgp_notification_error_string(noti->error_code));
            bd_result_set_insert_int(result, "error_code", noti->error_code);

            bd_result_set_insert_string(result, "error_subcode_string",
                module_bgp_notification_subcode_error_string(noti->error_code,
                noti->error_subcode));
            fprintf(stderr, "Error subcode %u\n", noti->error_subcode);

            /* data length */
            opt_len = ntohs(bgp_header->length) - sizeof(module_bgp_header) - sizeof(module_bgp_notification);

            /* advance pos to the data field */
            pos += sizeof(module_bgp_notification);

            /* print data in bytes */
            //for (i = 0; i < opt_len; i++) {
            //    fprintf(stderr, "%02x ", pos[i] & 0xff);
            //}
            //fprintf(stderr, "\n");
            /* TODO figure appropiate format to export this in */


            break;
        case MOUDLE_BGP_TYPE_KEEPALIVE:
        case MODULE_BGP_TYPE_OPEN_CONFIRM:
        default:
            break;
    }

    /* insert the timestamp and publish the result */
    bd_result_set_insert_timestamp(result, trace_get_seconds(bigdata->packet));
    bd_result_set_publish(bigdata, result, trace_get_seconds(bigdata->packet));
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

        fprintf(stderr, "BGP plugin enabled\n");
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

static const char *module_bgp_get_path_attr_type_string(uint8_t type) {

    switch (type) {
        case MODULE_BGP_PATH_ATTR_ORIGIN: return "ORIGIN";
        case MOUDLE_BGP_PATH_ATTR_ASPATH: return "AS_PATH";
        case MODULE_BGP_PATH_ATTR_NEXTHOP: return "NEXT_HOP";
        case MODULE_BGP_PATH_ATTR_MULTIEXITDISC: return "MULTI_EXIT_DISC";
        case MODULE_BGP_PATH_ATTR_LOCALPREF: return "LOCAL_PREF";
        case MODULE_BGP_PATH_ATTR_ATOMICAGGREGATE: return "ATOMIC_AGGREGATE";
        case MODULE_BGP_PATH_ATTR_AGGREGATOR: return "AGGREGATOR";
        default: return "UNKNOWN";
    }
}

static const char *module_bgp_type_string(uint8_t type) {

    switch (type) {
        case MODULE_BGP_TYPE_OPEN: return "open";
        case MODULE_BGP_TYPE_UPDATE: return "update";
        case MODULE_BGP_TYPE_NOTIFICATION: return "notification";
        case MOUDLE_BGP_TYPE_KEEPALIVE: return "keepalive";
        case MODULE_BGP_TYPE_OPEN_CONFIRM: return "open_confirm";
        default: return "unknown";
    }
}

static const char *module_bgp_capability_string(uint8_t type) {

    switch (type) {
        /* 0 - reserved */
        case 0x01: return "multi protocol extensions";
        case 0x02: return "route refresh";
        case 0x03: return "outbound route filtering";
        case 0x04: return "multiple routes to a destination (deprecated)";
        case 0x05: return "extended next hop encoding";
        case 0x06: return "BGP extended message";
        case 0x07: return "BGPsec";
        case 0x08: return "multiple labels";
        case 0x09: return "BGP role";
        /* 10 - 63 unassigned */
        case 64: return "graceful restart";
        case 65: return "support for 4-octet AS number";
        case 66: return "deprecated";
        case 67: return "support for dynamic";
        case 68: return "multisession BGP";
        case 69: return "ADD-PATH";
        case 70: return "enhanced route refresh";
        case 71: return "long-lived graceful restart";
        /* 72 unassigned */
        case 73: return "FQDN";
        /* 74 - 127 unassigned */
        /* 128 - 255 reserved for private use */
        default: return "unknown";
    }
}

static const char *module_bgp_notification_error_string(uint8_t type) {

    switch (type) {
        case 0x01: return "message header";
        case 0x02: return "open message";
        case 0x03: return "update message";
        case 0x04: return "hold timer expired";
        case 0x05: return "finite state machine";
        case 0x06: return "cease";
        default: return "unknown";
    }
}

static const char *module_bgp_notification_subcode_error_string(uint8_t error,
    uint8_t subcode) {

    switch (error) {
        case 0x01:
            switch (subcode) {
                case 0x01: return "connection not synchronized";
                case 0x02: return "bad message length";
                case 0x03: return "bad message type";
                default: return "unknown";
            }
        case 0x02:
            switch(subcode) {
                case 0x01: return "unsupported version number";
                case 0x02: return "bad peer AS";
                case 0x03: return "bad BGP identifier";
                case 0x04: return "unsupported optional parameter";
                case 0x05: return "deprecated";
                case 0x06: return "unacceptable hold time";
                default: return "unknown";
            }
        case 0x03:
            switch (subcode) {
                case 0x01: return "malformed attribute list";
                case 0x02: return "unrecognized well-known attribute";
                case 0x03: return "missing well-known attribute";
                case 0x04: return "attribute flags error";
                case 0x05: return "attribute length error";
                case 0x06: return "invalid origin attribute";
                case 0x07: return "deprecated";
                case 0x08: return "invalid next-hop attribute";
                case 0x09: return "optional attribute error";
                case 0x0a: return "invalid network field";
                case 0x0b: return "malformed AS path";
                default: return "unknown";
            }
        default: return "unknown";
    }
}
