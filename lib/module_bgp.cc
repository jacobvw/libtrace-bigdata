#include "module_bgp.h"
#include <stdio.h>
#include <unordered_map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

/* https://tools.ietf.org/html/rfc4271#section-4 */

#define MODULE_BGP_TYPE_OPEN 0x01
#define MODULE_BGP_TYPE_UPDATE 0x02
#define MODULE_BGP_TYPE_NOTIFICATION 0x03
#define MOUDLE_BGP_TYPE_KEEPALIVE 0x04

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
#define MODULE_BGP_PATH_ATTR_MP_REACH_NLRI 14
#define MODULE_BGP_PATH_ATTR_MP_UNREACH_NLRI 15

#define MODULE_BGP_NOTIFICATION_ERROR_HEADER 0x01
#define MODULE_BGP_NOTIFICATION_ERROR_OPEN 0x02
#define MODULE_BGP_NOTIFICATION_ERROR_UPDATE 0x03
#define MODULE_BGP_NOTIFICATION_ERRPR_HOLD 0x04
#define MODULE_BGP_NOTIFICATION_ERROR_FINITE 0x05
#define MODULE_BGP_NOTIFICATION_ERROR_CEASE 0x06

struct module_bgp_conf {
    bd_cb_set *callbacks;
    bool enabled;
    int timeout_check;
};
static struct module_bgp_conf *config;

typedef struct module_bgp_session {
    uint16_t src_asn;
    uint16_t dst_asn;
    uint16_t src_hold_time;
    uint16_t dst_hold_time;
    double src_last_update;
    double dst_last_update;
} mod_bgp_sess;

typedef struct module_bgp_storage {
    /* map holding state of each bgp session. Identified by the flow ID */
    std::unordered_map<uint64_t, mod_bgp_sess> *bgp_sessions;
} mod_bgp_stor;

/* functions to covert different BGP type codes to their string
 * representations. */
static const char *module_bgp_get_path_attr_type_string(uint8_t type);
static const char *module_bgp_type_string(uint8_t type);
static const char *module_bgp_open_parameter_string(uint8_t type);
static const char *module_bgp_capability_string(uint8_t type);
static const char *module_bgp_notification_error_string(uint8_t type);
static const char *module_bgp_notification_subcode_error_string(uint8_t error,
    uint8_t subcode);

/* functions to parse each of the BGP message types */
int module_bgp_parse_open(bd_bigdata_t *bigdata, mod_bgp_stor *storage,
    char *pos, struct module_bgp_header *bgp_header);
int module_bgp_parse_open_optional_capability(char *pos);
int module_bgp_parse_update(bd_bigdata_t *bigdata, mod_bgp_stor *storage,
    char *pos, struct module_bgp_header *bgp_header);
int module_bgp_parse_notification(char *pos, struct module_bgp_header *header);

/* functions to update to stored state for each BGP session */
int module_bgp_open_state(bd_bigdata_t *bigdata, mod_bgp_stor *storage,
    uint16_t asn, uint16_t hold_time);
int module_bgp_update_state(bd_bigdata_t *bigdata, mod_bgp_stor *storage);
int module_bgp_close_state(bd_bigdata_t *bigdata, mod_bgp_stor *storage);

/* helper functions */
char *module_bgp_get_ip4_prefix_string(char *pos, int octets);
int module_bgp_calculate_ip_prefix_length(int bits);

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
/* BGP open optional paramter */
struct module_bgp_open_opt {
    uint8_t param_type;
    uint8_t param_len;
    /* varible length field decoded based on the param_type */
} PACKED;
/* BGP open capability */
struct module_bgp_open_cap {
    uint8_t cap_code;
    uint8_t cap_len;
    /* varible length field decoded based on the cap_code */
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
    /* it is posible for this field to be 2 octets long. If this
     * is the case a flag is set indicating it */
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

/* MP_REACH_NLRI headers - https://tools.ietf.org/html/rfc2283 */
struct module_bgp_mp_reach {
    uint16_t afi; /* address family identifier */
    uint8_t safi; /* subsequent address family identifier */
    uint8_t nexthop_len;
    /* contains a varible length field determined by nexthop_len */
} PACKED;
struct module_bgp_mp_reach_snpa {
    uint8_t snpa_num; /* the number of snpa records to follow */
} PACKED;
struct module_bgp_mp_reach_snpa_record {
    uint8_t snpa_len;
    /* contains varible length field determined by snpa_len */
} PACKED;
struct module_bgp_mp_reach_nlri {
    uint8_t nlri_len;
    /* contains a varible length field determined by nlri_len */
} PACKED;

/* MP_UNREACH_NLRI headers - https://tools.ietf.org/html/rfc2283 */
struct module_bgp_mp_unreach {
    uint16_t afi;
    uint8_t safi;
} PACKED;
struct module_bgp_mp_unreach_nlri {
    uint8_t nlri_len;
    /* contains a varible length field determined by nlri_len */
} PACKED;


void *module_bgp_starting(void *tls) {

    mod_bgp_stor *storage = (mod_bgp_stor *)malloc(sizeof(
        mod_bgp_stor));
    if (storage == NULL) {
        fprintf(stderr, "Unable to allocate memory. func. "
            "module_bgp_starting()\n");
        exit(BD_OUTOFMEMORY);
    }

    storage->bgp_sessions = new std::unordered_map<uint64_t, mod_bgp_sess>;

    return storage;
}

int module_bgp_packet(bd_bigdata_t *bigdata, void *mls) {

    void *layer3;
    char *payload, *pos;
    uint8_t proto;
    uint16_t ethertype;
    uint32_t remaining;
    char src_ip[INET6_ADDRSTRLEN];
    char dst_ip[INET6_ADDRSTRLEN];
    char *source_ip, *destination_ip;
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

    /* a single BGP packet can contain multiple messages */
    while (remaining > 0) {

        bgp_header = (struct module_bgp_header *)pos;

        /* Ignore the BGP message if a invalid marker is found.
         * All BGP packets should have 16 bytes of 0xff */
        for (int i = 0; i < 16; i++ ) {
            if (bgp_header->marker[i] != 0xFF) {
                return 0;
            }
        }

        fprintf(stderr, "BGP message\n");
        fprintf(stderr, "length %u\n", ntohs(bgp_header->length));

        /* advance pos past the BGP header */
        pos += sizeof(struct module_bgp_header);

        /* parse the correct BGP message type */
        switch (bgp_header->type) {
            case MODULE_BGP_TYPE_OPEN:
                module_bgp_parse_open(bigdata, (mod_bgp_stor *)mls, pos, bgp_header);
                break;
            case MODULE_BGP_TYPE_UPDATE:
                module_bgp_parse_update(bigdata, (mod_bgp_stor *)mls,
                    pos, bgp_header);
                module_bgp_update_state(bigdata, (mod_bgp_stor *)mls);
                break;
            case MODULE_BGP_TYPE_NOTIFICATION:
                module_bgp_parse_notification(pos, bgp_header);
                module_bgp_close_state(bigdata, (mod_bgp_stor *)mls);
                break;
            case MOUDLE_BGP_TYPE_KEEPALIVE:
                module_bgp_update_state(bigdata, (mod_bgp_stor *)mls);
                break;
            default:
                break;
        }

        /* reduce the remaining payload */
        remaining -= ntohs(bgp_header->length);
        /* advance position to the next message */
        pos += ntohs(bgp_header->length) - sizeof(struct module_bgp_header);
    }

    fprintf(stderr, "\n");
}

int module_bgp_tick(bd_bigdata_t *bigdata, void *mls, uint64_t tick) {

    bd_result_set_t *res;
    mod_bgp_sess sess;
    mod_bgp_stor *storage = (mod_bgp_stor *)mls;

    std::unordered_map<uint64_t, mod_bgp_sess>::iterator it;
    for (it = storage->bgp_sessions->begin(); it !=
        storage->bgp_sessions->end(); ) {

        sess = it->second;

        if ((tick > (sess.src_last_update + sess.src_hold_time)) ||
           (tick > (sess.dst_last_update + sess.dst_hold_time))) {

            /* BGP timeout */

            res = bd_result_set_create(bigdata, "bgp");
            bd_result_set_insert_tag(res, "type", "session_timeout");

            bd_result_set_insert_uint(res, "source_asn", sess.src_asn);
            bd_result_set_insert_uint(res, "destination_asn", sess.dst_asn);
            bd_result_set_insert_uint(res, "source_hold_time", sess.src_hold_time);
            bd_result_set_insert_uint(res, "destination_hold_time", sess.dst_hold_time);

            bd_result_set_insert_timestamp(res, tick);
            bd_result_set_publish(bigdata, res, 0);

            storage->bgp_sessions->erase(it++);
        } else {
            ++it;
        }
    }
}

int module_bgp_open_state(bd_bigdata_t *bigdata, mod_bgp_stor *storage,
    uint16_t asn, uint16_t hold_time) {

    mod_bgp_sess sess;
    bd_result_set_t *res;
    struct timeval tv;

    /* get the flow id */
    uint64_t flow_id = bd_flow_get_id(bigdata->flow);

    /* search the bgp session map for this flow */
    std::unordered_map<uint64_t, mod_bgp_sess>::iterator it;
    it = storage->bgp_sessions->find(flow_id);

    /* if we have state stored for this bgp session update it */
    if (it != storage->bgp_sessions->end()) {
        sess = it->second;

        sess.dst_asn = asn;
        sess.dst_hold_time = hold_time;

        /* update the map */
        it->second = sess;

        /* should have a BGP sessions between 2 ases now. generate result */
        res = bd_result_set_create(bigdata, "bgp");
        bd_result_set_insert_tag(res, "type", "session_start");

        bd_result_set_insert_uint(res, "source_asn", sess.src_asn);
        bd_result_set_insert_uint(res, "destination_asn", sess.dst_asn);
        bd_result_set_insert_uint(res, "source_hold_time", sess.src_hold_time);
        bd_result_set_insert_uint(res, "destination_hold_time", sess.dst_hold_time);

        tv = trace_get_timeval(bigdata->packet);
        bd_result_set_insert_timestamp(res, tv.tv_sec);

        bd_result_set_publish(bigdata, res, 0);

    /* else create state for the BGP session */
    } else {

        sess.src_asn = asn;
        sess.src_hold_time = hold_time;
        sess.dst_asn = 0;
        sess.dst_hold_time = 0;

        /* insert into session map */
        storage->bgp_sessions->insert({flow_id, sess});
    }
}

int module_bgp_update_state(bd_bigdata_t *bigdata, mod_bgp_stor *storage) {

    mod_bgp_sess sess;
    /* get the flow id */
    uint64_t flow_id = bd_flow_get_id(bigdata->flow);
    int dir = bd_get_packet_direction(bigdata);

    /* search the bgp session map for this flow */
    std::unordered_map<uint64_t, mod_bgp_sess>::iterator it;
    it = storage->bgp_sessions->find(flow_id);

    /* if we have state stored for this bgp session update it */
    if (it != storage->bgp_sessions->end()) {
        sess = it->second;

        /* if dir = 0 packet is outbound meaning the src needs to be
           updated */
        if (dir == 0) {
            sess.src_last_update = trace_get_seconds(bigdata->packet);
        } else if (dir == 1) {
            sess.dst_last_update = trace_get_seconds(bigdata->packet);
        }

        /* update the map */
        it->second = sess;

    } else {
        /* something is wrong here. got a bgp keepalive for a unknown bgp
         * sessions? */
        fprintf(stderr, "Got BGP keepalive message for unknown BGP session\n");
    }
}

int module_bgp_close_state(bd_bigdata_t *bigdata, mod_bgp_stor *storage) {

    mod_bgp_sess sess;
    bd_result_set_t *res;
    struct timeval tv;
    /* get the flow id */
    uint64_t flow_id = bd_flow_get_id(bigdata->flow);

    /* search the bgp session map for this flow */
    std::unordered_map<uint64_t, mod_bgp_sess>::iterator it;
    it = storage->bgp_sessions->find(flow_id);

    /* if we have state stored for this bgp session update it */
    if (it != storage->bgp_sessions->end()) {

        sess = it->second;

        res = bd_result_set_create(bigdata, "bgp");
        bd_result_set_insert_tag(res, "type", "session_close");

        bd_result_set_insert_uint(res, "source_asn", sess.src_asn);
        bd_result_set_insert_uint(res, "destination_asn", sess.dst_asn);
        bd_result_set_insert_uint(res, "source_hold_time", sess.src_hold_time);
        bd_result_set_insert_uint(res, "destination_hold_time", sess.dst_hold_time);

        tv = trace_get_timeval(bigdata->packet);
        bd_result_set_insert_timestamp(res, tv.tv_sec);
        bd_result_set_publish(bigdata, res, 0);

        /* remove session state for this BGP session */
        storage->bgp_sessions->erase(it);

    } else {
        /* should never enter this */
        fprintf(stderr, "Got BGP notification message for unknown BGP session\n");
    }
}

int module_bgp_stopping(void *tls, void *mls) {

    mod_bgp_stor *storage = (mod_bgp_stor *)mls;

    delete(storage->bgp_sessions);

    free(storage);
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
                if (strcmp((char *)event->data.scalar.value, "timeout_check") == 0) {
                    consume_event(parser, event, level);
                    config->timeout_check = atoi((char *)event->data.scalar.value);
                    if (config->timeout_check == 0) {
                        fprintf(stderr, "Invalid timeout_check value. "
                            "module_bgp. setting to default 20 seconds\n");
                        config->timeout_check = 20;
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

        bd_register_start_event(config->callbacks, (cb_start)module_bgp_starting);
        bd_register_packet_event(config->callbacks, (cb_packet)module_bgp_packet);
        bd_add_filter_to_cb_set(config->callbacks, "port 179");
        bd_register_stop_event(config->callbacks, (cb_stop)module_bgp_stopping);

        config->callbacks->tick_cb = (cb_tick)module_bgp_tick;
        bd_add_tickrate_to_cb_set(config->callbacks, config->timeout_check);

        fprintf(stderr, "BGP Plugin Enabled\n");
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
    config->timeout_check = 20;

    bd_register_config_event(config->callbacks, (cb_config)module_bgp_config);

    bd_register_cb_set(bigdata, config->callbacks);

    return 0;
}

int module_bgp_parse_update(bd_bigdata_t *bigdata, mod_bgp_stor *storage,
    char *pos, struct module_bgp_header *bgp_header) {

    int counter;
    int bytes;

    /* first block is withdrawn routes */
    struct module_bgp_update_withdrawn *withdrawn;
    struct module_bgp_update_withdrawn_route *w_route;
    uint16_t withdrawn_len;

    withdrawn = (struct module_bgp_update_withdrawn *)pos;

    fprintf(stderr, "BGP update packet\n");
    fprintf(stderr, "withdrawn route length %u\n", ntohs(withdrawn->withdrawn_len));

    /* advance pos over withdrawn routes len */
    pos += sizeof(struct module_bgp_update_withdrawn);
    withdrawn_len = ntohs(withdrawn->withdrawn_len);
    counter = 0;
    while (withdrawn_len > 0) {
        w_route = (struct module_bgp_update_withdrawn_route *)pos;

        /* calculate number of bytes needed to store the IP prefix */
        bytes = module_bgp_calculate_ip_prefix_length(w_route->len);

        /* advance pos past the withdrawn prefix length */
        pos += sizeof(struct module_bgp_update_withdrawn_route);

        fprintf(stderr, "Withdrawn prefix: ");
        fprintf(stderr, "%s/%u\n", module_bgp_get_ip4_prefix_string(pos, bytes),
            w_route->len);

        /* reduce withdrawn length */
        withdrawn_len -= (sizeof(struct module_bgp_update_withdrawn_route) + bytes);
        /* advance pos to the next withdrawn route or to path attribute length */
        pos += bytes;
        counter += 1;
    }



    /* second block is path attributes */
    struct module_bgp_update_attribute *attribute;
    struct module_bgp_update_attribute_path *a_path;
    uint16_t attribute_len;

    attribute = (struct module_bgp_update_attribute *)pos;

    fprintf(stderr, "path attributes length: %u\n", ntohs(attribute->attribute_len));

    /* advance pos over attribute len */
    pos += sizeof(struct module_bgp_update_attribute);
    attribute_len = ntohs(attribute->attribute_len);
    counter = 0;
    while (attribute_len > 0) {
        a_path = (struct module_bgp_update_attribute_path *)pos;
        uint16_t attr_len;

        fprintf(stderr, "Path attribute flags %u\n", a_path->attr_flags);
        fprintf(stderr, "Path attribute type %s\n", module_bgp_get_path_attr_type_string(a_path->attr_type));

        /* check for extended length flag. When this flag is set the length field
         * is 2 octets long instead of 1. */
        if ((a_path->attr_flags & 16) == 16) {
            attr_len = ntohs(*(uint16_t *)(pos+2));
            /* when extended flag is set pos need to advance the extra octet and
             * remaining needs to be reduced by the extra octet. */
            pos += 1;
            attribute_len -= 1;
        } else {
            attr_len = a_path->len;
        }

        fprintf(stderr, "Path attribute length %u\n", attr_len);

        /* move past the current path attribute header */
        pos += sizeof(struct module_bgp_update_attribute_path);

        /* TODO decode each path attribute */
        switch (a_path->attr_type) {
            case MODULE_BGP_PATH_ATTR_ORIGIN:
            case MOUDLE_BGP_PATH_ATTR_ASPATH:
            case MODULE_BGP_PATH_ATTR_NEXTHOP:
            case MODULE_BGP_PATH_ATTR_MULTIEXITDISC:
            case MODULE_BGP_PATH_ATTR_LOCALPREF:
            case MODULE_BGP_PATH_ATTR_ATOMICAGGREGATE:
            case MODULE_BGP_PATH_ATTR_AGGREGATOR:
            case MODULE_BGP_PATH_ATTR_MP_REACH_NLRI:
            case MODULE_BGP_PATH_ATTR_MP_UNREACH_NLRI:
            default:
                fprintf(stderr, "Path attribute data: ");
                for (int i = 0; i < attr_len; i++) {
                    fprintf(stderr, "%02x ", pos[i] & 0xff);
                }
                fprintf(stderr, "\n");
        }

        attribute_len -= (sizeof(struct module_bgp_update_attribute_path) + attr_len);
        pos += attr_len;
        counter += 1;
    }



    /* third section should be network layer reachability information */
    struct module_bgp_update_nlri *nlri;
    uint16_t nlri_len;

    /* does this packet have network layer reachability information? */
    nlri_len = ntohs(bgp_header->length) - 23 -
        ntohs(withdrawn->withdrawn_len) - ntohs(attribute->attribute_len);
    counter = 0;
    while (nlri_len > 0) {
        nlri = (struct module_bgp_update_nlri *)pos;

        /* calculate number of bytes needed to store the IP prefix */
        bytes = module_bgp_calculate_ip_prefix_length(nlri->len);

        /* move forward to the varible length data */
        pos += sizeof(struct module_bgp_update_nlri);

        fprintf(stderr, "NLRI data: ");
        fprintf(stderr, "%s/%u\n", module_bgp_get_ip4_prefix_string(pos, bytes),
            nlri->len);

        nlri_len -= (sizeof(struct module_bgp_update_nlri) + bytes);
        pos += bytes;
        counter += 1;
    }

}

int module_bgp_parse_open(bd_bigdata_t *bigdata, mod_bgp_stor *storage, char *pos,
    struct module_bgp_header *bgp_header) {

    uint8_t opt_len;
    uint32_t ident;
    int counter;
    struct module_bgp_open *open;
    struct module_bgp_open_opt *opt;
    char buf[100];

    open = (struct module_bgp_open *)pos;

    module_bgp_open_state(bigdata, storage,
        ntohs(open->autonomous_system), ntohs(open->hold_time));

    fprintf(stderr, "BGP open message\n");
    fprintf(stderr, "version %u\n", open->version);
    fprintf(stderr, "AS number %u\n", ntohs(open->autonomous_system));
    fprintf(stderr, "hold time %u\n", ntohs(open->hold_time));

    ident = ntohl(open->bgp_identifier);
    snprintf(buf, sizeof(buf), "%u.%u.%u.%u", ((ident & 0xff000000) >> 24),
                                              ((ident & 0x00ff0000) >> 16),
                                              ((ident & 0x0000ff00) >> 8),
                                              (ident & 0x000000ff));
    fprintf(stderr, "identifier %s\n", buf);

    /* set counter for len of optional parameters */
    opt_len = open->opt_len;
    /* advance pos over the open header to the optional parameters */
    pos += sizeof(struct module_bgp_open);

    fprintf(stderr, "optional parameters length: %u\n", open->opt_len);

    counter = 0;
    /* this field is zero when no optional params are present */
    while (opt_len > 0) {
        opt = (struct module_bgp_open_opt *)pos;

        fprintf(stderr, "optional parameter: %s (%u)\n",
            module_bgp_open_parameter_string(opt->param_type),
            opt->param_type);
        fprintf(stderr, "optional length: %u\n", opt->param_len);

        /* parse optional parameter data */
        switch (opt->param_type) {
            /* capability */
            case 0x02: {
                module_bgp_parse_open_optional_capability(
                    (pos+sizeof(struct module_bgp_open_opt)));
            }
        }


        /* jump over the rest of this param to the next option */
        pos += sizeof(struct module_bgp_open_opt) + opt->param_len;

        /* reduce the option len counter */
        opt_len -= sizeof(struct module_bgp_open_opt) + opt->param_len;
        counter += 1;
    }
}

int module_bgp_parse_notification(char *pos, struct module_bgp_header *header) {

    struct module_bgp_notification *notification;
    uint16_t opt_len;

    notification = (struct module_bgp_notification *)pos;

    fprintf(stderr, "Notification packet\n");
    fprintf(stderr, "Major error code: %s (%u)\n",
        module_bgp_notification_error_string(notification->error_code), notification->error_code);
    fprintf(stderr, "Minor error code: %s (%u)\n",
        module_bgp_notification_subcode_error_string(notification->error_code, notification->error_subcode),
        notification->error_subcode);

    /* data length */
    opt_len =  ntohs(header->length) - sizeof(struct module_bgp_header) - sizeof(struct module_bgp_notification);

    /* advance pos to the data field */
    pos += sizeof(module_bgp_notification);

    /* print data in bytes */
    for (int i = 0; i < opt_len; i++) {
        fprintf(stderr, "%02x ", pos[i] & 0xff);
    }
    fprintf(stderr, "\n");

}

int module_bgp_parse_open_optional_capability(char *pos) {

    struct module_bgp_open_cap *capability;

    capability = (struct module_bgp_open_cap *)pos;

    fprintf(stderr, "Capability: %s (%u)\n",
        module_bgp_capability_string(capability->cap_code),
        capability->cap_code);
}

int module_bgp_calculate_ip_prefix_length(int bits) {
    return ((bits + 8 - 1) / 8);
}

char *module_bgp_get_ip4_prefix_string(char *pos, int octets) {

    struct in_addr ip4;
    ip4.s_addr = 0;
    memcpy(&ip4.s_addr, pos, octets);

    return inet_ntoa(ip4);
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
        case MODULE_BGP_PATH_ATTR_MP_REACH_NLRI: return "MP_REACH_NLRI";
        case MODULE_BGP_PATH_ATTR_MP_UNREACH_NLRI: return "MP_UNREACH_NLRI";
        default: return "UNKNOWN";
    }
}

static const char *module_bgp_type_string(uint8_t type) {

    switch (type) {
        case MODULE_BGP_TYPE_OPEN: return "open";
        case MODULE_BGP_TYPE_UPDATE: return "update";
        case MODULE_BGP_TYPE_NOTIFICATION: return "notification";
        case MOUDLE_BGP_TYPE_KEEPALIVE: return "keepalive";
        default: return "unknown";
    }
}

static const char *module_bgp_open_parameter_string(uint8_t type) {

    switch (type) {
        case 0x00: return "Reserved";
        case 0x01: return "Authentication";
        case 0x02: return "Capabilities";
        /* 3 - 254 unassigned */
        case 0xFF: return "Extended Length";
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
