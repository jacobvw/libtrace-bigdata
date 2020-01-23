#include "module_tls.h"
#include <list>
#include <openssl/md5.h>

/* TLS packet types */
#define TLS_PACKET_CHANGE_CIPHER_SPEC 20
#define TLS_PACKET_ALERT 21
#define TLS_PACKET_HANDSHAKE 22
#define TLS_PACKET_APPLICATION_DATA 23

/* TLS versions */
#define SSL_30 0x0300 // ssl 3.0
#define TLS_10 0x0301 // tls 1.0
#define TLS_11 0x0202 // tls 1.1
#define TLS_12 0x0303 // tls 1.2
#define TLS_13 0x0304 // tls 1.3

/* TLS handshake types, TLS packet type 22*/
#define TLS_HANDSHAKE_HELO_REQUEST 0
#define TLS_HANDSHAKE_CLIENT_HELLO 1
#define TLS_HANDSHAKE_SERVER_HELLO 2
#define TLS_HANDSHAKE_CERTIFICATE 11
#define TLS_HANDSHAKE_SERVER_KEY_EXCHANGE 12
#define TLS_HANDSHAKE_CERTIFICATE_REQUEST 13
#define TLS_HANDSHAKE_SERVER_DONE 14
#define TLS_HANDSHAKE_CERTIFICATE_VERIFY 15
#define TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE 16
#define TLS_HANDSHAKE_FINISHED 20

/* TLS change cipher spec types, TLS packet type 20.
 * This type only has a single message type. */

/* TLS alert types, TLS packet type 21 */
#define TLS_ALERT_SEVERITY_WARNING 1
#define TLS_ALERT_SEVERITY_FATAL 2
/* TLS alert descriptions */
#define TLS_ALERT_CLOSE_NOTIFY 0
#define TLS_ALERT_UNEXPECTED_MESSAGE 10
#define TLS_ALERT_BAD_RECORD_MAC 20
#define TLS_ALERT_DECRYPTION_FAILED 21
#define TLS_ALERT_RECORD_OVERFLOW 22
#define TLS_ALERT_DECOMPRESSION_FAILURE 30
#define TLS_ALERT_HANDSHAKE_FAILURE 40
#define TLS_ALERT_NO_CERTIFICATE 41
#define TLS_ALERT_BAD_CERTIFICATE 42
#define TLS_ALERT_UNSUPPORTED_CERTIFICATE 43
#define TLS_ALERT_CERTIFICATE_REVOKED 44
#define TLS_ALERT_CERTIFICATE_EXPIRED 45
#define TLS_ALERT_CERTIFICATE_UNKNOWN 46
#define TLS_ALERT_ILLEGAL_PARAMETER 47
#define TLS_ALERT_UNKNOWN_CA 48
#define TLS_ALERT_ACCESS_DENIED 49
#define TLS_ALERT_DECODE_ERROR 50
#define TLS_ALERT_DECRYPT_ERROR 51
#define TLS_ALERT_EXPORT_RESTRICTION 60
#define TLS_ALERT_PROTOCOL_VERSION 70
#define TLS_ALERT_INSUFFICIENT_SECURITY 71
#define TLS_ALERT_INTERNAL_ERROR 80
#define TLS_ALERT_USER_CANCELLED 90
#define TLS_ALERT_NO_RENEGOTIATION 100

/* TLS extension types */
#define TLS_EXTENSION_SERVER_NAME 0
#define TLS_EXTENSION_EC_CURVES 10 /* AKA supported groups */
#define TLS_EXTENSION_EC_POINT_FORMATS 11
#define TLS_EXTENSION_SESSION_TICKET 35
#define TLS_EXTENSION_SIGNATURE_ALGORITHMS 13
#define TLS_EXTENSION_HEARTBEAT 15
#define TLS_EXTENSION_NEXT_PROTOCOL_NEGOTIATION 13172
#define TLS_EXTENSION_APP_LAYER_PROTO_NEGOTIATION 16
#define TLS_EXTENSION_PADDING 21

/* TLS application data types. TLS packet type 23 */



/* structure prototypes */
typedef struct module_tls_handshake mod_tls_handshake;

typedef struct module_tls_config {
    bd_cb_set *callbacks;
} mod_tls_conf;
mod_tls_conf *config;

typedef struct module_tls_storage {
    /* map to store tls handshakes against each flow id */
    std::map<uint64_t, mod_tls_handshake *> *tls;
} mod_tls_stor;

/* TLS header, This is at the begining of every
 * tls packet. */
typedef struct module_tls_header {
    uint8_t type;
    uint16_t version;
    uint16_t length;
} PACKED mod_tls_hdr;

/* TLS handshake header */
typedef struct module_tls_handshake_header {
    uint8_t type;
    uint8_t length[3];
    uint16_t version;
    char random[32];
    uint8_t session_id_len;
} PACKED mod_tls_handshake_hdr;

/* TLS extension header */
typedef struct module_tls_extension_header {
    uint16_t type;
    uint16_t len;
} PACKED mod_tls_ext_hdr;

/* structures used to describe a tls session */
typedef struct module_tls_client {

    uint16_t version;

    /* codes need to calculate ja3 */
    std::list<uint16_t> *extensions;
    std::list<uint16_t> *ciphers;
    std::list<uint16_t> *ec_curves;
    std::list<uint16_t> *ec_points;

    char *ja3_md5;
    char *host_name;

} mod_tls_client;
typedef struct module_tls_server {

    uint16_t version;
    uint16_t cipher;
    uint8_t compression_method;

    std::list<uint16_t> *extensions;

    char *ja3_md5;

} mod_tls_server;
typedef struct module_tls_handshake {

    uint16_t version;
    char *version_protocol;
    uint16_t cipher;
    char *next_protocol;

    mod_tls_client *client;
    mod_tls_server *server;

} mod_tls_handshake;


/* function prototypes */
mod_tls_client *module_tls_client_create();
void module_tls_client_destroy(mod_tls_client *client);

mod_tls_client *module_tls_parse_client_hello(bd_bigdata_t *bigdata, char *payload);
mod_tls_server *module_tls_parse_server_hello(bd_bigdata_t *bigdata, char *payload);

void module_tls_parse_ec_point_extension(char *payload, mod_tls_client *client);
void module_tls_parse_ec_curves_extension(char *payload, mod_tls_client *client);
void module_tls_parse_server_name_extension(char *payload, mod_tls_client *client);

void module_tls_generate_server_ja3_md5(mod_tls_server *server);
void module_tls_generate_client_ja3_md5(mod_tls_client *client);



void *module_tls_starting(void *tls) {

    mod_tls_stor *storage;

    storage = (mod_tls_stor *)malloc(sizeof(mod_tls_stor));

    storage->tls = new std::map<uint64_t, mod_tls_handshake *>;

    return storage;
}

int module_tls_packet(bd_bigdata_t *bigdata, void *mls) {

    void *layer3;
    char *payload = NULL;
    uint8_t proto;
    uint16_t ethertype;
    uint32_t remaining;
    mod_tls_stor *storage;
    mod_tls_handshake *tls_handshake;
    uint64_t flow_id;
    std::map<uint64_t, mod_tls_handshake *>::iterator it;

    /* this only deals with flow data. */
    if (bigdata->flow == NULL) {
        return 0;
    }

    flow_id = bd_flow_get_id(bigdata->flow);
    storage = (mod_tls_stor *)mls;

    layer3 = trace_get_layer3(bigdata->packet, &ethertype, &remaining);
    /* make sure layer3 was found. */
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

    /* get TCP payload */
    payload = (char *)trace_get_payload_from_tcp((libtrace_tcp_t *)payload, &remaining);

    /* no tcp payload? */
    if (payload == NULL || remaining == 0) {
        return 0;
    }

    /* if this is not a tls/ssl packet may aswell return now */
    if (payload[0] != TLS_PACKET_CHANGE_CIPHER_SPEC &&
        payload[0] != TLS_PACKET_ALERT &&
        payload[0] != TLS_PACKET_HANDSHAKE &&
        payload[0] != TLS_PACKET_APPLICATION_DATA) {

        return 0;
    }

    /* see if any tls state is held for this flow */
    it = storage->tls->find(flow_id);
    /* if so get pointer to it else create it */
    if (it != storage->tls->end()) {
        tls_handshake = it->second;
    } else {
        tls_handshake = (mod_tls_handshake *)malloc(sizeof(
            mod_tls_handshake));
        if (tls_handshake == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. "
                "module_tls_packet()");
            exit(BD_OUTOFMEMORY);
        }
    }

    /* payload[0] should be pointing at tls packet type */
    switch (payload[0]) {

        case TLS_PACKET_CHANGE_CIPHER_SPEC: {

        break;
        }

        case TLS_PACKET_ALERT: {

        break;
        }

        case TLS_PACKET_HANDSHAKE: {

            /* what type of handshake is this message. */
            switch ((payload+5)[0]) {

                 case TLS_HANDSHAKE_HELO_REQUEST: {

                     break;
                 }
                 case TLS_HANDSHAKE_CLIENT_HELLO: {
                     tls_handshake->client =
                         module_tls_parse_client_hello(bigdata, payload+5);

                     break;
                 }
                 case TLS_HANDSHAKE_SERVER_HELLO: {
                     tls_handshake->server =
                         module_tls_parse_server_hello(bigdata, payload+5);
                     break;
                 }
                 case TLS_HANDSHAKE_CERTIFICATE:
                 case TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
                 case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
                 case TLS_HANDSHAKE_SERVER_DONE:
                 case TLS_HANDSHAKE_CERTIFICATE_VERIFY:
                 case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
                 case TLS_HANDSHAKE_FINISHED:
                 default: {
                     break;
                 }
            }

            break;
        }

        case TLS_PACKET_APPLICATION_DATA: {

        break;
        }

        default: {

        break;
        }

    }

    return 0;
}

int module_tls_init(bd_bigdata_t *bigdata) {

    config = (mod_tls_conf *)malloc(sizeof(mod_tls_conf));
    if (config == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_tls_init()");
        exit(BD_OUTOFMEMORY);
    }

    config->callbacks = bd_create_cb_set("tls");

    bd_register_start_event(config->callbacks, (cb_start)module_tls_starting);
    bd_register_packet_event(config->callbacks, (cb_packet)module_tls_packet);

    bd_register_cb_set(bigdata, config->callbacks);

    return 0;

}

mod_tls_server *module_tls_server_create() {

    mod_tls_server *server;

    server = (mod_tls_server *)malloc(sizeof(mod_tls_server));
    if (server == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_tls_server_create()");
        exit(BD_OUTOFMEMORY);
    }

    server->extensions = new std::list<uint16_t>;

    server->ja3_md5 = NULL;

    return server;
}

void module_tls_server_destroy(mod_tls_server *server) {

    delete(server->extensions);

    if (server->ja3_md5 != NULL) {
        free(server->ja3_md5);
        server->ja3_md5 = NULL;
    }

    free(server);
}

mod_tls_server *module_tls_parse_server_hello(bd_bigdata_t *bigdata, char *payload) {

    mod_tls_server *server;
    mod_tls_handshake_hdr *hdr;
    mod_tls_ext_hdr *ext;
    uint16_t length;
    uint16_t extensions_len;
    uint16_t extension_len;
    uint16_t extension;
    int i;

    /* create the server */
    server = module_tls_server_create();
    hdr = (mod_tls_handshake_hdr *)payload;

    /* calculate length of the hello message */
    length = hdr->length[0] << 16 | hdr->length[1] << 8 |
        hdr->length[2];

    server->version = ntohs(hdr->version);

    /* move to the cipher */
    payload += sizeof(mod_tls_handshake_hdr);
    server->cipher = ntohs(*(uint16_t *)payload);

    /* move to compression method */
    payload += 2;
    server->compression_method = *(uint8_t *)payload;

    /* move to extensions length */
    payload += 1;

    extensions_len = ntohs(*(uint16_t *)payload);

    /* move payload to the first extension */
    payload += 2;

    /* extensions */
    for (i = 0; i < extensions_len; i++) {

        ext = (mod_tls_ext_hdr *)payload;

        extension = ntohs(ext->type);
        extension_len = ntohs(ext->len);

        /* insert the extension code */
        server->extensions->push_back(extension);


        /* reduce extensions length by the length of this
         * extension. */
        extensions_len -= (extension_len + sizeof(mod_tls_ext_hdr));
        /* advance payload forward to the next extension */
        payload += (extension_len + sizeof(mod_tls_ext_hdr));
    }

    /* generate server ja3 md5 */
    module_tls_generate_server_ja3_md5(server);

    return NULL;
}

mod_tls_client *module_tls_client_create() {

    mod_tls_client *client;

    client = (mod_tls_client *)malloc(sizeof(mod_tls_client));
    if (client == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "module_tls_parse_client_hello()");
        exit(BD_OUTOFMEMORY);
    }
    client->extensions = new std::list<uint16_t>;
    client->ciphers = new std::list<uint16_t>;
    client->ec_curves = new std::list<uint16_t>;
    client->ec_points = new std::list<uint16_t>;

    client->host_name = NULL;
    client->ja3_md5 = NULL;

    return client;
}

void module_tls_client_destroy(mod_tls_client *client) {

    delete(client->extensions);
    delete(client->ciphers);
    delete(client->ec_curves);
    delete(client->ec_points);

    if (client->host_name != NULL) {
        free(client->host_name);
        client->host_name = NULL;
    }

    if (client->ja3_md5 != NULL) {
        free(client->ja3_md5);
        client->ja3_md5 = NULL;
    }

    free(client);
}

mod_tls_client *module_tls_parse_client_hello(bd_bigdata_t *bigdata,
    char *payload) {

    mod_tls_client *client;
    mod_tls_handshake_hdr *hdr;
    uint32_t length;
    uint16_t num_ciphers;
    uint16_t cipher_len;
    uint16_t extensions_len;
    uint16_t extension;
    uint16_t extension_len;
    int i = 0;

    /* create the client */
    client = module_tls_client_create();

    hdr = (mod_tls_handshake_hdr *)payload;

    /* calculate length of the hello message */
    length = hdr->length[0] << 16 | hdr->length[1] << 8 |
        hdr->length[2];

    /* get the clients tls version */
    client->version = ntohs(hdr->version);

    /* advance the payload pointer to the ciphers length */
    payload += sizeof(mod_tls_handshake_hdr) +
        hdr->session_id_len;

    /* get number of cipher suites listed. Listed in bytes
     * and each cipher is 2 bytes. */
    cipher_len = ntohs(*(uint16_t *)payload);
    num_ciphers = cipher_len / 2;

    /* advance the payload pointer to the ciphers.
     * skipping over the cipher length field. */
    payload += 2;

    /* copy over each ciper */
    for (i = 0; i < num_ciphers; i++) {
        client->ciphers->push_back(ntohs(*(uint16_t *)payload));
        /* move payload to the next cipher */
        payload += 2;
    }

    /* should now be at the compression methods length.
     * Jump over this and the length of compression methods. */
    payload += 1 + (*(uint8_t *)payload);

    /* should now be at the extensions length */
    extensions_len = ntohs(*(uint16_t *)payload);

    /* move forward to the position of the first extension */
    payload += 2;

    /* loop over each client extension */
    for (i = 0; i < extensions_len; i++) {

        extension = ntohs(*(uint16_t *)payload);
        extension_len = ntohs(*(uint16_t *)(payload+2));

        /* to calculate ja3 we need the extension codes */
        client->extensions->push_back(ntohs(*(uint16_t *)payload));

        switch (ntohs(*(uint16_t *)payload)) {
            case TLS_EXTENSION_SERVER_NAME: {
                module_tls_parse_server_name_extension(payload,
                    client);
                break;
            }
            case TLS_EXTENSION_EC_CURVES: {
                module_tls_parse_ec_curves_extension(payload,
                    client);
                break;
            }
            case TLS_EXTENSION_EC_POINT_FORMATS: {
                module_tls_parse_ec_point_extension(payload,
                    client);
                break;
            }
            case TLS_EXTENSION_SESSION_TICKET: {
                break;
            }
            default: {
                /* dont know this extension move to next */
                break;
            }
        }

        /* reduce extensions length by the length of this
         * extension. */
        extensions_len -= (extension_len + 4);
        /* advance payload forward to the next extension */
        payload += (extension_len + 4);
    }


    /* generate the ja3 string */
    module_tls_generate_client_ja3_md5(client);

    return client;
}

void module_tls_generate_server_ja3_md5(mod_tls_server *server) {

    char ja3[2000];
    char buf[20];
    char extensions[500] = "";
    unsigned char md5[16];
    char md5string[33];
    std::list<uint16_t>::iterator it;

    /* extensions */
    for (it = server->extensions->begin(); it !=
        server->extensions->end(); it++) {

        if (it != server->extensions->begin()) {
            strcat(extensions, "-");
        }
        snprintf(buf, sizeof(buf), "%u", *it);
        strcat(extensions, buf);
    }

    /* construct ja3 string */
    snprintf(ja3, sizeof(ja3), "%u,%u,%s",
        server->version,
        server->cipher,
        extensions);

    /* run MD5 hash over it */
    MD5((const unsigned char *)ja3, strlen(ja3), md5);

    /* convert the integer rep from MD5 to hex */
    for(int i = 0; i < 16; ++i) {
        sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
    }

    server->ja3_md5 = strndup(md5string, 33);
}

/* generates the ja3 string then convert to the MD5 hash of it. */
void module_tls_generate_client_ja3_md5(mod_tls_client *client) {

    char ja3[2000];
    char ciphers[500] = "";
    char extensions[500] = "";
    char ec_curves[500] = "";
    char ec_points[500] = "";
    char buf[20];
    unsigned char md5[16];
    char md5string[33];

    std::list<uint16_t>::iterator it;

    /* ciphers */
    for (it = client->ciphers->begin(); it !=
        client->ciphers->end(); it++) {

        if (it != client->ciphers->begin()) {
            strcat(ciphers, "-");
        }

        snprintf(buf, sizeof(buf), "%u", *it);
        strcat (ciphers, buf);
    }

    /* extensions */
    for (it = client->extensions->begin(); it !=
        client->extensions->end(); it++) {

        if (it != client->extensions->begin()) {
            strcat(extensions, "-");
        }

        snprintf(buf, sizeof(buf), "%u", *it);
        strcat(extensions, buf);
    }

    /* ec curves */
    for (it = client->ec_curves->begin(); it !=
        client->ec_curves->end(); it++) {

        if (it != client->ec_curves->begin()) {
            strcat(ec_curves, "-");
        }

        snprintf(buf, sizeof(buf), "%u", *it);
        strcat(ec_curves, buf);
    }

    /* ec points */
    for (it = client->ec_points->begin(); it !=
        client->ec_points->end(); it++) {

        if (it != client->ec_points->begin()) {
            strcat(ec_points, "-");
        }

        snprintf(buf, sizeof(buf), "%u", *it);
        strcat(ec_points, buf);
    }

    /* construct the ja3 string */
    snprintf(ja3, sizeof(ja3), "%u,%s,%s,%s,%s",
        client->version,
        ciphers,
        extensions,
        ec_curves,
        ec_points);

    /* run MD5 hash over it */
    MD5((const unsigned char *)ja3, strlen(ja3), md5);

    /* convert the integer rep from MD5 to hex */
    for(int i = 0; i < 16; ++i) {
        sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
    }

    client->ja3_md5 = strndup(md5string, 33);
}

void module_tls_parse_ec_point_extension(char *payload,
    mod_tls_client *client) {

    uint16_t len;
    uint8_t format_len;

    len = ntohs(*(uint16_t *)(payload+2));
    format_len = *(uint8_t *)(payload+4);

    /* move payload to the first point */
    payload += 5;

    for (int i = 0; i < format_len; i++) {
        client->ec_points->push_back(
            *(uint8_t *)(payload+i));
    }
}

void module_tls_parse_ec_curves_extension(char *payload,
    mod_tls_client *client) {

    uint16_t len;
    uint16_t num_curves;

    len = ntohs(*(uint16_t *)(payload+2));
    /* each ec curve takes up 2 bytes */
    num_curves = ntohs(*(uint16_t *)(payload+4)) / 2;

    /* move payload to the first curve */
    payload += 6;

    for (int i = 0; i < num_curves; i++) {
        client->ec_curves->push_back(
            ntohs(*(uint16_t *)(payload+(i*2))));
    }

}

void module_tls_parse_server_name_extension(char *payload,
    mod_tls_client *client) {

    uint16_t len;
    uint16_t list_len;
    uint16_t name_len;

    len = ntohs(*(uint16_t *)(payload+2));

    /* move to the first name */
    payload += 4;

    /* loop over each server_name */
    while (len > 0) {

        /* get the list len */
        list_len = ntohs(*(uint16_t *)payload);
        /* get the name len */
        name_len = ntohs(*(uint16_t *)(payload+3));

        /* depending on the name type */
        switch (*(uint8_t *)(payload+2)) {
            /* hostname */
            case 0x00: {
                client->host_name = strndup((payload+5),
                    name_len);
                break;
            }
        }

        payload += (list_len + 2);
        len -= (list_len + 2);
    }
}
