#include "bigdata.h"
#include "bigdata_tls.h"
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

/* Cipher Suite codes */
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xc02f
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xc02b
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0xc030
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xc02c
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 0x009e
#define TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 0x00a2
#define TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 0x00a3
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 0x009f
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 0xc027
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xc023
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 0xc013
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 0xc009
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 0xc028
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xc024
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 0xc014
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 0xc00a
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 0x0067
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA 0x0033
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 0x0040
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 0x006b
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA 0x0038
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA 0x0039
#define TLS_RSA_WITH_AES_128_GCM_SHA256 0x009c
#define TLS_RSA_WITH_AES_256_GCM_SHA384 0x009d
#define TLS_RSA_WITH_AES_128_CBC_SHA256 0x003c
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x003d
#define TLS_RSA_WITH_AES_128_CBC_SHA 0x002f
#define TLS_RSA_WITH_AES_256_CBC_SHA 0x0035
#define TLS_DH_DSS_WITH_AES_256_GCM_SHA384 0x00a5
#define TLS_DH_RSA_WITH_AES_256_GCM_SHA384 0x00a1
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 0x006a
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA256 0x0069
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA256 0x0068
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA 0x0037
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA 0x0036
#define TLS_DH_DSS_WITH_AES_128_GCM_SHA256 0x00a4
#define TLS_DH_RSA_WITH_AES_128_GCM_SHA256 0x00a0
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA256 0x003f
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA256 0x003e
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA 0x0032
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA 0x0031
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA 0x0030
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 0x0088
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA 0x0087
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA 0x0086
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA 0x0085
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA 0x0084
#define TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA 0x0045
#define TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA 0x0044
#define TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA 0x0043
#define TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA 0x0042
#define TLS_RSA_WITH_CAMELLIA_128_CBC_SHA 0x0041
#define TLS_RSA_WITH_3DES_EDE_CBC_SHA 0x000a
#define TLS_EMPTY_RENEGOTIATION_INFO_SCSV 0x00ff

/* TLS application data types. TLS packet type 23 */

/* https://tools.ietf.org/html/draft-davidben-tls-grease-01
 * These random extensions need to be ignored for ja3. */
static uint16_t GREASE[] = {
    0x0a0a,
    0x1a1a,
    0x2a2a,
    0x3a3a,
    0x4a4a,
    0x5a5a,
    0x6a6a,
    0x7a7a,
    0x8a8a,
    0x9a9a,
    0xaaaa,
    0xbaba,
    0xcaca,
    0xdada,
    0xeaea,
    0xfafa,
};
static int bd_tls_ext_grease(int ext) {
    int s = sizeof(GREASE) / sizeof(GREASE[0]);
    for (int i = 0; i < s; i++) {
        if (ext == GREASE[i]) {
            return 1;
        }
    }
    return 0;
}


/* TLS header, This is at the begining of every
 * tls packet. */
typedef struct bigdata_tls_header {
    uint8_t type;
    uint16_t version;
    uint16_t length;
} PACKED bd_tls_hdr;

/* TLS handshake header */
typedef struct bigdata_tls_handshake_header {
    uint8_t type;
    uint8_t length[3];
    uint16_t version;
    char random[32];
    uint8_t session_id_len;
} PACKED bd_tls_handshake_hdr;

/* TLS extension header */
typedef struct bigdata_tls_extension_header {
    uint16_t type;
    uint16_t len;
} PACKED bd_tls_ext_hdr;


/* function prototypes */
static bd_tls_client *bd_tls_client_create();
static void bd_tls_client_destroy(bd_tls_client *client);
static bd_tls_server *bd_tls_server_create();
static void bd_tls_server_destroy(bd_tls_server *server);

static bd_tls_client *bd_tls_parse_client_hello(bd_bigdata_t *bigdata, char *payload);
static bd_tls_server *bd_tls_parse_server_hello(bd_bigdata_t *bigdata, char *payload);

static void bd_tls_parse_ec_point_extension(char *payload, bd_tls_client *client);
static void bd_tls_parse_ec_curves_extension(char *payload, bd_tls_client *client);
static void bd_tls_parse_server_name_extension(char *payload, bd_tls_client *client);

static void bd_tls_generate_server_ja3_md5(bd_tls_server *server);
static void bd_tls_generate_client_ja3_md5(bd_tls_client *client);

/* API functions */
bd_tls_handshake *bd_tls_handshake_create() {

    bd_tls_handshake *handshake;

    handshake = (bd_tls_handshake *)malloc(
        sizeof(bd_tls_handshake));

    if (handshake == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "bd_tls_handshake_create())");
        exit(BD_OUTOFMEMORY);
    }

    handshake->client = NULL;
    handshake->server = NULL;

    return handshake;
}
void bd_tls_handshake_destroy(bd_tls_handshake *handshake) {

    if (handshake->client != NULL) {
        bd_tls_client_destroy(handshake->client);
        handshake->client = NULL;
    }

    if (handshake->server != NULL) {
        bd_tls_server_destroy(handshake->server);
        handshake->server = NULL;
    }

    free(handshake);
}
char *bd_tls_get_ja3_md5(Flow *flow) {

    bd_tls_handshake *handshake;

    handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        logger(LOG_DEBUG, "Flow record does not contain a tls "
            "handshake. func. bd_tls_get_ja3_md5()");
        return NULL;
    }

    if (handshake->client == NULL) {
        logger(LOG_DEBUG, "A TLS client hello has not been seen "
            "for this flow. func. bd_tls_get_ja3_md5()");
        return NULL;
    }

    /* if not generated generate the ja3 */
    if (handshake->client->ja3_md5 == NULL) {
        bd_tls_generate_client_ja3_md5(handshake->client);
    }

    return handshake->client->ja3_md5;
}
char *bd_tls_get_ja3s_md5(Flow *flow) {

    bd_tls_handshake *handshake;

    handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        logger(LOG_DEBUG, "Flow record does not contain a tls "
            "handshake. func. bd_tls_get_ja3s_md5()");
        return NULL;
    }

    if (handshake->server == NULL) {
        logger(LOG_DEBUG, "A TLS server hello has not been seen "
            "for this flow. func. bd_tls_get_ja3s_md5()");
        return NULL;
    }

    /* if not generated, generate the ja3s */
    if (handshake->server->ja3_md5 == NULL) {
        bd_tls_generate_server_ja3_md5(handshake->server);
    }

    return handshake->server->ja3_md5;
}
int bd_tls_flow(Flow *flow) {

    bd_tls_handshake *handshake;

    handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return 0;
    }

    /* musnt be a tls flow if client and server hello's are NULL */
    if (handshake->client == NULL &&
        handshake->server == NULL) {

        return 0;
    }

    return 1;

}
bd_tls_handshake *bd_tls_get_handshake(Flow *flow) {

    bd_flow_record_t *flow_record = bd_flow_get_record(flow);

    if (flow_record == NULL) {
        logger(LOG_DEBUG, "Unable to get flow record. func. "
            "bd_tls_get_handshake()");
        return NULL;
    }

    return flow_record->tls_handshake;
}
char *bd_tls_get_request_hostname(Flow *flow) {

    bd_tls_handshake *handshake;

    handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return NULL;
    }

    if (handshake->client == NULL) {
        return NULL;
    }

    return handshake->client->host_name;
}

int bd_tls_update(bd_bigdata_t *bigdata, bd_tls_handshake *tls_handshake) {

    void *layer3;
    char *payload = NULL;
    uint8_t proto;
    uint16_t ethertype;
    uint32_t remaining;
    bd_tls_hdr *hdr;

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
    if (payload == NULL) {
        return 0;
    }

    /* get TCP payload */
    payload = (char *)trace_get_payload_from_tcp((libtrace_tcp_t *)payload, &remaining);
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

    /* loop over each tls protocol in the packet */
    while (remaining > 0) {

        hdr = (bd_tls_hdr *)payload;

        switch (payload[0]) {
            case TLS_PACKET_CHANGE_CIPHER_SPEC: {
                //fprintf(stderr, "change ciper spec\n");
                break;
            }

            case TLS_PACKET_ALERT: {
                //fprintf(stderr, "tls alert\n");
                break;
            }

            case TLS_PACKET_HANDSHAKE: {

                /* what type of handshake is this message. */
                switch ((payload+5)[0]) {

                     case TLS_HANDSHAKE_HELO_REQUEST: {
                         //fprintf(stderr, "hello request\n");
                         break;
                     }
                     case TLS_HANDSHAKE_CLIENT_HELLO: {
                         if (tls_handshake->client == NULL) {
                             tls_handshake->client =
                                 bd_tls_parse_client_hello(bigdata, payload+5);
                         }
                         break;
                     }
                     case TLS_HANDSHAKE_SERVER_HELLO: {
                         if (tls_handshake->server == NULL) {
                             tls_handshake->server =
                                 bd_tls_parse_server_hello(bigdata, payload+5);
                         }
                         break;
                     }
                     case TLS_HANDSHAKE_CERTIFICATE: {
                         //fprintf(stderr, "got certificate\n");
                         break;
                     }
                     case TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
                         //fprintf(stderr, "got server key exchange\n");
                         break;
                     case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
                         //fprintf(stderr, "got certificate request\n");
                         break;
                     case TLS_HANDSHAKE_SERVER_DONE:
                         //fprintf(stderr, "got server done\n");
                         break;
                     case TLS_HANDSHAKE_CERTIFICATE_VERIFY:
                         //fprintf(stderr, "got certificate verify\n");
                         break;
                     case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
                         //fprintf(stderr, "got client key exchange\n");
                         break;
                     case TLS_HANDSHAKE_FINISHED:
                         //fprintf(stderr, "got handshake finished\n");
                         break;
                     default: {
                         /* unknown handshake type */
                         //fprintf(stderr, "unknonw handshake\n");
                         break;
                     }
                }

                break;
            }

            case TLS_PACKET_APPLICATION_DATA: {
                //fprintf(stderr, "tls packet app data\n");
                break;
            }

            default: {
                //fprintf(stderr, "unknown\n");
                break;
            }
        }

        /* if the tls header size says we have more than the remaining
         * just ignore it. Its most likely a certificate that has been
         * fragmented over multiple packets */
        if (remaining < (ntohs(hdr->length) + sizeof(bd_tls_hdr))) {
            remaining = 0;
        } else {
            /* the size within the header does not include the size of
             * the header itself. */
            remaining -= (ntohs(hdr->length) + sizeof(bd_tls_hdr));
            payload += (ntohs(hdr->length) + sizeof(bd_tls_hdr));
        }
    }

    return 0;
}

static bd_tls_server *bd_tls_server_create() {

    bd_tls_server *server;

    server = (bd_tls_server *)malloc(sizeof(bd_tls_server));
    if (server == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "bd_tls_server_create()");
        exit(BD_OUTOFMEMORY);
    }

    server->extensions = new std::list<uint16_t>;

    server->ja3_md5 = NULL;

    return server;
}

static void bd_tls_server_destroy(bd_tls_server *server) {

    if (server == NULL) {
     return;
    }

    delete(server->extensions);

    if (server->ja3_md5 != NULL) {
        free(server->ja3_md5);
        server->ja3_md5 = NULL;
    }

    free(server);
}

static bd_tls_server *bd_tls_parse_server_hello(bd_bigdata_t *bigdata, char *payload) {

    bd_tls_server *server;
    bd_tls_handshake_hdr *hdr;
    bd_tls_ext_hdr *ext;
    uint16_t length;
    uint16_t extensions_len;
    uint16_t extension_len;
    uint16_t extension;
    int i;

    /* create the server */
    server = bd_tls_server_create();
    hdr = (bd_tls_handshake_hdr *)payload;

    /* calculate length of the hello message */
    length = hdr->length[0] << 16 | hdr->length[1] << 8 |
        hdr->length[2];

    server->version = ntohs(hdr->version);

    /* move to the cipher */
    payload += sizeof(bd_tls_handshake_hdr) +
        hdr->session_id_len;

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

        ext = (bd_tls_ext_hdr *)payload;

        extension = ntohs(*(uint16_t *)payload);
        extension_len = ntohs(*(uint16_t *)(payload+2));

        /* insert the extension code if not GREASE */
        if (!bd_tls_ext_grease(extension)) {
            server->extensions->push_back(extension);
        }

        /* reduce extensions length by the length of this
         * extension. */
        extensions_len -= (extension_len + 4);
        /* advance payload forward to the next extension */
        payload += (extension_len + 4);
    }

    return server;
}

static bd_tls_client *bd_tls_client_create() {

    bd_tls_client *client;

    client = (bd_tls_client *)malloc(sizeof(bd_tls_client));
    if (client == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "bd_tls_parse_client_hello()");
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

static void bd_tls_client_destroy(bd_tls_client *client) {

    if (client == NULL) {
        return;
    }

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

static bd_tls_client *bd_tls_parse_client_hello(bd_bigdata_t *bigdata,
    char *payload) {

    bd_tls_client *client;
    bd_tls_handshake_hdr *hdr;
    uint32_t length;
    uint16_t num_ciphers;
    uint16_t cipher_len;
    uint16_t extensions_len;
    uint16_t extension;
    uint16_t extension_len;
    int i = 0;

    /* create the client */
    client = bd_tls_client_create();

    hdr = (bd_tls_handshake_hdr *)payload;

    /* calculate length of the hello message */
    length = hdr->length[0] << 16 | hdr->length[1] << 8 |
        hdr->length[2];

    /* get the clients tls version */
    client->version = ntohs(hdr->version);

    /* advance the payload pointer to the ciphers length */
    payload += sizeof(bd_tls_handshake_hdr) +
        hdr->session_id_len;

    /* get number of cipher suites listed. Listed in bytes
     * and each cipher is 2 bytes. */
    cipher_len = ntohs(*(uint16_t *)payload);
    num_ciphers = cipher_len / 2;

    /* advance the payload pointer to the ciphers.
     * skipping over the cipher length field. */
    payload += 2;

    /* copy over each ciper only if not grease */
    for (i = 0; i < num_ciphers; i++) {
        if (!bd_tls_ext_grease(ntohs(*(uint16_t *)payload))) {
            client->ciphers->push_back(ntohs(*(uint16_t *)payload));
        }
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

        /* insert extension code for ja3, only if not GREASE */
        if (!bd_tls_ext_grease(extension)) {
            client->extensions->push_back(extension);
        }

        switch (extension) {
            case TLS_EXTENSION_SERVER_NAME: {
                bd_tls_parse_server_name_extension(payload,
                    client);
                break;
            }
            case TLS_EXTENSION_EC_CURVES: {
                bd_tls_parse_ec_curves_extension(payload,
                    client);
                break;
            }
            case TLS_EXTENSION_EC_POINT_FORMATS: {
                bd_tls_parse_ec_point_extension(payload,
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

    return client;
}

static void bd_tls_generate_server_ja3_md5(bd_tls_server *server) {

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

static void bd_tls_generate_client_ja3_md5(bd_tls_client *client) {

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

static void bd_tls_parse_ec_point_extension(char *payload,
    bd_tls_client *client) {

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

static void bd_tls_parse_ec_curves_extension(char *payload,
    bd_tls_client *client) {

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

static void bd_tls_parse_server_name_extension(char *payload,
    bd_tls_client *client) {

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
