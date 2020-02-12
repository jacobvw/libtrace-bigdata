#include "bigdata.h"
#include "bigdata_tls.h"
#include <list>

#include <openssl/md5.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/asn1.h>
#include <openssl/x509_vfy.h>
#include <openssl/pem.h>

/* buffer sizes used to generate ja3 md5 */
#define BD_TLS_JA3_LEN 10000
#define BD_TLS_EXT_LEN 5000
#define BD_TLS_CPHR_LEN 5000
#define BD_TLS_ECC_LEN 5000
#define BD_TLS_ECP_LEN 5000
#define BD_TLS_BUF_LEN 40

#define X509_SERIAL_NUM_LEN 1000

#define X509_SHA1LEN 20
#define X509_ISO_DATELEN 128

/* TLS packet types */
#define TLS_PACKET_CHANGE_CIPHER_SPEC 20
#define TLS_PACKET_ALERT 21
#define TLS_PACKET_HANDSHAKE 22
#define TLS_PACKET_APPLICATION_DATA 23

/* TLS versions */
#define SSL_30 0x0300 // ssl 3.0
#define TLS_10 0x0301 // tls 1.0
#define TLS_11 0x0302 // tls 1.1
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
#define TLS_EXTENSION_SUPPORTED_VERSIONS 43
#define TLS_EXTENSION_ENCRYPTED_SERVER_NAME 65486

/* Cipher Suite codes */
#define TLS_RSA_WITH_CAMELLIA_256_CBC_SHA 0x0084
#define TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA 0x0085
#define TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA 0x0086
#define TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA 0x0087
#define TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA 0x0088
#define TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA 0x0089
#define TLS_PSK_WITH_RC4_128_SHA 0x008a
#define TLS_PSK_WITH_3DES_EDE_CBC_SHA 0x008b
#define TLS_PSK_WITH_AES_128_CBC_SHA 0x008c
#define TLS_PSK_WITH_AES_256_CBC_SHA 0x008d
#define TLS_DHE_PSK_WITH_RC4_128_SHA 0x008e
#define TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA 0x008f
#define TLS_DHE_PSK_WITH_AES_128_CBC_SHA 0x0090
#define TLS_DHE_PSK_WITH_AES_256_CBC_SHA 0x0091
#define TLS_RSA_PSK_WITH_RC4_128_SHA 0x0092
#define TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA 0x0093
#define TLS_RSA_PSK_WITH_AES_128_CBC_SHA 0x0094
#define TLS_RSA_PSK_WITH_AES_256_CBC_SHA 0x0095
#define TLS_RSA_WITH_SEED_CBC_SHA 0x0096
#define TLS_DH_DSS_WITH_SEED_CBC_SHA 0x0097
#define TLS_DH_RSA_WITH_SEED_CBC_SHA 0x0098
#define TLS_DHE_DSS_WITH_SEED_CBC_SHA 0x0099
#define TLS_DHE_RSA_WITH_SEED_CBC_SHA 0x009a
#define TLS_DH_ANON_WITH_SEED_CBC_SHA 0x009b
#define TLS_RSA_WITH_AES_128_GCM_SHA256 0x009c
#define TLS_RSA_WITH_AES_256_GCM_SHA384 0x009d
#define TLS_DHE_RSA_WITH_AES_128_GCM_SHA256 0x009e
#define TLS_DHE_RSA_WITH_AES_256_GCM_SHA384 0x009f
#define TLS_DH_RSA_WITH_AES_256_GCM_SHA384 0x00a1
#define TLS_DHE_DSS_WITH_AES_128_GCM_SHA256 0x00a2
#define TLS_DHE_DSS_WITH_AES_256_GCM_SHA384 0x00a3
#define TLS_DH_DSS_WITH_AES_128_GCM_SHA256 0x00a4
#define TLS_DH_DSS_WITH_AES_256_GCM_SHA384 0x00a5
#define TLS_DH_ANON_WITH_AES_128_GCM_SHA256 0x00a6
#define TLS_DH_ANON_WITH_AES_256_GCM_SHA384 0x00a7
#define TLS_PSK_WITH_AES_128_GCM_SHA256 0x00a8
#define TLS_PSK_WITH_AES_256_GCM_SHA384 0x00a9
#define TLS_DHE_PSK_WITH_AES_128_GCM_SHA256 0x00aa
#define TLS_DHE_PSK_WITH_AES_256_GCM_SHA384 0x00ab
#define TLS_RSA_PSK_WITH_AES_128_GCM_SHA256 0x00ac
#define TLS_RSA_PSK_WITH_AES_256_GCM_SHA384 0x00ad
#define TLS_PSK_WITH_AES_128_CBC_SHA256 0x00ae
#define TLS_PSK_WITH_AES_256_CBC_SHA384 0x00af

#define TLS_AES_128_GCM_SHA256 0x1301
#define TLS_AES_256_GCM_SHA384 0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303
#define TLS_AES_128_CCM_SHA256 0x1304
#define TLS_AES_128_CCM_8_SHA256 0x1305

#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA 0xc009
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA 0xc00a
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA 0xc013
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA 0xc014
#define TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 0xc023
#define TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384 0xc024
#define TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256 0xc027
#define TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384 0xc028
#define TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 0xc02b
#define TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 0xc02c
#define TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 0xc02f
#define TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 0xc030
#define TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256 0xc037

#define TLS_RSA_WITH_AES_128_CCM_8 0xc0a0
#define TLS_RSA_WITH_AES_256_CCM_8 0xc0a1
#define TLS_DHE_RSA_WITH_AES_128_CCM_8 0xc0a2
#define TLS_DHE_RSA_WITH_AES_256_CCM_8 0xc0a3
#define TLS_PSK_WITH_AES_128_CCM 0xc0a4
#define TLS_PSK_WITH_AES_256_CCM 0xc0a5
#define TLS_DHE_PSK_WITH_AES_128_CCM 0xc0a6
#define TLS_DHE_PSK_WITH_AES_256_CCM 0xc0a7
#define TLS_PSK_WITH_AES_128_CCM_8 0xc0a8
#define TLS_PSK_WITH_AES_256_CCM_8 0xc0a9
#define TLS_PSK_DHE_WITH_AES_128_CCM_8 0xc0aa
#define TLS_PSK_DHE_WITH_AES_256_CCM_8 0xc0ab
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM 0xc0ac
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM 0xc0ad
#define TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8 0xc0ae
#define TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8 0xc0af
#define TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 0xcca8
#define TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 0xcca9
#define TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 0xccaa
#define TLS_PSK_WITH_CHACHA20_POLY1305_SHA256 0xccab
#define TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256 0xccac
#define TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256 0xccad
#define TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256 0xccae

#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA256 0x0067
#define TLS_DHE_RSA_WITH_AES_128_CBC_SHA 0x0033
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA256 0x0040
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA256 0x006b
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA 0x0038
#define TLS_DHE_RSA_WITH_AES_256_CBC_SHA 0x0039
#define TLS_RSA_WITH_AES_128_CBC_SHA256 0x003c
#define TLS_RSA_WITH_AES_256_CBC_SHA256 0x003d
#define TLS_RSA_WITH_AES_128_CBC_SHA 0x002f
#define TLS_RSA_WITH_AES_256_CBC_SHA 0x0035
#define TLS_DHE_DSS_WITH_AES_256_CBC_SHA256 0x006a
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA256 0x0069
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA256 0x0068
#define TLS_DH_RSA_WITH_AES_256_CBC_SHA 0x0037
#define TLS_DH_DSS_WITH_AES_256_CBC_SHA 0x0036
#define TLS_DH_RSA_WITH_AES_128_GCM_SHA256 0x00a0
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA256 0x003f
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA256 0x003e
#define TLS_DHE_DSS_WITH_AES_128_CBC_SHA 0x0032
#define TLS_DH_RSA_WITH_AES_128_CBC_SHA 0x0031
#define TLS_DH_DSS_WITH_AES_128_CBC_SHA 0x0030

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
typedef struct bigdata_tls_handshake_hello_header {
    uint8_t type;
    uint8_t length[3];
    uint16_t version;
    char random[32];
    uint8_t session_id_len;
} PACKED bd_tls_hndske_hlo_hdr;

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

static const unsigned char *bd_tls_get_subject_NID(X509 *cert, int issuer, int nid);
static int bd_tls_convert_x509_asn1time(ASN1_TIME *t, char *buf,
    size_t len);

static bd_tls_client *bd_tls_parse_client_hello(bd_bigdata_t *bigdata,
    uint16_t remaining, char *payload);
static bd_tls_server *bd_tls_parse_server_hello(bd_bigdata_t *bigdata,
    uint16_t remaining, char *payload);

static void bd_tls_parse_ec_point_extension(char *payload,
    bd_tls_client *client);
static void bd_tls_parse_ec_curves_extension(char *payload,
    bd_tls_client *client);
static void bd_tls_parse_server_name_extension(char *payload,
    bd_tls_client *client);
static void bd_tls_parse_session_ticket_extension(char *payload,
    bd_tls_client *client);
static void bd_tls_parse_support_versions_extension(char *payload,
    std::list<uint16_t> *supported_versions);
static void bd_tls_parse_x509_certificate(char *payload, std::list<X509 *>
    *certificates, uint32_t remaining);

static int bd_tls_generate_server_ja3_md5(bd_tls_server *server);
static int bd_tls_generate_client_ja3_md5(bd_tls_client *client);

static bool bd_tls_is_handshake_encrypted(char *payload);

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

    handshake->tls_resumed = 0;
    handshake->client = NULL;
    handshake->server = NULL;
    handshake->server_done = 0;
    handshake->client_certificate_requested = 0;
    handshake->finished_messages = 0;
    handshake->complete = 0;

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
        /* bd_tls_generate_client_ja3_md5 returns 0 on success, 1
         * on error. return NULL if a error occured */
        if (bd_tls_generate_client_ja3_md5(handshake->client)) {
            return NULL;
        }
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
        /* bd_tls_generate_server_ja3_md5 returns 0 on success, 1
         * on error. return NULL if a error occured */
        if (bd_tls_generate_server_ja3_md5(handshake->server)) {
            return NULL;
        }
    }

    return handshake->server->ja3_md5;
}
int bd_tls_flow(Flow *flow) {

    bd_tls_handshake *handshake;

    handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return 0;
    }

    /* only count this as a tls flow if both client and server hello
     * has been seen */
    if (handshake->client != NULL && handshake->server != NULL) {
        return 1;
    }

    return 0;

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
char *bd_tls_get_client_extension_sni(Flow *flow) {

    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return NULL;
    }
    if (handshake->client == NULL) {
        return NULL;
    }
    return handshake->client->extension_sni;
}
uint16_t bd_tls_get_server_hello_version(Flow *flow) {

    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return 0;
    }
    if (handshake->server == NULL) {
        return 0;
    }
    return handshake->server->version;
}
uint16_t bd_tls_get_client_hello_version(Flow *flow) {

    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return 0;
    }
    if (handshake->client == NULL) {
        return 0;
    }
    return handshake->client->version;
}
uint16_t bd_tls_get_server_selected_cipher(Flow *flow) {

    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return 0;
    }
    if (handshake->server == NULL) {
        return 0;
    }
    return handshake->server->cipher;
}
uint8_t bd_tls_get_server_selected_compression(Flow *flow) {

    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return 0;
    }
    if (handshake->server == NULL) {
        return 0;
    }
    return handshake->server->compression_method;
}
const std::list<uint16_t> *bd_tls_get_client_supported_ciphers(Flow *flow) {

    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return NULL;
    }
    if (handshake->client == NULL) {
        return NULL;
    }
    return handshake->client->ciphers;
}
const std::list<uint8_t> *bd_tls_get_client_supported_compression(Flow *flow) {

    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return NULL;
    }
    if (handshake->client == NULL) {
        return NULL;
    }
    return handshake->client->compression_methods;
}
uint16_t bd_tls_get_version(Flow *flow) {

    /* The version decided for the tls session is normally sent.
     * in the tls server hello. */
    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return 0;
    }
    if (handshake->server == NULL) {
        return 0;
    }

    /* check if the tls extension versions exists, return version
     * number within that if it does. This is new to tls 1.3 */
    if (handshake->server->extension_version != 0) {
        return handshake->server->extension_version;
    }

    return handshake->server->version;
}
int bd_tls_server_done(Flow *flow) {

    bd_tls_handshake *handshake;

    handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return -1;
    }

    return handshake->server_done;
}
int bd_tls_client_certificate_requested(Flow *flow) {

    bd_tls_handshake *handshake;

    handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return -1;
    }

    return handshake->client_certificate_requested;
}
int bd_tls_handshake_complete(Flow *flow) {

    bd_tls_handshake *handshake;

    handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return -1;
    }

    return handshake->complete;
}

/* X509 certificate API functions */
const std::list<X509 *> *bd_tls_get_x509_server_certificates(Flow *flow) {
    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return NULL;
    }
    if (handshake->server == NULL) {
        return NULL;
    }
    return handshake->server->certificates;
}
const std::list<X509 *> *bd_tls_get_x509_client_certificates(Flow *flow) {
    bd_tls_handshake *handshake = bd_tls_get_handshake(flow);
    if (handshake == NULL) {
        return NULL;
    }
    if (handshake->client == NULL) {
        return NULL;
    }
    return handshake->client->certificates;
}
char *bd_tls_get_x509_subject(X509 *cert) {
    char *subject = X509_NAME_oneline(
        X509_get_subject_name(cert), NULL, 0);

    return subject;
}
void bd_tls_free_x509_subject(char *subject) {
    OPENSSL_free(subject);
}
const unsigned char *bd_tls_get_x509_common_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 0, NID_commonName);
}
const unsigned char *bd_tls_get_x509_country_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 0, NID_countryName);
}
const unsigned char *bd_tls_get_x509_locality_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 0, NID_localityName);
}
const unsigned char *bd_tls_get_x509_state_or_province_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 0, NID_stateOrProvinceName);
}
const unsigned char *bd_tls_get_x509_organization_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 0, NID_organizationName);
}
const unsigned char *bd_tls_get_x509_organization_unit_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 0, NID_organizationalUnitName);
}
char *bd_tls_get_x509_issuer(X509 *cert) {
    char *issuer = X509_NAME_oneline(
        X509_get_issuer_name(cert), NULL, 0);

    return issuer;
}
void bd_tls_free_x509_issuer(char *issuer) {
    OPENSSL_free(issuer);
}
const unsigned char *bd_tls_get_x509_issuer_common_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 1, NID_commonName);
}
const unsigned char *bd_tls_get_x509_issuer_country_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 1, NID_countryName);
}
const unsigned char *bd_tls_get_x509_issuer_locality_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 1, NID_localityName);
}
const unsigned char *bd_tls_get_x509_issuer_state_or_province_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 1, NID_stateOrProvinceName);
}
const unsigned char *bd_tls_get_x509_issuer_organization_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 1, NID_organizationName);
}
const unsigned char *bd_tls_get_x509_issuer_organization_unit_name(X509 *cert) {
    return bd_tls_get_subject_NID(cert, 1, NID_organizationalUnitName);
}
static const unsigned char *bd_tls_get_subject_NID(X509 *cert, int issuer,
    int nid) {

    X509_NAME *nme;
    if (issuer) {
        nme = X509_get_issuer_name(cert);
    } else {
        nme = X509_get_subject_name(cert);
    }

    int lastpos = -1;
    X509_NAME_ENTRY *e;
    for (;;) {
        lastpos = X509_NAME_get_index_by_NID(nme, nid,
            lastpos);
        if (lastpos == -1) {
            break;
        }
        e = X509_NAME_get_entry(nme, lastpos);
        ASN1_STRING *d = X509_NAME_ENTRY_get_data(e);
        return ASN1_STRING_get0_data(d);
    }
    return NULL;
}
std::list<char *> *bd_tls_get_x509_alt_names(X509 *cert) {
    std::list<char *> *altnames =
        new std::list<char *>;
    STACK_OF(GENERAL_NAME) *san_names;
    san_names = (stack_st_GENERAL_NAME *)X509_get_ext_d2i(
        cert, NID_subject_alt_name, NULL, NULL);
    if (!san_names) {
        delete(altnames);
        return NULL;
    }
    int numalts = sk_GENERAL_NAME_num(san_names);
    for (int i = 0; i < numalts; i++) {
        const GENERAL_NAME *current_name = sk_GENERAL_NAME_value(san_names, i);

        if (current_name->type == GEN_DNS) {

            char *dns_name = (char *)ASN1_STRING_get0_data(current_name->d.dNSName);

            // Make sure there isn't an embedded NUL character in the DNS name
            if ((size_t)ASN1_STRING_length(current_name->d.dNSName) != strlen(dns_name)) {
                break;
            } else {
                altnames->push_back(strdup(dns_name));
            }
        }
    }
    sk_GENERAL_NAME_pop_free(san_names, GENERAL_NAME_free);
    return altnames;
}
void bd_tls_free_x509_alt_names(std::list<char *> *altnames) {
    if (altnames != NULL) {
        std::list<char *>::const_iterator it;
        for (it = altnames->begin(); it != altnames->end(); it++) {
            free(*it);
        }
        delete(altnames);
    }
}
int bd_tls_get_x509_version(X509 *cert) {
    if (cert == NULL) {
        return -1;
    }
    /* the version is zero-indexed. hence + 1 */
    return ((int) X509_get_version(cert)) + 1;
}
char *bd_tls_get_x509_serial(X509 *cert, char *space, int spacelen) {
    ASN1_INTEGER *serial = X509_get_serialNumber(cert);

    BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
    if (bn == NULL) {
        return NULL;
    }

    char *tmp = BN_bn2dec(bn);
    if (tmp == NULL) {
        BN_free(bn);
        return NULL;
    }

    if (space == NULL) {
        spacelen = strlen(tmp);
        space = (char *)malloc(spacelen+1);
        if (space == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. "
                "bd_tls_get_x509_serial()");
            exit(BD_OUTOFMEMORY);
        }
    }

    strncpy(space, tmp, spacelen);
    space[spacelen] = '\0';

    BN_free(bn);
    OPENSSL_free(tmp);

    return space;
}
void bd_tls_free_x509_serial(char *serial) {
    free(serial);
}
char *bd_tls_get_x509_sha1_fingerprint(X509 *cert, char *space,
    int spacelen) {

    char buf[20];
    bool alloc_space = 0;

    if (space == NULL) {
        spacelen = (2*X509_SHA1LEN+1);
        space = (char *)malloc(spacelen);
        if (space == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. "
                "bd_tls_get_x509_sha1_fingerprint()");
            exit(BD_OUTOFMEMORY);
        }
        alloc_space = 1;
    }

    /* supplied space to small */
    if (spacelen < (2*X509_SHA1LEN+1)) {
        return NULL;
    }

    const EVP_MD *digest = EVP_sha1();
    unsigned len;

    int rc = X509_digest(cert, digest, (unsigned char *)buf, &len);
    if (rc == 0 || len != 20) {
        if (alloc_space) {
            free(space);
        }
        return NULL;
    }

    /* convert to human readable hex */
    for (size_t i = 0; i < X509_SHA1LEN; i++) {
        sprintf((char *)space+(i*2), "%02x", buf[i] & 0xff);
    }

    /* add the null terminator to the end of the string */
    space[40] = '\0';

    return space;
}
void bd_tls_free_x509_sha1_fingerprint(char *sha1) {
    free(sha1);
}
char *bd_tls_get_x509_not_before(X509 *cert, char *space, int spacelen) {

    bool alloc_space = 0;

    if (cert == NULL) {
        logger(LOG_WARNING, "NULL X509 certificate. func. "
            "bd_tls_get_x509_not_before()");
        return NULL;
    }

    if (space == NULL) {
        spacelen = X509_ISO_DATELEN;
        space = (char *)malloc(X509_ISO_DATELEN);
        if (space == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. "
                "bd_tls_get_x509_not_before()");
            exit(BD_OUTOFMEMORY);
        }
        alloc_space = 1;
    }

    if (spacelen > X509_ISO_DATELEN) {
        return NULL;
    }

    ASN1_TIME *not_before = X509_get_notBefore(cert);

    if (bd_tls_convert_x509_asn1time(not_before, space, spacelen)) {
        if (alloc_space) {
            free(space);
        }
        return NULL;
    }

    return space;
}
char *bd_tls_get_x509_not_after(X509 *cert, char *space, int spacelen) {

    bool alloc_space = 0;

    if (cert == NULL) {
        logger(LOG_WARNING, "NULL X509 certificate. func. "
            "bd_tls_get_x509_not_after()");
        return NULL;
    }

    if (space == NULL) {
        spacelen = X509_ISO_DATELEN;
        space = (char *)malloc(X509_ISO_DATELEN);
        if (space == NULL) {
            logger(LOG_CRIT, "Unable to allocate memory. func. "
                "bd_tls_get_x509_not_after()");
            exit(BD_OUTOFMEMORY);
        }
        alloc_space = 1;
    }

    if (spacelen < X509_ISO_DATELEN) {
        return NULL;
    }

    ASN1_TIME *not_after = X509_get_notAfter(cert);

    if (bd_tls_convert_x509_asn1time(not_after, space, spacelen)) {
        if (alloc_space) {
            free(space);
        }
        return NULL;
    }

    return space;
}
static int bd_tls_convert_x509_asn1time(ASN1_TIME *t, char *buf,
    size_t len) {

    int rc;
    BIO *b = BIO_new(BIO_s_mem());
    rc = ASN1_TIME_print(b, t);
    if (rc <= 0) {
        BIO_free(b);
        return 1;
    }
    rc = BIO_gets(b, buf, len);
    if (rc <= 0) {
        BIO_free(b);
        return 1;
    }
    BIO_free(b);

    return 0;
}
int bd_tls_get_x509_ca_status(X509 *cert) {

    if (cert == NULL) {
        return -1;
    }

    return X509_check_ca(cert);
}
int bd_tls_get_x509_public_key_size(X509 *cert) {
    EVP_PKEY *pkey = X509_get_pubkey(cert);

    int key_type = EVP_PKEY_base_id(pkey);
    int keysize = -1;

    switch (key_type) {
        case EVP_PKEY_RSA: {
            RSA *r = EVP_PKEY_get0_RSA(pkey);
            const BIGNUM *n, *e, *d;
            RSA_get0_key(r, &n, &e, &d);
            keysize = BN_num_bits(n);
            break;
        }
        case EVP_PKEY_DSA: {
            DSA *d = EVP_PKEY_get0_DSA(pkey);
            const BIGNUM *p, *q, *g;
            DSA_get0_pqg(d, &p, &q, &g);
            keysize =BN_num_bits(p);
            break;
        }
        case EVP_PKEY_DH: {
            DH *h = EVP_PKEY_get0_DH(pkey);
            const BIGNUM *p, *q, *g;
            DH_get0_pqg(h, &p, &q, &g);
            keysize = BN_num_bits(p);
            break;
        }
        case EVP_PKEY_EC: {
            EC_KEY *e = EVP_PKEY_get0_EC_KEY(pkey);
            const EC_GROUP *ecg = EC_KEY_get0_group(e);
            keysize = EC_GROUP_get_degree(ecg);
            break;
        }
        default:
            break;
    }

    EVP_PKEY_free(pkey);

    return keysize;
}
const char *bd_tls_get_x509_signature_algorithm(X509 *cert) {

    if (cert == NULL) {
        return NULL;
    }

    int pkey_nid = X509_get_signature_nid(cert);
    if (pkey_nid == NID_undef) {
        return NULL;
    }

    return OBJ_nid2ln(pkey_nid);
}
const char *bd_tls_get_x509_public_key_algorithm(X509 *cert) {

    if (cert == NULL) {
        return NULL;
    }

    EVP_PKEY *pkey = X509_get_pubkey(cert);
    int key_type = EVP_PKEY_base_id(pkey);
    EVP_PKEY_free(pkey);

    switch (key_type) {
        case EVP_PKEY_RSA:
            return "RSA";
        case EVP_PKEY_DSA:
            return "DSA";
        case EVP_PKEY_DH:
            return "DH";
        case EVP_PKEY_EC:
            return "ECC";
        default:
            return NULL;
    }
}
int bd_tls_validate_certificate(X509 *cert, const char *hostname) {

    bool match = 0;

    /* get the certificates common name */
    const char *cname = (const char *)bd_tls_get_x509_common_name(cert);
    if (cname != NULL) {
        /* check common name for a match */
        //if (Curl_cert_hostcheck(cname, hostname) == CURL_HOST_MATCH) {
        //    return 1;
        //}
    }

    std::list<char *> *altnames = bd_tls_get_x509_alt_names(cert);
    if (altnames != NULL) {
        std::list<char *>::iterator it;
        for (it = altnames->begin(); it != altnames->end(); it++) {
            /* check each alt name for a match */
            //if (Curl_cert_hostcheck(*it, hostname) == CURL_HOST_MATCH) {
            //    match = 1;
            //    continue;
            //}
        }
    }
    bd_tls_free_x509_alt_names(altnames);

    return match;
}

int bd_tls_update(bd_bigdata_t *bigdata, bd_tls_handshake *tls_handshake) {

    void *layer3;
    char *payload = NULL;
    uint8_t proto;
    uint16_t ethertype;
    uint32_t remaining = 0;
    bd_tls_hdr *hdr;
    uint16_t tls_version;

    layer3 = trace_get_layer3(bigdata->packet, &ethertype, &remaining);
    /* make sure layer3 was found. */
    if (layer3 == NULL || remaining == 0) {
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
    if (payload == NULL || remaining == 0) {
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

    tls_version = ntohs(*(uint16_t *)(payload+1));
    /* make sure packet is a supported tls version */
    if (tls_version != SSL_30 &&
        tls_version != TLS_10 &&
        tls_version != TLS_11 &&
        tls_version != TLS_12 &&
        tls_version != TLS_13) {

        return 0;
    }

    /* loop over each tls protocol in the packet */
    while (remaining > 0) {

        hdr = (bd_tls_hdr *)payload;

        /* first make sure enough data remains to contain the tls header. */
        if (remaining < sizeof(bd_tls_hdr)) {
            return 0;
        }

        /* now make sure the amount of remaining data is enough to hold
         * the full tls message.
         */
        if (remaining < (ntohs(hdr->length) + sizeof(bd_tls_hdr))) {
            return 0;
        }

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
                         if (tls_handshake->client == NULL) {
                             tls_handshake->client =
                                 bd_tls_parse_client_hello(bigdata,
                                      remaining-5, payload+5);
                         }
                         break;
                     }
                     case TLS_HANDSHAKE_SERVER_HELLO: {
                         if (tls_handshake->server == NULL) {
                             tls_handshake->server =
                                 bd_tls_parse_server_hello(bigdata,
                                      remaining-5, payload+5);
                         }
                         break;
                     }
                     case TLS_HANDSHAKE_CERTIFICATE: {
                         /* tls certificates in tls 1.3 are encrypted
                          * so ignore them. */
                         if (bd_tls_get_version(bigdata->flow) != TLS_13) {

                             /* did this packet originate from the server? */
                             int srv_pkt = bd_flow_is_server_packet(bigdata);

                             if (srv_pkt && tls_handshake->server != NULL) {
                                 bd_tls_parse_x509_certificate(payload+5,
                                     tls_handshake->server->certificates,
                                     remaining-5);
                                 break;
                             }

                             if (!srv_pkt && tls_handshake->client != NULL) {
                                 bd_tls_parse_x509_certificate(payload+5,
                                     tls_handshake->client->certificates,
                                     remaining-5);
                                 break;
                             }
                         }

                         break;
                     }
                     case TLS_HANDSHAKE_SERVER_KEY_EXCHANGE:
                         break;
                     case TLS_HANDSHAKE_CERTIFICATE_REQUEST:
                         tls_handshake->client_certificate_requested = 1;
                         break;
                     case TLS_HANDSHAKE_SERVER_DONE:
                         tls_handshake->server_done = 1;
                         break;
                     case TLS_HANDSHAKE_CERTIFICATE_VERIFY:
                         break;
                     case TLS_HANDSHAKE_CLIENT_KEY_EXCHANGE:
                         break;
                     case TLS_HANDSHAKE_FINISHED:
                         tls_handshake->finished_messages += 1;
                         break;
                     default: {
                         break;
                     }
                }

                break;
            }

            case TLS_PACKET_APPLICATION_DATA: {
                /* safe to say the handshake is complete if application data
                 * is being exchanged? */
                tls_handshake->complete = 1;
                break;
            }

            default: {
                break;
            }
        }

        /* reduce the remaining payload and move the payload pointer
         * forward */
        remaining -= (ntohs(hdr->length) + sizeof(bd_tls_hdr));
        payload += (ntohs(hdr->length) + sizeof(bd_tls_hdr));
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
    server->extension_version = 0;

    server->certificates = new std::list<X509 *>;

    server->ja3_md5 = NULL;

    return server;
}

static void bd_tls_server_destroy(bd_tls_server *server) {

    if (server == NULL) {
     return;
    }

    delete(server->extensions);

    std::list<X509 *>::iterator it;
    for (it = server->certificates->begin();
        it != server->certificates->end(); it++) {

        X509_free(*it);
    }
    delete(server->certificates);

    if (server->ja3_md5 != NULL) {
        free(server->ja3_md5);
        server->ja3_md5 = NULL;
    }

    free(server);
}

static bd_tls_server *bd_tls_parse_server_hello(bd_bigdata_t *bigdata,
    uint16_t remaining, char *payload) {

    bd_tls_server *server;
    bd_tls_hndske_hlo_hdr *hdr;
    bd_tls_ext_hdr *ext;
    uint16_t length;
    uint16_t extensions_len;
    uint16_t extension_len;
    uint16_t extension;
    int i;

    /* ensure this handshake message is not encrypted */
    if (bd_tls_is_handshake_encrypted(payload)) {
        return NULL;
    }

    hdr = (bd_tls_hndske_hlo_hdr *)payload;

    /* calculate length of the hello message */
    length = hdr->length[0] << 16 | hdr->length[1] << 8 |
        hdr->length[2];

    /* create the server hello structure */
    server = bd_tls_server_create();

    server->version = ntohs(hdr->version);

    /* move to the cipher */
    payload += sizeof(bd_tls_hndske_hlo_hdr) +
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

        switch (extension) {
            case TLS_EXTENSION_SUPPORTED_VERSIONS:
                server->extension_version =
                    ntohs(*(uint16_t *)(payload+4));
                break;
        }

        /* reduce extensions length by the length of this
         * extension including its header. */
        extensions_len -= (extension_len + sizeof(bd_tls_ext_hdr));
        /* advance payload forward to the next extension */
        payload += (extension_len + sizeof(bd_tls_ext_hdr));
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
    client->compression_methods = new std::list<uint8_t>;
    client->extensions = new std::list<uint16_t>;
    client->ciphers = new std::list<uint16_t>;
    client->ec_curves = new std::list<uint16_t>;
    client->ec_points = new std::list<uint16_t>;

    client->extension_versions = new std::list<uint16_t>;

    client->certificates = new std::list<X509 *>;

    client->extension_sni = NULL;
    client->ja3_md5 = NULL;

    return client;
}

static void bd_tls_client_destroy(bd_tls_client *client) {

    if (client == NULL) {
        return;
    }

    delete(client->compression_methods);
    delete(client->extensions);
    delete(client->ciphers);
    delete(client->ec_curves);
    delete(client->ec_points);

    delete(client->extension_versions);

    std::list<X509 *>::iterator it;
    for (it = client->certificates->begin();
        it != client->certificates->end(); it++) {

        X509_free(*it);
    }
    delete(client->certificates);

    if (client->extension_sni != NULL) {
        free(client->extension_sni);
        client->extension_sni = NULL;
    }

    if (client->ja3_md5 != NULL) {
        free(client->ja3_md5);
        client->ja3_md5 = NULL;
    }

    free(client);
}

static bd_tls_client *bd_tls_parse_client_hello(bd_bigdata_t *bigdata,
    uint16_t remaining, char *payload) {

    bd_tls_client *client;
    bd_tls_hndske_hlo_hdr *hdr;
    uint32_t length;
    uint16_t num_ciphers;
    uint16_t cipher_len;
    uint16_t extensions_len;
    uint16_t extension;
    uint16_t extension_len;
    uint8_t compression_methods_len;
    int i = 0;

    /* ensure this handshake message is not encrypted */
    if (bd_tls_is_handshake_encrypted(payload)) {
        return NULL;
    }

    hdr = (bd_tls_hndske_hlo_hdr *)payload;

    /* calculate length of the hello message */
    length = hdr->length[0] << 16 | hdr->length[1] << 8 |
        hdr->length[2];

    /* create the client */
    client = bd_tls_client_create();

    /* get the clients tls version */
    client->version = ntohs(hdr->version);

    /* advance the payload pointer to the ciphers length */
    payload += sizeof(bd_tls_hndske_hlo_hdr) +
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

    /* should now be at the compression methods length */
    compression_methods_len = *(uint8_t *)payload;
    /* move to the first compression method */
    payload += 1;

    /* copy over each compression method */
    for (i = 0; i < compression_methods_len; i++) {
        client->compression_methods->push_back(
            *(uint8_t *)payload);
        /* move to the next compression method */
        payload += 1;
    }

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
                bd_tls_parse_session_ticket_extension(payload,
                    client);
                break;
            }
            case TLS_EXTENSION_SUPPORTED_VERSIONS: {
                bd_tls_parse_support_versions_extension(payload,
                    client->extension_versions);
                break;
            }
            case TLS_EXTENSION_ENCRYPTED_SERVER_NAME: {
                if (client->extension_sni == NULL) {
                    client->extension_sni = strdup("encrypted sni");
                    if (client->extension_sni == NULL) {
                        logger(LOG_CRIT, "Unable to allocate memory. func."
                            "bd_tls_parse_client_hello()");
                        exit(BD_OUTOFMEMORY);
                    }
                }
                break;
            }
            default: {
                /* dont know this extension move to next */
                break;
            }
        }

        /* reduce extensions length by the length of this
         * extension including its header. */
        extensions_len -= (extension_len + 4);
        /* advance payload forward to the next extension */
        payload += (extension_len + 4);
    }

    return client;
}

static int bd_tls_generate_server_ja3_md5(bd_tls_server *server) {

    char ja3[BD_TLS_JA3_LEN] = "\0";
    char buf[BD_TLS_BUF_LEN] = "\0";
    char extensions[BD_TLS_EXT_LEN] = "\0";
    unsigned char md5[16] = "\0";
    char md5string[33] = "\0";
    std::list<uint16_t>::iterator it;

    if (server == NULL) {
        logger(LOG_DEBUG, "NULL bd_tls_server structure. func. "
            "bd_tls_generate_server_ja3_md5()");
        return 1;
    }

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
    if (snprintf(ja3, sizeof(ja3), "%u,%u,%s",
        server->version,
        server->cipher,
        extensions) < 0) {

        logger(LOG_WARNING, "JA3 string buffer to small. func. "
            "bd_tls_generate_server_ja3_md5()");
        return 1;
    }

    /* run MD5 hash over it */
    MD5((const unsigned char *)ja3, strlen(ja3), md5);

    /* convert the integer rep from MD5 to hex */
    for(int i = 0; i < 16; ++i) {
        sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
    }

    server->ja3_md5 = strndup(md5string, 33);
    if (server->ja3_md5 == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "bd_tls_generate_server_ja3_md5()");
        exit(BD_OUTOFMEMORY);
    }

    return 0;
}

static int bd_tls_generate_client_ja3_md5(bd_tls_client *client) {

    char ja3[BD_TLS_JA3_LEN] = "\0";
    char ciphers[BD_TLS_CPHR_LEN] = "\0";
    char extensions[BD_TLS_EXT_LEN] = "\0";
    char ec_curves[BD_TLS_ECC_LEN] = "\0";
    char ec_points[BD_TLS_ECP_LEN] = "\0";
    char buf[BD_TLS_BUF_LEN] = "\0";
    unsigned char md5[16] = "\0";
    char md5string[33] = "\0";
    std::list<uint16_t>::iterator it;

    if (client == NULL) {
        logger(LOG_DEBUG, "NULL bd_tls_client structure. func. "
            "bd_tls_generate_client_ja3_md5()");
        return 1;
    }

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
    if (snprintf(ja3, sizeof(ja3), "%u,%s,%s,%s,%s",
        client->version,
        ciphers,
        extensions,
        ec_curves,
        ec_points) < 0) {

        logger(LOG_WARNING, "JA3 string buffer to small. func. "
            "bd_tls_generate_client_ja3_md5()");
        return 1;
    }

    /* run MD5 hash over it */
    MD5((const unsigned char *)ja3, strlen(ja3), md5);

    /* convert the integer rep from MD5 to hex */
    for(int i = 0; i < 16; ++i) {
        sprintf(&md5string[i*2], "%02x", (unsigned int)md5[i]);
    }

    client->ja3_md5 = strndup(md5string, 33);
    if (client->ja3_md5 == NULL) {
        logger(LOG_CRIT, "Unable to allocate memory. func. "
            "bd_tls_generate_client_ja3_md5()");
        exit(BD_OUTOFMEMORY);
    }

    return 0;
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

static void bd_tls_parse_session_ticket_extension(char *payload,
    bd_tls_client *client) {

    uint16_t len;

    len = ntohs(*(uint16_t *)(payload+2));

    /* move to the session ticket data */
    payload += 4;

    /* next len bytes contain the session tick data */

}

static void bd_tls_parse_support_versions_extension(char *payload,
    std::list<uint16_t> *supported_versions) {

    uint16_t len;
    int num_versions;
    int i;

    len = ntohs(*(uint16_t *)(payload+2));
    num_versions = *(uint8_t *)(payload+4) / 2;

    /* jump to the first version */
    payload += 5;
    for(i = 0; i < num_versions; i++) {
        /* push the version to the list */
        supported_versions->push_back(ntohs(*(uint16_t *)payload));

        /* move to the next version */
        payload += 2;
    }
}

static void bd_tls_parse_x509_certificate(char *payload, std::list<X509 *>
    *certificates, uint32_t remaining) {

    uint32_t len;
    uint32_t cert_len;
    uint32_t certs_len;
    X509 *cert;

    /* move to the length field */
    payload += 1;
    /* calculate length of the certificate message */
    len = *(uint8_t *)(payload) << 16 | *(uint8_t *)(payload+1) << 8 |
        *(uint8_t *)(payload+2);

    /* sometimes we are getting large incorrect lengths. ignore these */
    if (len > remaining) { return; }

    /* move to the certificates length */
    payload += 3;
    /* get the total certificates length */
    certs_len = *(uint8_t *)payload << 16 | *(uint8_t *)(payload+1) << 8 |
        *(uint8_t *)(payload+2);

    /* sometimes we are getting large incorrect lengths. ignore these */
    if (certs_len > remaining) { return; }

    /* move to the first certificate */
    payload += 3;

    while (certs_len > 0) {
        /* get the length of this certificate */
        cert_len = *(uint8_t *)payload << 16 | *(uint8_t *)(payload+1) << 8 |
            *(uint8_t *)(payload+2);

        /* sometimes we are getting large incorrect lengths. ignore these */
        if (cert_len > remaining) { return; }

        /* move to the certificate */
        payload += 3;

        /* if the certificate is successfully parsed insert it into the list.
         * NOTE:/ d21_X509 advances payload past the certificate. */
        if ((cert = d2i_X509(NULL, (const unsigned char **)&payload, cert_len))) {

            certificates->push_back(cert);
        }

        /* reduce size of remaining certificates */
        certs_len -= (cert_len + 3);
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
                if (client->extension_sni == NULL) {
                    client->extension_sni = strndup((payload+5),
                        name_len);

                    if (client->extension_sni == NULL) {
                        logger(LOG_CRIT, "Unable to allocate memory. func. "
                            "bd_tls_parse_server_name_extension()");
                        exit(BD_OUTOFMEMORY);
                    }
                }
                break;
            }
        }

        payload += (list_len + 2);
        len -= (list_len + 2);
    }
}

static bool bd_tls_is_handshake_encrypted(char *payload) {

    uint16_t tls_version = ntohs(*(uint16_t *)(payload+4));

    /* if the tls version is one we are expecting its highly
     * unlikely this handshake is encrypted */
    if (tls_version != SSL_30 &&
        tls_version != TLS_10 &&
        tls_version != TLS_11 &&
        tls_version != TLS_12 &&
        tls_version != TLS_13) {

        return 1;
    }

    return 0;
}

const char *bd_tls_cipher_to_string(uint16_t cipher) {
    switch (cipher) {
        case TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256";
        case TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256";
        case TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384";
        case TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384";
        case TLS_DHE_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256";
        case TLS_DHE_DSS_WITH_AES_128_GCM_SHA256:
            return "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256";
        case TLS_DHE_DSS_WITH_AES_256_GCM_SHA384:
            return "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384";
        case TLS_DHE_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384";
        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256";
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256";
        case TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA";
        case TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA";
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384:
            return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384";
        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384";
        case TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA";
        case TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA";
        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256";
        case TLS_DHE_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_DHE_RSA_WITH_AES_128_CBC_SHA";
        case TLS_DHE_DSS_WITH_AES_128_CBC_SHA256:
            return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256";
        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA256:
            return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256";
        case TLS_DHE_DSS_WITH_AES_256_CBC_SHA:
            return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA";
        case TLS_DHE_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_DHE_RSA_WITH_AES_256_CBC_SHA";
        case TLS_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_RSA_WITH_AES_128_GCM_SHA256";
        case TLS_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_RSA_WITH_AES_256_GCM_SHA384";
        case TLS_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_RSA_WITH_AES_128_CBC_SHA256";
        case TLS_RSA_WITH_AES_256_CBC_SHA256:
            return "TLS_RSA_WITH_AES_256_CBC_SHA256";
        case TLS_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_RSA_WITH_AES_128_CBC_SHA";
        case TLS_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_RSA_WITH_AES_256_CBC_SHA";
        case TLS_DH_DSS_WITH_AES_256_GCM_SHA384:
            return "TLS_DH_DSS_WITH_AES_256_GCM_SHA384";
        case TLS_DH_RSA_WITH_AES_256_GCM_SHA384:
            return "TLS_DH_RSA_WITH_AES_256_GCM_SHA384";
        case TLS_DHE_DSS_WITH_AES_256_CBC_SHA256:
            return "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256";
        case TLS_DH_RSA_WITH_AES_256_CBC_SHA256:
            return "TLS_DH_RSA_WITH_AES_256_CBC_SHA256";
        case TLS_DH_DSS_WITH_AES_256_CBC_SHA256:
            return "TLS_DH_DSS_WITH_AES_256_CBC_SHA256";
        case TLS_DH_RSA_WITH_AES_256_CBC_SHA:
            return "TLS_DH_RSA_WITH_AES_256_CBC_SHA";
        case TLS_DH_DSS_WITH_AES_256_CBC_SHA:
            return "TLS_DH_DSS_WITH_AES_256_CBC_SHA";
        case TLS_DH_DSS_WITH_AES_128_GCM_SHA256:
            return "TLS_DH_DSS_WITH_AES_128_GCM_SHA256";
        case TLS_DH_RSA_WITH_AES_128_GCM_SHA256:
            return "TLS_DH_RSA_WITH_AES_128_GCM_SHA256";
        case TLS_DH_RSA_WITH_AES_128_CBC_SHA256:
            return "TLS_DH_RSA_WITH_AES_128_CBC_SHA256";
        case TLS_DH_DSS_WITH_AES_128_CBC_SHA256:
            return "TLS_DH_DSS_WITH_AES_128_CBC_SHA256";
        case TLS_DHE_DSS_WITH_AES_128_CBC_SHA:
            return "TLS_DHE_DSS_WITH_AES_128_CBC_SHA";
        case TLS_DH_RSA_WITH_AES_128_CBC_SHA:
            return "TLS_DH_RSA_WITH_AES_128_CBC_SHA";
        case TLS_DH_DSS_WITH_AES_128_CBC_SHA:
            return "TLS_DH_DSS_WITH_AES_128_CBC_SHA";
        case TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA";
        case TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA";
        case TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA";
        case TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA";
        case TLS_RSA_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_RSA_WITH_CAMELLIA_256_CBC_SHA";
        case TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA";
        case TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA";
        case TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA";
        case TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA";
        case TLS_RSA_WITH_CAMELLIA_128_CBC_SHA:
            return "TLS_RSA_WITH_CAMELLIA_128_CBC_SHA";
        case TLS_RSA_WITH_3DES_EDE_CBC_SHA:
            return "TLS_RSA_WITH_3DES_EDE_CBC_SHA";
        case TLS_EMPTY_RENEGOTIATION_INFO_SCSV:
            return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV";
        case TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA:
            return "TLS_DH_ANON_WITH_CAMELLIA_256_CBC_SHA";
        case TLS_PSK_WITH_RC4_128_SHA:
            return "TLS_PSK_WITH_RC4_128_SHA";
        case TLS_PSK_WITH_3DES_EDE_CBC_SHA:
            return "TLS_PSK_WITH_3DES_EDE_CBC_SHA";
        case TLS_PSK_WITH_AES_128_CBC_SHA:
            return "TLS_PSK_WITH_AES_128_CBC_SHA";
        case TLS_PSK_WITH_AES_256_CBC_SHA:
            return "TLS_PSK_WITH_AES_256_CBC_SHA";
        case TLS_DHE_PSK_WITH_RC4_128_SHA:
            return "TLS_DHE_PSK_WITH_RC4_128_SHA";
        case TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA:
            return "TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA";
        case TLS_DHE_PSK_WITH_AES_128_CBC_SHA:
            return "TLS_DHE_PSK_WITH_AES_128_CBC_SHA";
        case TLS_DHE_PSK_WITH_AES_256_CBC_SHA:
            return "TLS_DHE_PSK_WITH_AES_256_CBC_SHA";
        case TLS_RSA_PSK_WITH_RC4_128_SHA:
            return "TLS_RSA_PSK_WITH_RC4_128_SHA";
        case TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA:
            return "TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA";
        case TLS_RSA_PSK_WITH_AES_128_CBC_SHA:
            return "TLS_RSA_PSK_WITH_AES_128_CBC_SHA";
        case TLS_RSA_PSK_WITH_AES_256_CBC_SHA:
            return "TLS_RSA_PSK_WITH_AES_256_CBC_SHA";
        case TLS_RSA_WITH_SEED_CBC_SHA:
            return "TLS_RSA_WITH_SEED_CBC_SHA";
        case TLS_DH_DSS_WITH_SEED_CBC_SHA:
            return "TLS_DH_DSS_WITH_SEED_CBC_SHA";
        case TLS_DH_RSA_WITH_SEED_CBC_SHA:
            return "TLS_DH_RSA_WITH_SEED_CBC_SHA";
        case TLS_DHE_DSS_WITH_SEED_CBC_SHA:
            return "TLS_DHE_DSS_WITH_SEED_CBC_SHA";
        case TLS_DHE_RSA_WITH_SEED_CBC_SHA:
            return "TLS_DHE_RSA_WITH_SEED_CBC_SHA";
        case TLS_DH_ANON_WITH_SEED_CBC_SHA:
            return "TLS_DH_ANON_WITH_SEED_CBC_SHA";
        case TLS_DH_ANON_WITH_AES_128_GCM_SHA256:
            return "TLS_DH_ANON_WITH_AES_128_GCM_SHA256";
        case TLS_DH_ANON_WITH_AES_256_GCM_SHA384:
            return "TLS_DH_ANON_WITH_AES_256_GCM_SHA384";
        case TLS_PSK_WITH_AES_128_GCM_SHA256:
            return "TLS_PSK_WITH_AES_128_GCM_SHA256";
        case TLS_PSK_WITH_AES_256_GCM_SHA384:
            return "TLS_PSK_WITH_AES_256_GCM_SHA384";
        case TLS_DHE_PSK_WITH_AES_128_GCM_SHA256:
            return "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256";
        case TLS_DHE_PSK_WITH_AES_256_GCM_SHA384:
            return "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384";
        case TLS_RSA_PSK_WITH_AES_128_GCM_SHA256:
            return "TLS_RSA_PSK_WITH_AES_128_GCM_SHA256";
        case TLS_RSA_PSK_WITH_AES_256_GCM_SHA384:
            return "TLS_RSA_PSK_WITH_AES_256_GCM_SHA384";
        case TLS_PSK_WITH_AES_128_CBC_SHA256:
            return "TLS_PSK_WITH_AES_128_CBC_SHA256";
        case TLS_PSK_WITH_AES_256_CBC_SHA384:
            return "TLS_PSK_WITH_AES_256_CBC_SHA384";
        case TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256:
            return "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256";
        case TLS_AES_128_GCM_SHA256:
            return "TLS_AES_128_GCM_SHA256";
        case TLS_AES_256_GCM_SHA384:
            return "TLS_AES_256_GCM_SHA384";
        case TLS_CHACHA20_POLY1305_SHA256:
            return "TLS_CHACHA20_POLY1305_SHA256";
        case TLS_AES_128_CCM_SHA256:
            return "TLS_AES_128_CCM_SHA256";
        case TLS_AES_128_CCM_8_SHA256:
            return "TLS_AES_128_CCM_8_SHA256";
        case TLS_RSA_WITH_AES_128_CCM_8:
            return "TLS_RSA_WITH_AES_128_CCM_8";
        case TLS_RSA_WITH_AES_256_CCM_8:
            return "TLS_RSA_WITH_AES_256_CCM_8";
        case TLS_DHE_RSA_WITH_AES_128_CCM_8:
            return "TLS_DHE_RSA_WITH_AES_128_CCM_8";
        case TLS_DHE_RSA_WITH_AES_256_CCM_8:
            return "TLS_DHE_RSA_WITH_AES_256_CCM_8";
        case TLS_PSK_WITH_AES_128_CCM:
            return "TLS_PSK_WITH_AES_128_CCM";
        case TLS_PSK_WITH_AES_256_CCM:
            return "TLS_PSK_WITH_AES_256_CCM";
        case TLS_DHE_PSK_WITH_AES_128_CCM:
            return "TLS_DHE_PSK_WITH_AES_128_CCM";
        case TLS_DHE_PSK_WITH_AES_256_CCM:
            return "TLS_DHE_PSK_WITH_AES_256_CCM";
        case TLS_PSK_WITH_AES_128_CCM_8:
            return "TLS_PSK_WITH_AES_128_CCM_8";
        case TLS_PSK_WITH_AES_256_CCM_8:
            return "TLS_PSK_WITH_AES_256_CCM_8";
        case TLS_PSK_DHE_WITH_AES_128_CCM_8:
            return "TLS_PSK_DHE_WITH_AES_128_CCM_8";
        case TLS_PSK_DHE_WITH_AES_256_CCM_8:
            return "TLS_PSK_DHE_WITH_AES_256_CCM_8";
        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM";
        case TLS_ECDHE_ECDSA_WITH_AES_256_CCM:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM";
        case TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8:
            return "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8";
        case TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8:
            return "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8";
        case TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        case TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256";
        case TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256";
        case TLS_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256";
        case TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
        case TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256";
        case TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256:
            return "TLS_RSA_PSK_WITH_CHACHA20_POLY1305_SHA256";
        default:
            return "UNKNOWN";
    }
}

const char *bd_tls_version_to_string(uint16_t version) {

    switch (version) {
        case SSL_30:
            return "SSL 3.0";
        case TLS_10:
            return "TLS 1.0";
        case TLS_11:
            return "TLS 1.1";
        case TLS_12:
            return "TLS 1.2";
        case TLS_13:
            return "TLS 1.3";
        default:
            return "unknown";
    }
}
