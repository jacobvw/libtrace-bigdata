#ifndef BIGDATA_TLS_H
#define BIGDATA_TLS_H

#include "bigdata.h"
#include <list>

/* structures used to describe a tls session */
typedef struct bigdata_tls_client {

    uint16_t version;

    std::list<uint8_t> *compression_methods;
    /* codes need to calculate ja3 */
    std::list<uint16_t> *extensions;
    std::list<uint16_t> *ciphers;
    std::list<uint16_t> *ec_curves;
    std::list<uint16_t> *ec_points;

    /* extension data */
    std::list<uint16_t> *extension_versions;

    char *ja3_md5;
    /* sni hostname */
    char *extension_sni;

} bd_tls_client;

typedef struct bigdata_tls_server {

    uint16_t version;
    uint16_t cipher;
    uint8_t compression_method;

    std::list<uint16_t> *extensions;
    uint16_t extension_version;

    char *ja3_md5;

} bd_tls_server;

typedef struct bigdata_tls_handshake {

    /* if this tls session has been resumed */
    bool tls_resumed;

    /* has a client hello been completed */
    bool client_hello_complete;
    bd_tls_client *client;

    /* has a server hello been completed */
    bool server_hello_complete;
    bd_tls_server *server;

    /* have we seen a server done tls message */
    bool server_done;

} bd_tls_handshake;

/* Create a tls structure to hold tls handshake information.
 *
 * @returns	bd_tls_handshake structure.
 */
bd_tls_handshake *bd_tls_handshake_create();

/* Update any state held by the tls handshake structure with the current packet.
 *
 * @params	bigdata - bigdata structure.
 *		bd_tls_handshake - tls handshake structure.
 * @returns	0 on success.
 *		-1 on error.
 */
int bd_tls_update(bd_bigdata_t *bigdata, bd_tls_handshake *tls_handshake);

/* Destroy a tls handshake structure created with bd_tls_handshake_create().
 *
 * @params	bd_tls_handshake - tls handshake structure to destroy.
 */
void bd_tls_handshake_destroy(bd_tls_handshake *handshake);

/* Checks if the flow is a tls flow.
 *
 * @params	flow - Libflowmanager flow.
 * @returns	1 if the flow is a tls flow.
 *		0 if the flow is NOT a tls flow.
 */
int bd_tls_flow(Flow *flow);

/* Get the ja3 md5 hash for the tls flow.
 *
 * @params	flow - Libflowmanager flow.
 * @returns	pointer to the ja3 md5 string for the flow. This memory
 *              handled by the application core and should NOT be free'd by the user.
 *		NULL on error or unknown.
 */
char *bd_tls_get_ja3_md5(Flow *flow);

/* Get the ja3s md5 hash for the tls flow.
 *
 * @params      flow - Libflowmanager flow.
 * @returns     pointer to the ja3s md5 string for the flow. This memory
 *              handled by the application core and should NOT be free'd by the user.
 *              NULL on error or unknown.
 */
char *bd_tls_get_ja3s_md5(Flow *flow);

/* Returns the tls handshake structure for the supplied flow.
 *
 * @params      flow - The flow.
 * @returns     pointer to the mod_tls_handshake structure for the flow.
 *              null on error.
 */
bd_tls_handshake *bd_tls_get_handshake(Flow *flow);

/* Returns the sni hostname seen inside the client tls hello message.
 * Note:/ TLS1.3 encrypts the sni so tls1.3 flows will return NULL.
 *
 * @params	flow - The flow.
 * @returns	pointer to the hostname seen inside the client hello. This memory
 *		is handled by the application core and should NOT be free'd by the user.
 *		NULL on error or unknown.
 */
char *bd_tls_get_client_extension_sni(Flow *flow);

uint16_t bd_tls_get_server_hello_version(Flow *flow);

uint16_t bd_tls_get_client_hello_version(Flow *flow);

uint16_t bd_tls_get_server_selected_cipher(Flow *flow);

uint8_t bd_tls_get_server_selected_compression(Flow *flow);

uint16_t bd_tls_get_version(Flow *flow);

std::list<uint16_t> *bd_tls_get_client_supported_ciphers(Flow *flow);

std::list<uint8_t> *bd_tls_get_client_supported_compression(Flow *flow);

const char *bd_tls_cipher_to_string(uint16_t cipher);

const char *bd_tls_version_to_string(uint16_t version);

#endif
