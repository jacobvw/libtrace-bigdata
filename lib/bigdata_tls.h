#ifndef BIGDATA_TLS_H
#define BIGDATA_TLS_H

#include "bigdata.h"
#include <list>

/* structures used to describe a tls session */
typedef struct bigdata_tls_client {

    uint16_t version;

    /* codes need to calculate ja3 */
    std::list<uint16_t> *extensions;
    std::list<uint16_t> *ciphers;
    std::list<uint16_t> *ec_curves;
    std::list<uint16_t> *ec_points;

    char *ja3_md5;
    char *host_name;

} bd_tls_client;

typedef struct bigdata_tls_server {

    uint16_t version;
    uint16_t cipher;
    uint8_t compression_method;

    std::list<uint16_t> *extensions;

    char *ja3_md5;

} bd_tls_server;

typedef struct bigdata_tls_handshake {

    uint16_t version;
    char *version_protocol;
    uint16_t cipher;
    char *next_protocol;

    bd_tls_client *client;
    bd_tls_server *server;

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

/* Returns the hostname seen inside the the client tls hello message.
 *
 * @params	flow - The flow.
 * @returns	pointer to the hostname seen inside the client hello. This memory
 *		is handled by the application core and should NOT be free'd by the user.
 *		NULL on error or unknown.
 */
char *bd_tls_get_request_hostname(Flow *flow);

#endif
