#ifndef BIGDATA_TLS_H
#define BIGDATA_TLS_H

#include "bigdata.h"
#include <list>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bio.h>

/* structures used to describe a tls session */
typedef struct bigdata_tls_client {

    uint16_t version;

    std::list<uint8_t> *compression_methods;
    /* codes need to calculate ja3 */
    std::list<uint16_t> *extensions;
    std::list<uint16_t> *ciphers;
    std::list<uint16_t> *ec_curves;
    std::list<uint16_t> *ec_points;

    std::list<X509 *> *certificates;

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
    std::list<X509 *> *certificates;

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

/* Get the server tls hello version for the flow.
 *
 * @params	flow - the flow to get the tls server hello version from.
 * @returns	the server hello version on success.
 *		0 on error or unknown.
 */
uint16_t bd_tls_get_server_hello_version(Flow *flow);

/* Get the client tls hello version for the flow.
 *
 * @params	flow - the flow to get the the tls client hello version from.
 * @returns	the client hello version on success.
 *		0 on error or unknown.
 */
uint16_t bd_tls_get_client_hello_version(Flow *flow);

/* Get the server selected tls cipher for the flow.
 *
 * @params	flow - the flow to get the server selected tls
 *		tls cipher for.
 * @returns	the server selected cipher on success.
 *		0 on error or unknown.
 */
uint16_t bd_tls_get_server_selected_cipher(Flow *flow);

/* Get the server selected tls version for the flow.
 *
 * @params	flow - the flow to get the server selected tls
 *		version for.
 * @returns	the server selected tls version on success.
 *		0 on error or unknown.
 */
uint8_t bd_tls_get_server_selected_compression(Flow *flow);

/* Get the decided tls version for the flow.
 *
 * @params	flow - the flow to get the tls version for.
 * @returns	the tls version for the flow on success.
 *		0 on error or unknown.
 */
uint16_t bd_tls_get_version(Flow *flow);

/* Get the list of client supported ciphers for the flow.
 *
 * @params	flow - the flow to get the supported client ciphers
 *		from.
 * @returns	list of support client ciphers.
 */
const std::list<uint16_t> *bd_tls_get_client_supported_ciphers(Flow *flow);

/* Get the list of client supported compress methods for the flow.
 *
 * @params	flow - the flow to get the supported client compression
 *		algorithms from.
 * @returns	list of supported client compression
 *		algorithms.
 */
const std::list<uint8_t> *bd_tls_get_client_supported_compression(Flow *flow);

/* Convert the tls cipher number to its string representation.
 *
 * @params	cipher - the tls cipher version.
 * @returns	pointer to the ciphers string
 *		representaition.
 */
const char *bd_tls_cipher_to_string(uint16_t cipher);

/* Convert the tls version number to its string representation.
 *
 * @params	version - the tls version number.
 * @returns	const char *pointer to the versions string
 *		representation.
 */
const char *bd_tls_version_to_string(uint16_t version);

/* Get the list of all the server certificates seen for this flow.
 *
 * @params      flow - the flow to get server certificates for.
 * @returns     std::list<X509 *> list of pointers to each certificate.
 */
const std::list<X509 *> *bd_tls_get_x509_server_certificates(Flow *flow);

/* Get the list of all the client certificates seen for this flow.
 *
 * @params	flow - the flow to get client certificates for.
 * @returns	std::list<X509 *> list of pointers to each certificate.
 */
const std::list<X509 *> *bd_tls_get_x509_client_certificates(Flow *flow);

/* Get the subject for the X509 certificate.
 * Note: The subject must be free'd with bd_tls_free_x509_subject().
 *
 * @params	cert - the X509 certificate.
 * @returns	char * containing the certificate subject.
 */
char *bd_tls_get_x509_subject(X509 *cert);

/* Free the memory allocated by bd_tls_free_x509_subject.
 *
 * @params	subject - char *pointer to the subject.
 */
void bd_tls_free_x509_subject(char *subject);

/* Get the issuer for the X509 certificate.
 * Note: The issuer must be free'd with bd_tls_free_x509_issuer().
 *
 * @params	cert - the X509 certificate.
 * @returns	char * containing the issuer.
 */
char *bd_tls_get_x509_issuer(X509 *cert);

/* Free the memory allocated by bs_tls_get_x509_issuer.
 *
 * @params	issuer - char *pointer to the issuer.
 */
void bd_tls_free_x509_issuer(char *issuer);

/* Get the version of the X509 certificate.
 *
 * @params	cert - the X509 certificate.
 * @returns	version number on success.
 *		-1 on error.
 */
int bd_tls_get_x509_version(X509 *cert);

/* Get the serial number for the X509 certificate.
 * Note: If NULL is supplied for space dynamic memory will be
 * allocated and must be free'd with bd_tls_free_x509_serial().
 *
 * @params	cert - the X509 certificate.
 *		space - allocated space for the result.
 *		spacelen - the size of the allocated space.
 * @returns	char * containing the certificates serial number.
 */
char *bd_tls_get_x509_serial(X509 *cert, char *space, int spacelen);

/* Free the memory allocated by bd_tls_get_x509_serial().
 *
 * @params	serial - char *pointer to the serial number.
 */
void bd_tls_free_x509_serial(char *serial);

/* Get the country within the subject for the X509 certificate.
 * Note: This is an internal structure and should NOT be free'd or
 * modified in any way.
 *
 * @params	cert - the x509 certificate.
 * @returns	country from the certificate on success.
 *		NULL on error.
 */
const unsigned char *bd_tls_get_x509_country_name(X509 *cert);

/* Get the organization name within the subject for the X509 certificate.
 * Note: This is an internal structure and should NOT be free'd or
 * modified in any way.
 *
 * @params	cert - the x509 certificate.
 * @returns	organization from the certificate on success.
 *		NULL on error.
 */
const unsigned char *bd_tls_get_x509_organization_name(X509 *cert);

/* Get the organization unit name within the subject for the X509 certificate.
 * Note: This is a internal structure and should NOT be free'd or
 * modified in any way.
 *
 * @params	cert - the x509 certificate.
 * @returns	organization unit from the certificate on success.
 *		NULL on error.
 */
const unsigned char *bd_tls_get_x509_organization_unit_name(X509 *cert);

/* Get a list of common names within the subject for the X509 certificate.
 * Note: This is an internal structure and should NOT be free'd or
 * modified in any way. When finished pass the structure into
 * bd_tls_free_x509_common_names() for proper cleanup.
 *
 * @params	cert - the x509 certificate
 * @returns	list of common names on success.
 *		NULL on error.
 */
std::list<const unsigned char *> *bd_tls_get_x509_common_names(X509 *cert);

/* Free the memory allocated by bd_tls_get_x509_common_names().
 *
 * @params	list of common names allocated by bd_tls_get_x509_common_names().
 */
void bd_tls_free_x509_common_names(std::list<const unsigned char *> *cnames);

#endif
