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

int bd_tls_update(bd_bigdata_t *bigdata, bd_tls_handshake *tls_handshake);

bd_tls_handshake *bd_tls_handshake_create();
void bd_tls_handshake_destroy(bd_tls_handshake *handshake);

char *bd_tls_get_ja3_md5(Flow *flow);
char *bd_tls_get_ja3s_md5(Flow *flow);

#endif
