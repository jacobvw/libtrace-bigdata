typedef struct format_dns_header {
    uint16_t identified;

    /* look into byte ordering */
    uint16_t qr:1;
    uint16_t opcode:4;
    uint16_t aa:1;
    uint16_t tc:1;
    uint16_t rd:1;
    uint16_t ra:1;
    uint16_t z:1;
    uint16_t ad:1;
    uint16_t cd:1;
    uint16_t rcode:4;

    uint16_t total_questions;
    uint16_t total_answers_rrs;
    uint16_t total_authority_rrs;
    uint16_t total_additional_rrs;
} PACKED format_dns_header_t;

int format_dns_packet(libtrace_t *trace, libtrace_packet_t *packet) {
    fprintf(stderr, "DNS packet\n");
    return 1;

}

int format_dns_init() {
    ltbigdata_register_event(FILTER, (callback)format_dns_packet, "port 53");
}

int format_dns_get_record_type() {

}
