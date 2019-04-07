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

typedef struct format_dns_question {
    // name field n bytes?? how can i figure this out??
    //uint16_t type;
    //uint16_t class;
} PACKED format_dns_question_t;

typedef struct format_dns_local {

} format_dns_local_t;

int format_dns_starting(void *data) {
    // Gain access to thread local storage
    bigdata_local_t *local = (bigdata_local_t *)data;
    // insert some local storage into this
    return 1;
}

int format_dns_packet(libtrace_t *trace, libtrace_packet_t *packet, bd_record_t *data) {
    format_dns_header_t *hdr;
    libtrace_udp_t *udp;
    libtrace_tcp_t *tcp;
    uint32_t remaining;
    void *payload;

    // jump to the dns payload whether is be tcp or udp
    if ((udp = trace_get_udp(packet)) == NULL) {
        if ((tcp = trace_get_tcp(packet)) == NULL) {
            return 1;
        }
        payload = trace_get_payload_from_tcp(tcp, &remaining);
    } else {
        payload = trace_get_payload_from_udp(udp, &remaining);
    }

    hdr = (format_dns_header_t *)payload;

    fprintf(stderr, "dns packet request id %u to dst: %s\n", ntohs(hdr->identified),
        data->dst_ip);

    return 1;
}

int format_dns_ending(void *data) {

}

int format_dns_init() {
    bd_register_event(STARTING, (callback)format_dns_starting, NULL);
    bd_register_event(FILTER, (callback)format_dns_packet, "port 53");
    bd_register_event(STOPPING, (callback)format_dns_ending, NULL);
}
