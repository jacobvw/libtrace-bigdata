int format_http_packet(libtrace_t *trace, libtrace_packet_t *packet, void *data) {
    fprintf(stderr, "HTTP packet\n");
    return 1;
}

int format_http_init() {
    bd_register_event(FILTER, (callback)format_http_packet, "port 80 or port 443");
}
