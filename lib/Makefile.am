
if HAVE_LIBRDKAFKA
KAFKASOURCE = module_kafka.cc module_kafka.h
else
KAFKASOURCE=
endif

if HAVE_MAXMINDDB
MAXMINDSOURCES = module_maxmind.cc module_maxmind.h
else
MAXMINDSOURCE =
endif

bin_PROGRAMS = bigdata
bigdata_SOURCES = bigdata.cc bigdata.h \
		bigdata_common.cc bigdata_common.h \
		bigdata_callbacks.cc bigdata_callbacks.h \
		bigdata_flow.cc bigdata_flow.h \
		bigdata_parser.cc bigdata_parser.h \
		bigdata_resultset.cc bigdata_resultset.h \
		bigdata_logger.cc bigdata_logger.h \
		bigdata_tls.cc bigdata_tls.h \
		module_dns.cc module_dns.h module_dns_spcdns.h module_dns_spcdns_codec.c \
		module_dns_spcdns_mappings.c module_dns_spcdns_mappings.h \
		module_protocol_statistics.cc module_protocol_statistics.h \
		module_statistics.cc module_statistics.h \
		module_flow_statistics.cc module_flow_statistics.h \
		module_influxdb.cc module_influxdb.h \
		module_elasticsearch.cc module_elasticsearch.h \
                module_http.cc module_http.h \
                module_http_picoparser.c module_http_picoparser.h \
                module_bgp.cc module_bgp.h \
                module_ja3.cc module_ja3.h \
		$(KAFKASOURCE) \
		$(MAXMINDSOURCES)
