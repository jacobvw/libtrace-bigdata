CC=gcc

# LINK EVERYTHING TOGETHER
main: module_dns_spcdns_codec.o module_dns_spcdns_mappings.o module_dns.o bigdata_flow.o module_http.o module_influxdb.o bigdata.o module_statistics.o module_protocol_statistics.o bigdata_parser.o bigdata_resultset.o bigdata_callbacks.o module_cdn_statistics.o module_kafka.o
	$(CC) lib/module_dns_spcdns_codec.o lib/module_dns_spcdns_mappings.o \
		lib/module_dns.o \
		lib/bigdata_flow.o \
		lib/module_http.o \
		lib/module_influxdb.o \
		lib/bigdata.o \
		lib/module_statistics.o \
		lib/module_protocol_statistics.o \
		lib/bigdata_parser.o \
		lib/bigdata_resultset.o \
		lib/bigdata_callbacks.o \
		lib/module_cdn_statistics.o \
		lib/module_kafka.o \
		-ltrace -lflowmanager -lyaml -lprotoident -lm -lstdc++ -lcurl -lrdkafka\
		-o bigdata -g


# DNS MODULE
module_dns_spcdns_codec.o: lib/module_dns_spcdns_codec.c lib/module_dns_spcdns.h
	$(CC) lib/module_dns_spcdns_codec.c -c -o lib/module_dns_spcdns_codec.o -g

module_dns_spcdns_mappings.o: lib/module_dns_spcdns_mappings.c lib/module_dns_spcdns.h
	$(CC) lib/module_dns_spcdns_mappings.c -c -o lib/module_dns_spcdns_mappings.o -g

module_dns.o: lib/module_dns.cc lib/module_dns.h module_dns_spcdns_codec.o module_dns_spcdns_mappings.o
	$(CC) lib/module_dns.cc -c -o lib/module_dns.o -g

# HTTP MODULE
module_http.o: lib/module_http.cc lib/module_http.h
	$(CC) lib/module_http.cc -c -o lib/module_http.o -g

# INFLUXDB MODULE
module_influxdb.o: lib/module_influxdb.cc lib/module_influxdb.h
	$(CC) lib/module_influxdb.cc -c -o lib/module_influxdb.o -g

# KAFKA MODULE
module_kafka.o: lib/module_kafka.cc lib/module_kafka.h
	$(CC) lib/module_kafka.cc -c -o lib/module_kafka.o -g

# STATISTICS MODULE
module_statistics.o: lib/module_statistics.cc lib/module_statistics.h
	$(CC) lib/module_statistics.cc -c -o lib/module_statistics.o -g

# PROTOCOL STATISTICS MODULE
module_protocol_statistics.o: lib/module_protocol_statistics.cc lib/module_protocol_statistics.h
	$(CC) lib/module_protocol_statistics.cc -c -o lib/module_protocol_statistics.o -g

# CDN STATISTICS MODULE
module_cdn_statistics.o: lib/module_cdn_statistics.cc lib/module_cdn_statistics.h
	$(CC) lib/module_cdn_statistics.cc -c -o lib/module_cdn_statistics.o -g

# MAIN APPLICATION
bigdata.o: lib/bigdata.cc lib/bigdata.h
	$(CC) lib/bigdata.cc -c -o lib/bigdata.o -g

bigdata_flow.o: lib/bigdata_flow.cc lib/bigdata_flow.h
	$(CC) lib/bigdata_flow.cc -c -o lib/bigdata_flow.o -g

bigdata_parser.o: lib/bigdata_parser.cc lib/bigdata_parser.h
	$(CC) lib/bigdata_parser.cc -c -o lib/bigdata_parser.o -g

bigdata_resultset.o: lib/bigdata_resultset.cc lib/bigdata_resultset.h
	$(CC) lib/bigdata_resultset.cc -c -o lib/bigdata_resultset.o -g

bigdata_callbacks.o: lib/bigdata_callbacks.cc lib/bigdata_callbacks.h
	$(CC) lib/bigdata_callbacks.cc -c -o lib/bigdata_callbacks.o -g

clean:
	rm -rf lib/*.o
	rm -rf bigdata
