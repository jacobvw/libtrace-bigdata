CC=gcc

# LINK EVERYTHING TOGETHER
main: module_dns_spcdns_codec.o module_dns_spcdns_mappings.o module_dns.o bigdata_flow.o module_http.o module_influxdb.o bigdata.o module_statistics.o module_flow_statistics.o bigdata_parser.o
	$(CC) lib/module_dns_spcdns_codec.o lib/module_dns_spcdns_mappings.o \
		lib/module_dns.o \
		lib/bigdata_flow.o \
		lib/module_http.o \
		lib/module_influxdb.o \
		lib/bigdata.o \
		lib/module_statistics.o \
		lib/module_flow_statistics.o \
                lib/bigdata_parser.o \
		-ltrace -lflowmanager -lyaml -lprotoident -lm -lstdc++ \
		-o bigdata -g


# DNS MODULE
module_dns_spcdns_codec.o: lib/module_dns_spcdns_codec.c lib/module_dns_spcdns.h
	$(CC) lib/module_dns_spcdns_codec.c -c -o lib/module_dns_spcdns_codec.o -g

module_dns_spcdns_mappings.o: lib/module_dns_spcdns_mappings.c lib/module_dns_spcdns.h
	$(CC) lib/module_dns_spcdns_mappings.c -c -o lib/module_dns_spcdns_mappings.o -g

module_dns.o: lib/module_dns.cc lib/module_dns.h module_dns_spcdns_codec.o module_dns_spcdns_mappings.o
	$(CC) lib/module_dns.cc -c -o lib/module_dns.o -g

# FLOW MODULE
bigdata_flow.o: lib/bigdata_flow.cc lib/bigdata_flow.h
	$(CC) lib/bigdata_flow.cc -c -o lib/bigdata_flow.o -g

# HTTP MODULE
module_http.o: lib/module_http.cc lib/module_http.h
	$(CC) lib/module_http.cc -c -o lib/module_http.o -g

# INFLUXDB MODULE
module_influxdb.o: lib/module_influxdb.cc lib/module_influxdb.h lib/module_influxdb_core.h
	$(CC) lib/module_influxdb.cc -c -o lib/module_influxdb.o -g

# STATISTICS MODULE
module_statistics.o: lib/module_statistics.cc lib/module_statistics.h
	$(CC) lib/module_statistics.cc -c -o lib/module_statistics.o -g

# FLOW STATISTICS MODULE
module_flow_statistics.o: lib/module_flow_statistics.cc lib/module_flow_statistics.h
	$(CC) lib/module_flow_statistics.cc -c -o lib/module_flow_statistics.o -g

bigdata_parser.o: lib/bigdata_parser.cc lib/bigdata_parser.h
	$(CC) lib/bigdata_parser.cc -c -o lib/bigdata_parser.o -g

# MAIN APPLICATION
bigdata.o: lib/bigdata.cc lib/bigdata.h
	$(CC) lib/bigdata.cc -c -o lib/bigdata.o -g

clean:
	rm -rf lib/*.o
	rm -rf bigdata
