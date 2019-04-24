CC=gcc
CFLAGS = -ISPCDNS/src
LDFLAGS = -LSPCDNS/src

main: spcdns_codec.o spcdns_mappings.o bigdata.o
	$(CC) lib/module_dns_spcdns_codec.o lib/module_dns_spcdns_mappings.o \
		lib/bigdata.o \
		-ltrace -lflowmanager -lyaml -lprotoident -lm -lstdc++ \
		-o bigdata -g

spcdns_codec.o: lib/module_dns_spcdns_codec.c
	$(CC) lib/module_dns_spcdns_codec.c -c -o lib/module_dns_spcdns_codec.o -g

spcdns_mappings.o: lib/module_dns_spcdns_mappings.c
	$(CC) lib/module_dns_spcdns_mappings.c -c -o lib/module_dns_spcdns_mappings.o -g

bigdata.o: lib/*.cc lib/*.c
	$(CC) lib/bigdata.cc -c -o lib/bigdata.o -g

clean:
	rm -rf lib/*.o
	rm -rf bigdata
