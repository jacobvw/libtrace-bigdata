CC=gcc
CFLAGS = -ISPCDNS/src
LDFLAGS = -LSPCDNS/src

main: spcdns.o bigdata.o
	$(CC) lib/module_dns_spcdns_codec.o lib/bigdata.o \
		-ltrace -lflowmanager -lyaml -lprotoident -lm -lstdc++ \
		-o bigdata -g

spcdns.o: lib/module_dns_spcdns_codec.c
	$(CC) lib/module_dns_spcdns_codec.c -c -o lib/module_dns_spcdns_codec.o -g


bigdata.o: lib/*.cc lib/*.c
	$(CC) lib/bigdata.cc -c -o lib/bigdata.o -g

clean:
	rm -rf lib/*.o
	rm -rf bigdata
