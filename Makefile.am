AUTOMAKE_OPTIONS = foreign
SUBDIRS = lib
EXTRA_DIST = examples

if HAVE_DOXYGEN
SUBDIRS += docs
endif

bigdataconfdir = $(sysconfdir)/bigdata
bigdataconf_DATA = examples/config.yaml

bigdatalogdir = $(localstatedir)/log/bigdata
