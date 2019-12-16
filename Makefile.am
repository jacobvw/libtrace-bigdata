DISTCHECK_CONFIGURE_FLAGS = \
        --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

SUBDIRS = lib
EXTRA_DIST = examples/config.yaml

AUTOMAKE_OPTIONS=foreign

if HAVE_DOXYGEN
SUBDIRS += docs
endif

if HAVE_SYSTEMD
SUBDIRS += systemd
endif

bigdataconfdir = $(sysconfdir)/bigdata
bigdataconf_DATA = examples/config.yaml

