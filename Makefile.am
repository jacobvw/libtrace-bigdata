DISTCHECK_CONFIGURE_FLAGS = \
        --with-systemdsystemunitdir=$$dc_install_base/$(systemdsystemunitdir)

SUBDIRS = lib etc

AUTOMAKE_OPTIONS=foreign

if HAVE_DOXYGEN
SUBDIRS += docs
endif

if HAVE_SYSTEMD
SUBDIRS += systemd
endif
