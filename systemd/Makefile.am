if HAVE_SYSTEMD
systemdsystemunit_DATA = libtrace-bigdata.service

install-data-hook:
	${SED} -i 's|@bindir[@]|${bindir}/|g;s|@sysconfdir[@]|${sysconfdir}/|g' \
		${systemdsystemunitdir}/libtrace-bigdata.service

endif
