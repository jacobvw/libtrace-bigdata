bigdataconfdir = $(sysconfdir)/bigdata
bigdataconf_DATA = config.yaml elasticsearch_template.json \
	ja3signatures.json

install-data-hook:
	${SED} -i 's|@sysconfdir[@]|${sysconfdir}|g' \
		$(sysconfdir)/bigdata/config.yaml
