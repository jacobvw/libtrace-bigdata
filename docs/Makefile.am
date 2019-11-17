if HAVE_DOXYGEN
directory = $(top_srcdir)/docs/doxygen/man/man3

dist_man_MANS = $(directory)/bd*.3 $(directory)/bigdata*.3

$(directory)/bd*.3: doxyfile.stamp
$(directory)/bigdata*.3: doxyfile.stamp

doxyfile.stamp:
	doxygen Doxyfile
	echo Timestamp > doxyfile.stamp

CLEANFILES = doxyfile.stamp

all-local: doxyfile.stamp
clean-local:
	rm -rf $(top_srcdir)/docs/man
endif
