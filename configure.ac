AC_PREREQ([2.69])
AC_INIT([libtrace-bigdata], [1.0], [jacobvw@icloud.com])
AC_CONFIG_SRCDIR([lib/bigdata.cc])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([subdir-objects])

# Make sure we use the relatively silent automake output
m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_GNU_SOURCE

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_MKDIR_P
AC_PROG_SED
PKG_PROG_PKG_CONFIG

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h syslog.h openssl/md5.h])

AC_CHECK_LIB([trace], [trace_pstart],,[AC_MSG_ERROR(Libtrace 4.0.1 or greater is required to compile Libtrace-bigdata)])
AC_CHECK_LIB([protoident], [lpi_get_category_by_protocol],,[AC_MSG_ERROR(Libprotoident 2.0.15 or greater is required to compile Libtrace-bigdata)])
AC_CHECK_LIB([yaml], [yaml_parser_initialize],,[AC_MSG_ERROR(Libyaml is required to compile Libtrace-bigdata)])
AC_CHECK_LIB([flowmanager], [lfm_version_three],,[AC_MSG_ERROR(Libflowmanager 3.0.0 or greater is required to compile Libtrace-bigdata)])
AC_CHECK_LIB([curl], [curl_global_init],,[AC_MSG_ERROR(Libcurl is required to compile Libtrace-bigdata)])
AC_CHECK_LIB([crypto], [EVP_EncryptInit], [], [AC_MSG_FAILURE([can't find openssl crypto lib])])


# check for librdkafka
rdkafkafound=true
AC_CHECK_LIB([rdkafka], [rd_kafka_conf_new],,[rdkafkafound=false])
if test "x$rdkafkafound" = xfalse; then
    AC_MSG_WARN(Librdkafka not found. Kafka plugin will not be compiled)
fi

# check for libmaxminddb
maxminddbfound=true
AC_CHECK_LIB([maxminddb], [MMDB_open],, [maxminddbfound=false])
if test "x$maxminddbfound" = xfalse; then
    AC_MSG_WARN(Libmaxminddb not found. Maxmind plugin will not be compiled)
fi

# check for doxygen
AC_CHECK_PROG([bd_doxygen], [doxygen], [true], [false])

# check for systemd
AC_ARG_WITH([systemdsystemunitdir],
    AS_HELP_STRING([--with-systemdunitdir=DIR], [Directory for systemd service files]),
    [], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
# push the systemd unit dir into the makefile
AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])

# Checks for typedefs, structures, and compiler characteristics.
AC_CHECK_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_INT64_T
AC_C_RESTRICT
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_TYPE_UINT8_T

# All our source files for function replacements are in lib/
AC_CONFIG_LIBOBJ_DIR(lib)

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AM_CONDITIONAL([HAVE_LIBRDKAFKA], [test "x$rdkafkafound" = xtrue])
AM_CONDITIONAL([HAVE_DOXYGEN], [test x"$bd_doxygen" = xtrue])
AM_CONDITIONAL([HAVE_MAXMINDDB], [test "x$maxminddbfound" = xtrue])
AM_CONDITIONAL([HAVE_SYSTEMD], [test -n "$with_systemdsystemunitdir"])

AM_COND_IF([HAVE_DOXYGEN], [AC_CONFIG_FILES([docs/Doxyfile docs/Makefile])])
AM_COND_IF([HAVE_SYSTEMD], [AC_CONFIG_FILES([systemd/Makefile])])
AC_OUTPUT(Makefile lib/Makefile)
