#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.69])
AC_INIT([Libtrace-bigdata], [1.0], [jacobvw@icloud.com])
AC_CONFIG_SRCDIR([lib/bigdata.cc])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build])

AM_INIT_AUTOMAKE([subdir-objects])

# Checks for programs.
AC_PROG_CXX
AC_PROG_CC
AC_PROG_INSTALL
AC_PROG_AWK
AC_PROG_CPP
AC_PROG_MKDIR_P

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h limits.h netdb.h netinet/in.h stddef.h stdint.h stdlib.h string.h sys/socket.h])

AC_CHECK_LIB([trace], [trace_pstart],,[AC_MSG_ERROR(Libtrace is required to compile Libtrace-bigdata)])
AC_CHECK_LIB([protoident], [lpi_init_library],,[AC_MSG_ERROR(Libprotoident is required to compile Libtrace-bigdata)])
AC_CHECK_LIB([yaml], [yaml_parser_initialize],,[AC_MSG_ERROR(Libyaml is required to compile Libtrace-bigdata)])
AC_CHECK_LIB([flowmanager], [lfm_version_three],,[AC_MSG_ERROR(Libflowmanager 3.0.0 or greater is required to compile Libtrace-bigdata)])

# check for librdkafka
rdkafkafound=true
AC_CHECK_LIB([rdkafka], [rd_kafka_conf_new],,[rdkafkafound=false])
if test "x$rdkafkafound" = xfalse; then
    AC_MSG_WARN(Librdkafka not found. Kafka plugin will not be compiled)
fi

# check for libcurl
curlfound=true
AC_CHECK_LIB([curl], [curl_global_init],,[curlfound=false])
if test "x$curlfound" = xfalse; then
    AC_MSG_WARN(Libcurl not found. InfluxDB plugin will not be compiled)
fi


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

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([memchr memset modf pow strdup])

AM_CONDITIONAL([HAVE_LIBRDKAFKA], [test "x$rdkafkafound" = xtrue])
AM_CONDITIONAL([HAVE_LIBCURL], [test "x$curlfound" = xtrue])

AC_OUTPUT(Makefile lib/Makefile)
