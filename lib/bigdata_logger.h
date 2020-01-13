#ifndef BIGDATA_LOGGER_H
#define BIGDATA_LOGGER_H

#include "config.h"
#if HAVE_SYSLOG_H
#include <sys/syslog.h>
#else
#define LOG_DAEMON (3 << 3)
#endif

extern int daemonised;

void remove_pidfile(char *fname);
void logger(int priority, const char *fmt, ...);
void daemonise(char *name, char *pidfile);
void open_daemonlog(char *name);

#endif
