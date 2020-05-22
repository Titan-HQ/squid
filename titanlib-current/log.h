/*******************************************************************************
 * FileName            : log.h
 * Share Type          : Public
 * Description         : This file logs messages to a file.
 ******************************************************************************/
/*
 * $Id$
 */
#ifndef TITAN_LOG_H
#define TITAN_LOG_H

#include <syslog.h>
#include "global.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Use the log levels from syslog.h, but provide aliases for a couple -
 * LOG_EMERG and LOG_ERR so that existing code still works.
 */
#ifndef LOG_FATAL
   #define LOG_FATAL LOG_EMERG
#endif

#ifndef LOG_ERROR
   #define LOG_ERROR LOG_ERR
#endif

void titax_loginit(const char *program);

void titax_logsetlevel(int level);
void titax_logsetlevel_stderr(int level);

__attribute__((__format__ (__printf__, 2, 3)))
void titax_log(const int level, const char *const fmt, ...);

__attribute__((__format__ (__printf__, 3, 4)))
void any_sys_log(const int facility, const int level, const char * const fmt, ...);

#ifdef __cplusplus
}
#endif

#endif /* TITAN_LOG_H */
