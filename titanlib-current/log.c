/*******************************************************************************
 * FileName            : log.c
 * Share Type          : Public
 * Description         : Logs messages to a file.
 ******************************************************************************/

/*
 * $Id$
 */

/* Large file support, just in case */


#include "log.h"
#include "global.h"
#include <assert.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

static int sLogLevelStdErr = LOG_DEBUG;

void titax_loginit(const char *program){
   openlog(program, LOG_PID | LOG_NDELAY | LOG_NOWAIT, LOG_LOCAL2);
   titax_logsetlevel(LOG_NOTICE);
}

void titax_logsetlevel(int level){
   int mask = LOG_UPTO(level);
   (void)setlogmask(mask);
}

void titax_logsetlevel_stderr(int level){
   sLogLevelStdErr = level;
}

void titax_log(const int level, const char * const fmt, ...){
   va_list ap;

   if (level <= sLogLevelStdErr){
      va_start(ap, fmt);
      fprintf(stderr, "%d: ", level);
      vfprintf(stderr, fmt, ap);
      va_end(ap);
   }

   /* Log to syslog */
   va_start(ap,fmt);
   vsyslog(level, fmt, ap);
   va_end(ap);
}

/**
 * @name any_sys_log
 * @param facility 
 * @param level
 * @param fmt
 * @param ...
 */
void any_sys_log(const int facility, const int level, const char * const fmt, ...){
   va_list ap;

   if (level <= sLogLevelStdErr){
      va_start(ap, fmt);
      fprintf(stderr, "%d: ", level);
      vfprintf(stderr, fmt, ap);
      va_end(ap);
   }

   /* Log to syslog */
   va_start(ap,fmt);
   vsyslog((facility|level), fmt, ap);
   va_end(ap);
}
