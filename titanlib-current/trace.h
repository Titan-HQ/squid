/*
 *  $Header: /usr/home/svn/cvsroot/wt1/titax2/libtitax/trace.h,v 1.5 2010-11-24 10:30:03 jinhee Exp $
 *
 *  $Name: not supported by cvs2svn $
 *  $Author: jinhee $
 *  $Revision: 1.5 $
 *  $State: Exp $
 *
 *  CVS History:
 *
 *  $Log: not supported by cvs2svn $
 *  Revision 1.1  2010/02/01 14:03:05  jinhee
 *  modifed files for squid update.
 *
 *  Revision 1.1.1.1  2008/07/23 11:03:36  sean
 *  Initial Titax code.
 *
 *  Revision 1.16.464.2.16.1.8.1  2006/10/30 14:41:22  jsutherland
 *  Turning off tracing and minor cosmetic fixes
 *
 *  Revision 1.16.464.2.16.1  2006/10/09 17:38:51  jsutherland
 *  Mixinf clustering for fishing
 *
 *  Revision 1.16.464.2  2006/08/08 15:53:48  jsutherland
 *  Merging bug 751 727 755 and 756
 *
 *  Revision 1.16.464.1  2006/07/19 13:19:18  jsutherland
 *  Merged bug 661 and 711 into 3.2.1.0 - This is the new group URL list feature
 *
 *  Revision 1.16.478.2  2006/07/13 08:43:45  smukherjee
 *  Removed tracing enable flag
 *
 *  Revision 1.16.478.1  2006/07/11 15:27:21  dredpath
 *  Merge of bug661 and bug711 features of per user URL categories and group B/A lists.
 *
 *  Revision 1.16  2005/08/16 15:50:31  gbisset
 *  Merged all 3.1.3.0 code from the merge_3_1_3 merge branch
 *
 *  Revision 1.15.62.2  2005/06/24 16:10:29  gbisset
 *  Merged bug 154 from nick_bug154
 *
 *  Revision 1.15.62.1  2005/06/22 13:25:54  cmacdonald
 *  Merge to 3.1.3
 *
 *  Revision 1.15.34.4  2005/06/17 13:17:14  nick
 *  B428_Nick_max: Minor fixes and code cleanup
 *
 *  Revision 1.15.34.3  2005/06/16 16:27:57  nick
 *  B428_Nick_Max: bugfix for hangup on virus parsing + extend trace logs
 *
 *  Revision 1.15.10.1  2005/06/02 12:33:08  nick
 *  New feature - SafeSearch engine, added for Google, Yahoo
 *  MSN Search and Lycos search sites.
 *  This engine allow to override user's cookies and URLs related to
 *  SafeSearch engine according to proxy administrative policy.
 *
 *  Revision 1.15  2004/12/15 10:06:39  cmacdonald
 *  Restored the intentional fault to force no tracing
 *
 *  Revision 1.14  2004/11/12 12:09:05  gbisset
 *  Merged all V3 changes from gb_allV3Changes branch to mainline
 *
 *  Revision 1.13.8.1  2004/09/30 11:19:21  gbisset
 *  Merged latest changes from gb_icapPageScanner branch
 *
 *  Revision 1.13.4.1  2004/09/02 08:49:19  gbisset
 *  Comment parse error
 *
 *  Revision 1.13  2003/11/12 08:46:11  johnston
 *  Removing trace calls from committed code.
 *
 *  Revision 1.12  2003/10/21 12:38:22  johnston
 *  Re-structuring of report subsystem for Summary Report. Email notification settings fixed when box is defaulted. Added CVS headers where required. Reduced use of proprietary String class.
 *
 *  Revision 1.11  2003/09/17 14:55:59  johnston
 *  Added DOS line breaks to config export, and took out tracing from checked-in code.
 *
 *  Revision 1.10  2003/09/03 14:56:10  johnston
 *  Large number of mainly user-interface focused changes, plus ability to report host name as well as user and IP when emailing notification of blocked access.
 *
 *  Revision 1.9  2003/07/31 15:48:00  johnston
 *  First cut of distributed policy management functionality.
 *
 *  Revision 1.8  2003/05/01 14:09:22  gordon
 *  first release of cf3000
 *
 *  Revision 1.7  2003/04/16 15:57:40  gordon
 *  changes for rh 8
 *
 *  Revision 1.6  2003/03/20 10:30:09  gordon
 *  spaces in name, corrupt config, ftp updates
 *
 *  Revision 1.5  2003/01/27 09:16:32  gordon
 *  changed to work with C code
 *
 *  Revision 1.4  2002/11/06 14:43:31  gordon
 *  memory leaks and some tracing
 *
 *  Revision 1.3  2002/08/26 12:08:30  gordon
 *  Merge of PD proxy product build
 *
 *  Revision 1.2  2002/08/15 16:14:16  gordon
 *  added trace4
 *
 *  Revision 1.1  2002/06/20 08:55:25  gordon
 *  macro tracing
 *
 *
 */


#ifdef TRACING

#error Be careful! Tracing is on!!! Comment this line to use tracing!

#include <unistd.h>
#include <stdio.h>
#include <pthread.h>
#include <time.h>
static int TON = 1;
static char* _TRCFILE_ = "/tmp/trace";
static pthread_mutex_t fileMutex = PTHREAD_MUTEX_INITIALIZER;
#ifdef sprintf
#undef sprintf
#endif

#define TRACEINIT(X)  if (TON) { \
  pthread_mutex_lock(&fileMutex); \
  FILE* _TRC_; \
  char b[256]; \
  _TRCFILE_=X; \
  sprintf(b,"%s",_TRCFILE_); \
  _TRC_=fopen(b,"w"); \
  fclose(_TRC_); \
  pthread_mutex_unlock(&fileMutex); \
}

#define TRACE0(X)  if (TON) { \
  pthread_mutex_lock(&fileMutex); \
  FILE* _TRC_; \
  char b[256]; \
  sprintf(b,"%s",_TRCFILE_); \
  _TRC_=fopen(b,"a"); \
  time_t theTime = time(NULL); \
  struct tm* t = localtime(&theTime); \
  pthread_t tid = pthread_self(); \
  fprintf(_TRC_, "%02d/", t->tm_mday); \
  fprintf(_TRC_, "%02d/", t->tm_mon); \
  fprintf(_TRC_, "%4d ", (1900 + t->tm_year)); \
  fprintf(_TRC_, "%02d:", t->tm_hour); \
  fprintf(_TRC_, "%02d:", t->tm_min); \
  fprintf(_TRC_, "%02d ", t->tm_sec); \
  fprintf(_TRC_, "tid[%lu] ", tid); \
  fprintf(_TRC_, "pid[%d] ", getpid()); \
  fprintf(_TRC_,X); \
  fclose(_TRC_); \
  pthread_mutex_unlock(&fileMutex); \
}

#define TRACE1(X,Y)  if (TON) { \
  pthread_mutex_lock(&fileMutex); \
  FILE* _TRC_; \
  char b[256]; \
  sprintf(b,"%s",_TRCFILE_); \
  _TRC_=fopen(b,"a"); \
  time_t theTime = time(NULL); \
  struct tm* t = localtime(&theTime); \
  pthread_t tid = pthread_self(); \
  fprintf(_TRC_, "%02d/", t->tm_mday); \
  fprintf(_TRC_, "%02d/", t->tm_mon); \
  fprintf(_TRC_, "%4d ", (1900 + t->tm_year)); \
  fprintf(_TRC_, "%02d:", t->tm_hour); \
  fprintf(_TRC_, "%02d:", t->tm_min); \
  fprintf(_TRC_, "%02d ", t->tm_sec); \
  fprintf(_TRC_, "tid[%lu] ", tid); \
  fprintf(_TRC_, "pid[%d] ", getpid()); \
  fprintf(_TRC_,X,Y); \
  fclose(_TRC_); \
  pthread_mutex_unlock(&fileMutex); \
}

#define TRACE2(X,Y,Z)  if (TON) { \
  pthread_mutex_lock(&fileMutex); \
  FILE* _TRC_; \
  char b[256]; \
  sprintf(b,"%s",_TRCFILE_); \
  _TRC_=fopen(b,"a"); \
  time_t theTime = time(NULL); \
  struct tm* t = localtime(&theTime); \
  pthread_t tid = pthread_self(); \
  fprintf(_TRC_, "%02d/", t->tm_mday); \
  fprintf(_TRC_, "%02d/", t->tm_mon); \
  fprintf(_TRC_, "%4d ", (1900 + t->tm_year)); \
  fprintf(_TRC_, "%02d:", t->tm_hour); \
  fprintf(_TRC_, "%02d:", t->tm_min); \
  fprintf(_TRC_, "%02d ", t->tm_sec); \
  fprintf(_TRC_, "tid[%lu] ", tid); \
  fprintf(_TRC_, "pid[%d] ", getpid()); \
  fprintf(_TRC_,X,Y,Z); \
  fclose(_TRC_); \
  pthread_mutex_unlock(&fileMutex); \
}

#define TRACE3(X,Y,Z,A)  if (TON) { \
  pthread_mutex_lock(&fileMutex); \
  FILE* _TRC_; \
  char b[256]; \
  sprintf(b,"%s",_TRCFILE_); \
  _TRC_=fopen(b,"a"); \
  time_t theTime = time(NULL); \
  struct tm* t = localtime(&theTime); \
  pthread_t tid = pthread_self(); \
  fprintf(_TRC_, "%02d/", t->tm_mday); \
  fprintf(_TRC_, "%02d/", t->tm_mon); \
  fprintf(_TRC_, "%4d ", (1900 + t->tm_year)); \
  fprintf(_TRC_, "%02d:", t->tm_hour); \
  fprintf(_TRC_, "%02d:", t->tm_min); \
  fprintf(_TRC_, "%02d ", t->tm_sec); \
  fprintf(_TRC_, "tid[%lu] ", tid); \
  fprintf(_TRC_, "pid[%d] ", getpid()); \
  fprintf(_TRC_,X,Y,Z,A); \
  fclose(_TRC_); \
  pthread_mutex_unlock(&fileMutex); \
}

#define TRACE4(X,Y,Z,A,B)  if (TON) { \
  pthread_mutex_lock(&fileMutex); \
  FILE* _TRC_; \
  char b[256]; \
  sprintf(b,"%s",_TRCFILE_); \
  _TRC_=fopen(b,"a"); \
  time_t theTime = time(NULL); \
  struct tm* t = localtime(&theTime); \
  pthread_t tid = pthread_self(); \
  fprintf(_TRC_, "%02d/", t->tm_mday); \
  fprintf(_TRC_, "%02d/", t->tm_mon); \
  fprintf(_TRC_, "%4d ", (1900 + t->tm_year)); \
  fprintf(_TRC_, "%02d:", t->tm_hour); \
  fprintf(_TRC_, "%02d:", t->tm_min); \
  fprintf(_TRC_, "%02d ", t->tm_sec); \
  fprintf(_TRC_, "tid[%lu] ", tid); \
  fprintf(_TRC_, "pid[%d] ", getpid()); \
  fprintf(_TRC_,X,Y,Z,A,B); \
  fclose(_TRC_); \
  pthread_mutex_unlock(&fileMutex); \
}

#define XTRACE(...)  if (TON) { \
  pthread_mutex_lock(&fileMutex); \
  FILE* _TRC_; \
  char b[256]; \
  sprintf(b,"%s",_TRCFILE_); \
  _TRC_=fopen(b,"a"); \
  time_t theTime = time(NULL); \
  struct tm* t = localtime(&theTime); \
  pthread_t tid = pthread_self(); \
  fprintf(_TRC_, "%02d/", t->tm_mday); \
  fprintf(_TRC_, "%02d/", t->tm_mon); \
  fprintf(_TRC_, "%4d ", (1900 + t->tm_year)); \
  fprintf(_TRC_, "%02d:", t->tm_hour); \
  fprintf(_TRC_, "%02d:", t->tm_min); \
  fprintf(_TRC_, "%02d ", t->tm_sec); \
  fprintf(_TRC_, "tid[%lu] ", tid); \
  fprintf(_TRC_, "pid[%d] ", getpid()); \
  fprintf(_TRC_, __FILE__ ": "); \
  fprintf(_TRC_,__VA_ARGS__); \
  fclose(_TRC_); \
  pthread_mutex_unlock(&fileMutex); \
}


#else

#define TRACEINIT(X)
#define TRACE0(X) 
#define TRACE1(X,Y) 
#define TRACE2(X,Y,Z) 
#define TRACE3(X,Y,Z,A)
#define TRACE4(X,Y,Z,A,B)
#define XTRACE(...)

#endif











