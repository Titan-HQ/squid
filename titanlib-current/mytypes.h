/*
 * $Id$
 *
 * Copyright (c) 2005-2013, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 *
 * The software contained herein is proprietary to and embodies the
 * confidential technology of Copperfasten Technologies, Teoranta.
 * Possession, use, duplication or dissemination of the software and
 * media is authorized only pursuant to a valid written license from
 * Copperfasten Technologies, Teoranta.
 *
 */
/*
- Last modified: 20130114
*/
#ifndef MYTYPES_H
#define MYTYPES_H
#ifdef __cplusplus
extern "C" {
#endif
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdarg.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <signal.h>
#ifdef __cplusplus
}
#endif
//#ifndef _INT128_T_DECLARED
   typedef __int128_t         int128_t;
 //  #define _INT128_T_DECLARED
//#endif
//#ifndef _UINT128_T_DECLARED
   typedef __uint128_t        uint128_t;
 //  #define _UINT128_T_DECLARED
//#endif
////////////////////////////////////////////////////////////////////////////////
//      SIMPLE TYPES ALIASES

typedef int8_t                int8;
typedef uint8_t               uint8;

typedef int16_t               int16;
#ifndef UINT16_H //Avoid conflict with the dnscache declaration
   #define UINT16_H
   typedef uint16_t           uint16;
#endif

typedef int32_t               int32;
#ifndef UINT32_H //Avoid conflict with the dnscache declaration
   #define UINT32_H
   typedef uint32_t           uint32;
#endif

typedef int64_t               int64;
#ifndef UINT64_H //Avoid conflict with the dnscache declaration
   #define UINT64_H
   typedef uint64_t           uint64;
#endif

typedef int128_t              int128;
typedef uint128_t             uint128;
typedef uint8                 byte;
typedef uint32                IPADDR;

/*
 * in the c11 the bool type is provided
 */

#ifndef PRIINT_
   #if __LP64__
     #define PRIINT_         PRId64
   #else
     #define PRIINT_         PRId32
   #endif
#endif

#ifndef PRIUINT_
   #if __LP64__
     #define PRIUINT_        PRIu64
   #else
     #define PRIUINT_        PRIu32
   #endif
#endif
/*
 * Portable ``packed'' declarations
 *
 * Usage:
 *   PACKED struct xxx {
 *      int   member1    PCKD;
 *      char  member2    PCKD;
 *   };
 */
#ifdef __GNUC__
   #define PACKED
   #if ((__GNUC__ == 2) && (__GNUC_MINOR__ < 7))
      #define PCKD   __attribute__((packed))
   #else
      #define PCKD   __attribute__((__packed__))
   #endif
#else
   #define PACKED packed
   #define PCKD
#endif

#ifndef UINT64_MAX
   #define UINT64_MAX (18446744073709551615ULL)
#endif

#ifndef INT64_MAX
   #define INT64_MAX (9223372036854775807LL)
#endif

typedef unsigned long long t_category;   
   
#endif /* MYTYPES_H */
