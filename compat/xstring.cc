/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "compat/xalloc.h"
#include "compat/xstring.h"
#include <iostream>
#include <cerrno>

#ifndef __atr
   #define __atr __restrict
#endif

char * 
xstrdup(const char *const __atr  s)
{

    if (s == NULL) {
        if (failure_notify) {
            (*failure_notify) ("xstrdup: tried to dup a NULL pointer!\n");
        } else {
            errno = EINVAL;
            perror("xstrdup: tried to dup a NULL pointer!");
        }
        exit(1);
    }

    /* copy string, including terminating character */
    const size_t sz = strlen(s) + 1;
    char * const p = (char *const)xmalloc(sz);
    (void)memcpy(p, s, sz);
    return p;
}

char * 
xstrdupex(const char *const __atr  s,const size_t sz){
    if (s == NULL|| !sz) {
        if (failure_notify) {
            (*failure_notify) ("xstrdup: tried to dup a NULL pointer!\n");
        } else {
            errno = EINVAL;
            perror("xstrdup: tried to dup a NULL pointer!");
        }
        exit(1);
    };

    char * const p = (char *const)xmalloc(sz+1);
    assert(p && "xstrdupex failed");
    (void)strlcpy(p,s,sz+1);
    return p;
}

char * 
xstrncpy(char * __atr dst, const char * __atr src,size_t n)
{
    if (n && dst  && src){
       char * const __atr _dst =(char* const)dst;
       while (
             (--n != 0 && *src != '\0' && (*dst++ = *src++)) &&
             (--n != 0 && *src != '\0' && (*dst++ = *src++)) &&
             (--n != 0 && *src != '\0' && (*dst++ = *src++)) &&
             (--n != 0 && *src != '\0' && (*dst++ = *src++)) &&
             (--n != 0 && *src != '\0' && (*dst++ = *src++)) &&
             (--n != 0 && *src != '\0' && (*dst++ = *src++)) &&
             (--n != 0 && *src != '\0' && (*dst++ = *src++)) &&
             (--n != 0 && *src != '\0' && (*dst++ = *src++))
       );
       *dst = '\0';
       return _dst;
    };
    return dst;
}

char * 
xstrndup(const char *const __atr  s, size_t n)
{

    if (s == NULL) {
        errno = EINVAL;
        if (failure_notify) {
            (*failure_notify) ("xstrndup: tried to dup a NULL pointer!\n");
        } else {
            perror("xstrndup: tried to dup a NULL pointer!");
        }
        exit(1);
    }

    size_t sz = strlen(s) + 1;
    // size_t is unsigned, as mandated by c99 and c++ standards.
    if (sz > n)
        sz = n;

    return (xstrncpy((char *)xmalloc(sz), s, sz));
}

