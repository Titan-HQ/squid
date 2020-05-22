/**
 * $Id$
 * This is a drop in replacement for the openssl sha1 code.
 * It has a small performance penalty compared to the openssl code,
 * but that's no surprise at all as the openssl code is highly
 * optimized.
 *
 * Copyright © 2013, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 *
 * The software contained herein is proprietary to and embodies the
 * confidential technology of Copperfasten Technologies, Teoranta.
 * Possession, use, duplication or dissemination of the software and
 * media is authorized only pursuant to a valid written license from
 * Copperfasten Technologies, Teoranta.
 */
#ifndef SHA1_H__
#define SHA1_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <stdint.h>
#include "global.h"
   
typedef uint32_t Sha1[5];

typedef struct s_shaContext {
   uint8_t           temp_buffer[64];
   Sha1              hash;
   size_t            ntemp_buffer;
   size_t            size;
} SHA_CTX ;

int SHA1_Init(SHA_CTX * const );
int SHA1_Update(SHA_CTX * const , const void *, const size_t);
int SHA1_Final(u_char * const , SHA_CTX * const);

#ifdef __cplusplus
}
#endif

#endif //__SHA1_H__
