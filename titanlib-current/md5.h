/*
 * $Id$
 *
 * This is the header file for the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 *
 * Equivalent code is available from RSA Data Security, Inc.
 * This code has been tested against that, and is equivalent,
 * except that you don't need to include two pages of legalese
 * with every copy.
 *
 * To compute the message digest of a chunk of bytes, declare an
 * MD5Context structure, pass it to MD5Init, call MD5Update as
 * needed on buffers full of bytes, and then call MD5Final, which
 * will fill a supplied 16-byte array with the digest.
 *
 * Changed so as no longer to depend on Colin Plumb's `usual.h'
 * header definitions; now uses stuff from dpkg's config.h
 *  - Ian Jackson <ian@chiark.greenend.org.uk>.
 * Still in the public domain.
 *
 * Changed MD5Update to take a void * for easier use and some other
 * minor cleanup. - Henrik Nordstrom <henrik@henriknordstrom.net>.
 * Still in the public domain.
 *
 * Prefixed all symbols with "Squid" so they don't collide with
 * other libraries.  Duane Wessels <wessels@squid-cache.org>.
 * Still in the public domain.
 *
 */
#ifndef TX_MD5_H
#define TX_MD5_H

#include "global.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct  ttn_md5_context {
   uint32_t buf[4];
   uint32_t bytes[2];
   uint32_t in[MD5RAW_SIZE];
} ttn_md5_ctx;


typedef struct{
   char     hex[MD5BASE64_MAX_SIZE];
   uint8_t  raw[MD5RAW_SIZE];
   size_t   hexsz;
}ttn_md5;


#ifdef __cplusplus
}
#endif


TXATR bool ttn_md5_init(struct ttn_md5_context * const  );
TXATR bool ttn_md5_update(struct ttn_md5_context * const , const void * const, size_t);
TXATR bool ttn_md5_final(u_char * const  , struct ttn_md5_context * const );

TXATR void ttn_md5_clear(ttn_md5 * const );
TXATR t_strptr ttn_md5_get_str(ttn_md5 * const );

TXATR bool ttn_get_md5raw(const char *  const, const size_t, ttn_md5 * const);

TXATR size_t ttn_md5_base16_encode(ttn_md5 * const  pIO);

#endif /* SQUID_MD5_H */
