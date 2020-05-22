/*
 * $Id$
 * This code implements the MD5 message-digest algorithm.
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
 * SquidMD5Context structure, pass it to SquidMD5Init, call
 * SquidMD5Update as needed on buffers full of bytes, and then call
 * SquidMD5Final, which will fill a supplied 16-byte array with the
 * digest.
 *
 * Changed so as no longer to depend on Colin Plumb's `usual.h' header
 * definitions; now uses stuff from dpkg's config.h.
 *  - Ian Jackson <ian@chiark.greenend.org.uk>.
 * Still in the public domain.
 *
 * Changed SquidMD5Update to take a void * for easier use and some
 * other minor cleanup. - Henrik Nordstrom <henrik@henriknordstrom.net>.
 * Still in the public domain.
 *
 * Prefixed all symbols with "Squid" so they don't collide with
 * other libraries.  Duane Wessels <wessels@squid-cache.org>.
 * Still in the public domain.
 *
 */


#include "md5.h"
#include "global.h"
#include <assert.h>

TXATR uint64_t ttn_base16_encode(const void * const restrict , const size_t, char * const restrict , const size_t);

/* The four core functions - F1 is optimized somewhat */

/* #define F1(x, y, z) (x & y | ~x & z) */
#define F1(x, y, z) ( (z) ^ ( (x) & ( (y) ^ (z) )))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) ( (x) ^ (y) ^ (z) )
#define F4(x, y, z) ( (y) ^ ( (x) | ~(z) ))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f,w,x,y,z,in,s) \
     ( (w) += f(x,y,z) + (in), (w) = ( (w)<<(s) | (w)>>( 32-(s) ) ) + (x) )


/*
 * The core of the MD5 algorithm, this alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  SquidMD5Update blocks
 * the data and converts bytes into longwords for this routine.
 */

TX_INTERNAL_INLINE
void ttn_md5_transform_(uint32_t * const restrict buf, const uint32_t  * const restrict  in){
    uint32_t a, b, c, d;

    a = buf[0];
    b = buf[1];
    c = buf[2];
    d = buf[3];

    MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
    MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
    MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
    MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
    MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
    MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
    MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
    MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
    MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
    MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
    MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
    MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
    MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
    MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
    MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
    MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

    MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
    MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
    MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
    MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
    MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
    MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
    MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
    MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
    MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
    MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
    MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
    MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
    MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
    MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
    MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
    MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

    MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
    MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
    MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
    MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
    MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
    MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
    MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
    MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
    MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
    MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
    MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
    MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
    MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
    MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
    MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
    MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

    MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
    MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
    MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
    MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
    MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
    MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
    MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
    MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
    MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
    MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
    MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
    MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
    MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
    MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
    MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
    MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

    buf[0] += a;
    buf[1] += b;
    buf[2] += c;
    buf[3] += d;
}


/*
 * Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 * initialization constants.
 */
bool ttn_md5_init(struct ttn_md5_context * const restrict ctx){
   uint32_t * const buf=(uint32_t * const)ctx->buf;
   buf[0] = 0x67452301;
   buf[1] = 0xefcdab89;
   buf[2] = 0x98badcfe;
   buf[3] = 0x10325476;
   ctx->bytes[0] = 0;
   ctx->bytes[1] = 0;
   (void)zm(&ctx->in,MD5RAW_SIZE);
   return (true);
}

/*
 * Update context to reflect the concatenation of another buffer full
 * of bytes.
 */
bool ttn_md5_update(struct ttn_md5_context * const restrict ctx, const void * const restrict buf, size_t len){
    const uint8_t *  buf_ = buf;

    /* Update byte count */

    uint32_t t = ctx->bytes[0];
    if ((ctx->bytes[0] = t +(uint32_t)len) < t)
      ctx->bytes[1]++;    /* Carry from low to high */

    t = MD5CONST1 - (t & 0x3f); /* Space available in ctx->in (at least 1) */
    if (t > len) {
        (void)tx_safe_memcpy((uint8_t *) ctx->in + MD5CONST1 - t, buf_, len);
        return (true);
    }
    /* First chunk is an odd size */
    (void)tx_safe_memcpy((uint8_t *) ctx->in + MD5CONST1 - t, buf_, t);
    ttn_md5_transform_(ctx->buf, ctx->in);
    buf_ += t;
    len -= t;

    /* Process data in 64-byte chunks */
    uint32_t * const in=ctx->in;
    uint32_t * const tbuf=ctx->buf;
    while (len >= MD5CONST1) {
        (void)tx_safe_memcpy(in, buf_, MD5CONST1);
        ttn_md5_transform_(tbuf, ctx->in);
        buf_ += MD5CONST1;
        len -= MD5CONST1;
    }

    /* Handle any remaining bytes of data. */
   (void)tx_safe_memcpy(ctx->in, buf_, len);
    
   return (true);
}

/*
 * Final wrapup - pad to 64-byte boundary with the bit pattern
 * 1 0* (64-bit count of bits processed, MSB-first)
 */
bool ttn_md5_final(u_char * const restrict digest, struct ttn_md5_context * const restrict ctx){
   int count = ctx->bytes[0] & 0x3f;   /* Number of bytes in ctx->in */
   uint8_t *  p = (uint8_t *const) ctx->in + count;

   /* Set the first char of padding to 0x80.  There is always room. */
   *p++ = 0x80;

   /* Bytes of padding needed to make 56 bytes (-8..55) */
   count = 56 - 1 - count;

   if (count < 0) {        /* Padding forces an extra block */
      const int x=count+8;
      (void)zm(p, (size_t)(x) );
      ttn_md5_transform_(ctx->buf, ctx->in);
      p = (uint8_t *) ctx->in;
      count = 56;
   }
   (void)zm(p,(size_t)count);

   /* Append length in bits and transform */
   ctx->in[14] = ctx->bytes[0] << 3;
   ctx->in[15] = ctx->bytes[1] << 3 | ctx->bytes[0] >> 29;
   ttn_md5_transform_(ctx->buf, ctx->in);


   (void)tx_safe_memcpy(digest, ctx->buf, MD5RAW_SIZE);
   (void)zm(ctx, sizeof(*ctx));   /* In case it's sensitive */
   return (true);
}


void ttn_md5_clear(ttn_md5 * const restrict pBuf){
   if (pBuf){
      if (pBuf->hex[0] || pBuf->hexsz || pBuf->raw[0])
         (void)zm(pBuf,sizeof(ttn_md5));
      #ifdef TXDebug
         pdebug("DEB: [ttn_md5_clear] ! \n");
      #endif
   }
}

t_strptr ttn_md5_get_str(ttn_md5 * const restrict pBuf){
   if (pBuf){
      #ifdef TXDebug
         pdebug("DEB: [ttn_md5_get_str] ! \n");
      #endif
      t_strptr r_={
         .ptr_=pBuf->hex,
         .sz_=pBuf->hexsz
      };
      return r_;
   }
   t_strptr r_={ .ptr_=NULL, .sz_=0 };
   return r_;
}


bool ttn_get_md5raw(const char *  const restrict pInput, const size_t pInput_sz , ttn_md5 * const restrict pOutput){
   if (pOutput && pInput && pInput_sz){
      ttn_md5_ctx md5ctx;
      zm(&md5ctx, sizeof(ttn_md5_ctx) );
      (void)ttn_md5_init(&md5ctx);
      (void)ttn_md5_update(&md5ctx, pInput, pInput_sz);
      (void)zm(pOutput->raw,MD5RAW_SIZE);
      (void)ttn_md5_final(pOutput->raw,&md5ctx);
      return true;
   }
   return false;
}

size_t ttn_md5_base16_encode(ttn_md5 * const restrict pIO){
   pIO->hexsz=ttn_base16_encode(pIO->raw,MD5RAW_SIZE,pIO->hex,MD5BASE64_VAL_SIZE);
   return (pIO->hexsz);
}
