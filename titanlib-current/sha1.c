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

#include "sha1.h"
#include "global.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>

#ifdef __MINGW32__
#include <winsock.h>
#else
#include <arpa/inet.h>
#endif


#define ROTL(val, n)       (((val)<<(n)) | ((val)>>(32-(n))))
#define CH(x, y, z)        (((x)&(y))^(~(x)&(z)))
#define PARITY(x, y, z)    ((x)^(y)^(z))
#define MAJOR(x, y, z)     (((x)&(y))^((x)&(z))^((y)&(z)))

#ifndef TX_INTERNAL_INLINE
   #ifdef __clang__
      #define TX_INTERNAL_INLINE static  __attribute__((gnu_inline, always_inline)) inline
   #else
      #define TX_INTERNAL_INLINE  extern __attribute__ ((always_inline,__gnu_inline__,__externally_visible__,visibility ("hidden"))) inline
   #endif
#endif

TX_INTERNAL_INLINE
void sha1_hashblock(SHA_CTX * const restrict ctx, const u_char * const restrict block){
   

   uint32_t work[80]={};
   //need to copy block to local block_ prevent accessing data via misaligned pointer
   u_char block_[sizeof(uint32_t) <<4];
   (void)tx_safe_memcpy(block_, block, sizeof(uint32_t) <<4);

   uint32_t * const hash=(uint32_t * const)&ctx->hash;
   
   uint32_t a = hash[0];
   uint32_t b = hash[1];
   uint32_t c = hash[2];
   uint32_t d = hash[3];
   uint32_t e = hash[4];
   

   for (uint_fast64_t i=0;i<80; ++i){
      if (i<16){
         //fix misaligned cpy & cast-align
         uint32_t ublock_=0;
         tx_safe_memcpy(&ublock_,block_+(i*sizeof(uint32_t)),sizeof(uint32_t));
         work[i]=htonl(ublock_);
      } else {
        work[i]=ROTL(work[i-3] ^ work[i-8] ^ work[i-14] ^ work[i-16], 1);
      }

      uint32_t T= ROTL(a, 5) + e + work[i];

      switch (i / 20) {
         case 0: 
            T += CH(b, c, d) + 0x5a827999;
            break;

         case 1:
            T += PARITY(b, c, d) + 0x6ed9eba1;
            break;

         case 2:
            T += MAJOR(b, c, d) + 0x8f1bbcdc;
            break;

         case 3:
            T += PARITY(b, c, d) + 0xca62c1d6;
            break;
      }

      e = d;
      d = c;
      c = ROTL(b, 30);
      b = a;
      a = T;
   }
                   
   hash[0] += a;
   hash[1] += b;
   hash[2] += c;
   hash[3] += d;
   hash[4] += e;

}


int SHA1_Init(SHA_CTX * const  restrict ctx){
   uint32_t * const hash=(uint32_t * const)&ctx->hash;
   hash[0] = 0x67452301;
   hash[1] = 0xefcdab89;
   hash[2] = 0x98badcfe;
   hash[3] = 0x10325476;
   hash[4] = 0xc3d2e1f0;

   (void)zm(ctx->temp_buffer,64);
   ctx->ntemp_buffer = 0;
   ctx->size         = 0;

   return 1;
}

int
SHA1_Update(SHA_CTX * const restrict ctx, const void * data, const size_t ndata){
   size_t pos_data = 0;

   if (0 != ctx->ntemp_buffer || 64 > ctx->ntemp_buffer + ndata) {
      /*
       * either there was already data in temp_buffer or we have
       * not enough data for a complete block or both.
       * This means we start with filling up temp_buffer and
       * if it is full use it as the first block.
       */
      size_t to_move = ndata < 64 - ctx->ntemp_buffer
         ? ndata
         : 64 - ctx->ntemp_buffer;

      (void)tx_safe_memcpy(ctx->temp_buffer + ctx->ntemp_buffer, data, to_move);
      ctx->ntemp_buffer += to_move;
      pos_data           = to_move;

      if (ctx->ntemp_buffer != 64) {
         /*
          * if temp_buffer is still not full we can stop here
          */
         return 1;
      }

      sha1_hashblock(ctx, ctx->temp_buffer);


      (void)zm(ctx->temp_buffer,64);
      ctx->ntemp_buffer  = 0;
      ctx->size         += 64;
   }


   while (ndata >= 64 && pos_data <= (ndata-64)) {
           sha1_hashblock(ctx, (((const u_char *)data) + pos_data));
           pos_data  += 64;
           ctx->size += 64;
       }

   if (pos_data == ndata) {
      return 1;
   }

   ctx->ntemp_buffer = ndata - pos_data;
   (void)tx_safe_memcpy(ctx->temp_buffer, (((const u_char *)data) + pos_data), ctx->ntemp_buffer);

   return 1;
}

int
SHA1_Final(u_char * const restrict  digest, SHA_CTX * const restrict ctx)
{
   const union
   {
      uint64_t size64;
      uint32_t size32[2];

   } x_size = { .size64 = (ctx->size + ctx->ntemp_buffer) << 3 /* size in bits */ };

   /*
    * it might happen that the size in bits does not
    * fit within the block...in that case it has to be
    * but in a second empty block.
    */
   /*
    * Anyway, temp_block is never full, as then it would have been
    * processed in SHA1_Update. So it is save to set the 0x80
    * end marker.
    */
   ctx->temp_buffer[ctx->ntemp_buffer++] = 0x80;

   if ((64 - ctx->ntemp_buffer) < 8) {

      sha1_hashblock(ctx, ctx->temp_buffer);

      zm(ctx->temp_buffer,64);
   }

   uint32_t s32=ntohl(x_size.size32[1]);

   tx_safe_memcpy((ctx->temp_buffer+(sizeof(uint32_t)*14)),&s32,sizeof(uint32_t)); 

   s32=ntohl(x_size.size32[0]);

   tx_safe_memcpy((ctx->temp_buffer+(sizeof(uint32_t)*15)),&s32,sizeof(uint32_t)); 

   sha1_hashblock(ctx, ctx->temp_buffer);

   uint32_t * const hash=(uint32_t * const)&ctx->hash;

   //fix misaligned cpy & cast-align

   s32=ntohl(hash[0]);
   (void)tx_safe_memcpy((digest+(sizeof(uint32_t)*0)),&s32,sizeof(uint32_t)); 

   s32=ntohl(hash[1]);
   tx_safe_memcpy((digest+(sizeof(uint32_t)*1)),&s32,sizeof(uint32_t)); 

   s32=ntohl(hash[2]);
   tx_safe_memcpy((digest+(sizeof(uint32_t)*2)),&s32,sizeof(uint32_t)); 

   s32=ntohl(hash[3]);
   tx_safe_memcpy((digest+(sizeof(uint32_t)*3)),&s32,sizeof(uint32_t)); 

   s32=ntohl(hash[4]);
   tx_safe_memcpy((digest+(sizeof(uint32_t)*4)),&s32,sizeof(uint32_t)); 

   return 1;
}
