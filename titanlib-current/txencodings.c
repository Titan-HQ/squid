/*
 * $Id$
 * 
 */

#include "txbase64.h"
#include "global.h"
#include "md5.h"
#include "txbase16.h"
#include <assert.h>
#include <sys/endian.h>

static const char * TX_BASE64_CHARS__ = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

///------------------------------------------------------------------
///            tx_base64.... group
TX_INTERNAL_INLINE
bool base64_encode_triple_(const u_char * const restrict triple, char * const restrict result ) {
   if (triple && result){
      uint32_t tripleValue = triple[0];
      tripleValue <<= 8;
      tripleValue += triple[1];
      tripleValue <<= 8;
      tripleValue += triple[2];

      size_t i=4;
      while(i>0){
         result[--i] = TX_BASE64_CHARS__[tripleValue%64];
         tripleValue >>=6 ;
      }
      return true;
   }
   return false;
}

size_t ttn_base64_encode(const char * const restrict src, size_t sourcelen, char * restrict target, size_t targetlen) {

   /* check if the result will fit in the target buffer */
   if (!target || ((sourcelen+2)/3*4 > targetlen-1))
      return 0;

   const u_char *  source=(const u_char *)src;

   uint_fast64_t ctx=0;
   /* encode all full triples */

   while(
         (sourcelen >= 3)
         && base64_encode_triple_(source, target)
         && ((sourcelen -= 3)||1)
         && (source += 3)
         && (target += 4)
         && (ctx+=4)
      );

   /* encode the last one or two characters */
   if (sourcelen > 0) {
      u_char temp[3];
      temp[0]=0; temp[1]=0; temp[2]=0;
      (void)tx_safe_memcpy(temp, source, sourcelen);
      if (base64_encode_triple_(temp, target) ){
         target[3] = '=';
         if (sourcelen == 1)
            target[2] = '=';
         target += 4;
         ctx+=4;
      }
   }

   /* terminate the string */
   (void)(target &&  (target[0] = 0));

   return ctx;
}

TX_INTERNAL_INLINE
int base64_char_value_(const char base64char) {
   switch (base64char){
      case 'A' ... 'Z':return base64char-'A';
      case 'a' ... 'z':return base64char-'a'+26;
      case '0' ... '9':return base64char-'0'+2*26;
      case '+':return 2*26+10;
      case '/':return 2*26+11;
      default: return -1;
   }
}

TX_INTERNAL_INLINE
size_t base64_decode_triple_(char * restrict quadruple, u_char * const restrict result) {
   uint_fast64_t i;
   int triple_value, bytes_to_decode = 3, only_equals_yet = 1;
   int char_value[4];

   char_value[0] = base64_char_value_(quadruple[0]);
   char_value[1] = base64_char_value_(quadruple[1]);
   char_value[2] = base64_char_value_(quadruple[2]);
   char_value[3] = base64_char_value_(quadruple[3]);
   /* check if the characters are valid */
   i=4;
   while(i>0){
      if (char_value[--i]<0){
         if (only_equals_yet && quadruple[i]=='='){
            //we will ignore this character anyway, make it something
            //that does not break our calculations
            char_value[i]=0;
            bytes_to_decode--;
         } else {
            return 0;
         }
      } else {
         //after we got a real character, no other '=' are allowed anymore
         only_equals_yet = 0;
      }
   }


   /* if we got "====" as input, bytes_to_decode is -1 */
   (void)(bytes_to_decode < 0 && !(bytes_to_decode = 0));

   /* make one big value out of the partial values */
   triple_value = char_value[0];
   triple_value <<= 6;
   triple_value += char_value[1];
   triple_value <<= 6;
   triple_value += char_value[2];
   triple_value <<= 6;
   triple_value += char_value[3];

   /* break the big value into bytes */

   switch (bytes_to_decode){
      case 0: triple_value >>= 8;
      case 1: triple_value >>= 8;
      case 2: triple_value >>= 8;
   }
   i=(uint_fast64_t)bytes_to_decode;
   while(i>0){
      result[--i] = (u_char)(triple_value%256);
      triple_value >>= 8;
   }
   
   return (bytes_to_decode>=0?(size_t)bytes_to_decode:0);
}

size_t ttn_base64_decode(const char *const restrict source,const size_t srclen, char * const restrict dst, size_t targetlen){
   char quadruple[4];
   u_char tmpresult[3];
   size_t converted = 0;
   u_char *  target=(u_char *)dst;
   /* concatenate '===' to the source to handle unpadded base64 data */
   char src[srclen+8];
   (void)strlcpy(src, source,sizeof(src));
   (void)strlcat(src, "====",sizeof(src));
   char *  tmpptr = src;
   /* convert as long as we get a full result */
   size_t tmplen = 3;
   while (tmplen == 3) {
      //get 4 characters to convert
      
      for (int i=0;i<4;){
         while(*tmpptr != '=' && base64_char_value_(*tmpptr)<0 && tmpptr++);
         quadruple[i++] = *(tmpptr++);
      }
      //convert the characters
      tmplen = base64_decode_triple_(quadruple, tmpresult);
      //check if the fit in the result buffer
      if (targetlen < tmplen) return 0;

      //put the partial result in the result buffer
      (void)tx_safe_memcpy(target, tmpresult, tmplen);
      target += tmplen;
      targetlen -= tmplen;
      converted += tmplen;
   }
   return converted;
}

////////////////////////////////////////////////////////////////////////////////

bool tx_base64_valid(const char * const restrict str, const uint_fast64_t len){
   uint_fast64_t i=0;
   while(i<len){
      switch (str[i++]){
         case 43:
         case 47:
         case 48 ... 57:
         case 61:
         case 65 ... 90:
         case 97 ... 122:break;
         default: return false;
      }
   }
   return true;
}


///            end of group
///------------------------------------------------------------------


/*
 * -----------------------------------------------------------------------------
 * ttn_base16.... group
 * -----------------------------------------------------------------------------
 */

TX_INTERNAL_INLINE
size_t base16_encode_(const void * const restrict source,const uint_fast64_t sourcelen,char * const restrict target,const uint_fast64_t targetlen){
   if (source && sourcelen && target && targetlen && targetlen>=(sourcelen<<1)){
      size_t count=0;
      while(count<sourcelen){
         const uint_fast64_t idx=count<<1;
         (void)(((target[idx]=(((const u_char*)source)[count]>>4)+'0')>'9')&&(target[idx]+='a'-'9'-1));
         (void)(((target[idx+1]=(((const u_char*)source)[count++]&0x0F)+'0')>'9')&&(target[idx+1]+='a'-'9'-1));
      }
      return (count * 2);
   }
   return 0;
}

#ifndef B16BYTES_
   #define B16BYTES_(V) (u_char)( (V) -((((-WITHIN_('A','Z', (V) ))&('A'-10))|((-WITHIN_('a','z', (V) ))&('a'-10))|((-WITHIN_('0','9', (V) ))&('0')))?:(V) ))
#endif

TX_INTERNAL_INLINE
size_t base16_decode_( const char * const restrict source, 
                       const uint_fast64_t sourcelen,
                       void * const restrict target,
                       const uint_fast64_t targetlen )
{
   uint_fast64_t sl;
   if (source && sourcelen && target && targetlen && targetlen>=((sl=sourcelen>>1))){
      uint_fast64_t   tpos=0;
      uint_fast64_t   count=0;
      char * const ctarget = target;
      while( count < sl ) {

         const uint_fast64_t idx1 = ( count++ << 1 );

         ctarget[ tpos++ ] =
               (char)( ( B16BYTES_( source[ idx1 ] ) << 4 ) | B16BYTES_( source[ idx1+1 ] ) );

      }
      return tpos;
   }
   return 0;
}

/*
 * -----------------------------------------------------------------------------
 * interface
 * -----------------------------------------------------------------------------
 */
size_t ttn_base16_encode(const void * const restrict src , const size_t srcsz, char * const restrict dst, const size_t dstsz){
   return (base16_encode_(src,srcsz,dst,dstsz));
}

size_t ttn_base16_decode(const char * const restrict src, const size_t srcsz, void * const restrict dst, const size_t dstsz){
   return (base16_decode_(src,srcsz,dst,dstsz));
}

bool ttn_base16_encode_uint32(uint32_t src,char * const restrict dst, const size_t dstsz){
   src=bswap32(src);
   return(base16_encode_((void * const)&src,sizeof(uint32_t),dst,dstsz));
}

bool ttn_base16_decode_uint32(const char * const restrict src, const size_t srcsz,uint32_t * const restrict dst){
   if (base16_decode_(src,srcsz,(char*const)dst,sizeof(uint32_t))){
      *dst=bswap32(*dst);
      return true;
   }
   return false;
}

bool ttn_base16_encode_uint64(uint64_t src,char * const restrict dst, const size_t dstsz){
   src=bswap64(src);
   return(base16_encode_((void * const)&src,sizeof(uint64_t),dst,dstsz));
}

bool ttn_base16_decode_uint64(const char * const restrict src, const size_t srcsz,uint64_t * const restrict dst){
   if(base16_decode_(src,srcsz,(char*const)dst, sizeof(uint64_t))){
      *dst=bswap64(*dst);
      return true;
   }
   return false;
}
