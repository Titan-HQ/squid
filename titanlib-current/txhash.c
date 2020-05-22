/*
 * $Id$
 */
#include "txhash.h"
#include "global.h"
#include "sha1.h"
#include "txal.h"
#include "txbase16.h"
#include <assert.h>


static
const uint32_t crcTable[256] = {
0x00000000,0x77073096,0xEE0E612C,0x990951BA,0x076DC419,0x706AF48F,0xE963A535,
0x9E6495A3,0x0EDB8832,0x79DCB8A4,0xE0D5E91E,0x97D2D988,0x09B64C2B,0x7EB17CBD,
0xE7B82D07,0x90BF1D91,0x1DB71064,0x6AB020F2,0xF3B97148,0x84BE41DE,0x1ADAD47D,
0x6DDDE4EB,0xF4D4B551,0x83D385C7,0x136C9856,0x646BA8C0,0xFD62F97A,0x8A65C9EC,
0x14015C4F,0x63066CD9,0xFA0F3D63,0x8D080DF5,0x3B6E20C8,0x4C69105E,0xD56041E4,
0xA2677172,0x3C03E4D1,0x4B04D447,0xD20D85FD,0xA50AB56B,0x35B5A8FA,0x42B2986C,
0xDBBBC9D6,0xACBCF940,0x32D86CE3,0x45DF5C75,0xDCD60DCF,0xABD13D59,0x26D930AC,
0x51DE003A,0xC8D75180,0xBFD06116,0x21B4F4B5,0x56B3C423,0xCFBA9599,0xB8BDA50F,
0x2802B89E,0x5F058808,0xC60CD9B2,0xB10BE924,0x2F6F7C87,0x58684C11,0xC1611DAB,
0xB6662D3D,0x76DC4190,0x01DB7106,0x98D220BC,0xEFD5102A,0x71B18589,0x06B6B51F,
0x9FBFE4A5,0xE8B8D433,0x7807C9A2,0x0F00F934,0x9609A88E,0xE10E9818,0x7F6A0DBB,
0x086D3D2D,0x91646C97,0xE6635C01,0x6B6B51F4,0x1C6C6162,0x856530D8,0xF262004E,
0x6C0695ED,0x1B01A57B,0x8208F4C1,0xF50FC457,0x65B0D9C6,0x12B7E950,0x8BBEB8EA,
0xFCB9887C,0x62DD1DDF,0x15DA2D49,0x8CD37CF3,0xFBD44C65,0x4DB26158,0x3AB551CE,
0xA3BC0074,0xD4BB30E2,0x4ADFA541,0x3DD895D7,0xA4D1C46D,0xD3D6F4FB,0x4369E96A,
0x346ED9FC,0xAD678846,0xDA60B8D0,0x44042D73,0x33031DE5,0xAA0A4C5F,0xDD0D7CC9,
0x5005713C,0x270241AA,0xBE0B1010,0xC90C2086,0x5768B525,0x206F85B3,0xB966D409,
0xCE61E49F,0x5EDEF90E,0x29D9C998,0xB0D09822,0xC7D7A8B4,0x59B33D17,0x2EB40D81,
0xB7BD5C3B,0xC0BA6CAD,0xEDB88320,0x9ABFB3B6,0x03B6E20C,0x74B1D29A,0xEAD54739,
0x9DD277AF,0x04DB2615,0x73DC1683,0xE3630B12,0x94643B84,0x0D6D6A3E,0x7A6A5AA8,
0xE40ECF0B,0x9309FF9D,0x0A00AE27,0x7D079EB1,0xF00F9344,0x8708A3D2,0x1E01F268,
0x6906C2FE,0xF762575D,0x806567CB,0x196C3671,0x6E6B06E7,0xFED41B76,0x89D32BE0,
0x10DA7A5A,0x67DD4ACC,0xF9B9DF6F,0x8EBEEFF9,0x17B7BE43,0x60B08ED5,0xD6D6A3E8,
0xA1D1937E,0x38D8C2C4,0x4FDFF252,0xD1BB67F1,0xA6BC5767,0x3FB506DD,0x48B2364B,
0xD80D2BDA,0xAF0A1B4C,0x36034AF6,0x41047A60,0xDF60EFC3,0xA867DF55,0x316E8EEF,
0x4669BE79,0xCB61B38C,0xBC66831A,0x256FD2A0,0x5268E236,0xCC0C7795,0xBB0B4703,
0x220216B9,0x5505262F,0xC5BA3BBE,0xB2BD0B28,0x2BB45A92,0x5CB36A04,0xC2D7FFA7,
0xB5D0CF31,0x2CD99E8B,0x5BDEAE1D,0x9B64C2B0,0xEC63F226,0x756AA39C,0x026D930A,
0x9C0906A9,0xEB0E363F,0x72076785,0x05005713,0x95BF4A82,0xE2B87A14,0x7BB12BAE,
0x0CB61B38,0x92D28E9B,0xE5D5BE0D,0x7CDCEFB7,0x0BDBDF21,0x86D3D2D4,0xF1D4E242,
0x68DDB3F8,0x1FDA836E,0x81BE16CD,0xF6B9265B,0x6FB077E1,0x18B74777,0x88085AE6,
0xFF0F6A70,0x66063BCA,0x11010B5C,0x8F659EFF,0xF862AE69,0x616BFFD3,0x166CCF45,
0xA00AE278,0xD70DD2EE,0x4E048354,0x3903B3C2,0xA7672661,0xD06016F7,0x4969474D,
0x3E6E77DB,0xAED16A4A,0xD9D65ADC,0x40DF0B66,0x37D83BF0,0xA9BCAE53,0xDEBB9EC5,
0x47B2CF7F,0x30B5FFE9,0xBDBDF21C,0xCABAC28A,0x53B39330,0x24B4A3A6,0xBAD03605,
0xCDD70693,0x54DE5729,0x23D967BF,0xB3667A2E,0xC4614AB8,0x5D681B02,0x2A6F2B94,
0xB40BBE37,0xC30C8EA1,0x5A05DF1B,0x2D02EF8D };


struct basic_hash_elems{size_t i_; const size_t max_; t_hash * const out_; const u_char * const in_;};

TX_INTERNAL_INLINE
bool sdbm_hash_(const void * const restrict v, const size_t len, t_hash *  const restrict out){
   if (v && len && out){
      CLU_
      for (struct basic_hash_elems e={
         .max_=len,
         .out_=out,
         .in_=(const u_char * const)v
      };e.i_<e.max_;*e.out_=(e.in_[e.i_++] + (*e.out_ << 6) + (*e.out_ << 16) - (*e.out_)));
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
bool djb2m_hash_(const void * const restrict v, const size_t len, t_hash * const restrict out){
   if (v && len && out){
      CLU_
      for (struct basic_hash_elems e={
         .max_=len,
         .out_=out,
         .in_=(const u_char * const)v
      };e.i_<e.max_;*e.out_=(33 * (*e.out_) ^ e.in_[e.i_++]));
      return true;
   }
   return false;
}


TX_INTERNAL_INLINE
bool fnv_hash_(const void * const restrict v, const size_t len, t_hash * const restrict out){
   if (v && len && out){
      CLU_
      for (struct basic_hash_elems e={
         .max_=len,
         .out_=out,
         .in_=(const u_char * const)v
      };e.i_<e.max_;*e.out_=(16777619 * (*e.out_) ^ e.in_[e.i_++]));
      return true;
   }
   return false;
}

struct eoat{size_t i_; const size_t max_;t_hash * hash_;const u_char * const in_;};

TX_INTERNAL_INLINE
bool oat_hash_(const void * const  restrict v, const size_t len, t_hash * const restrict  out){
   if (v && len && out){
      CLU_
      for (struct eoat e={
         .max_=len,
         .hash_=out,
         .in_=(const u_char *const)v
      };e.i_<e.max_;++e.i_){
         *e.hash_ += e.in_[e.i_];
         *e.hash_ += (*e.hash_ << 10) ;
         *e.hash_ ^= (*e.hash_ >> 6);
      }
      *out += (*out << 3 );
      *out ^= (*out >> 11 );
      *out += (*out << 15 );
      return true;
   }
   return false;
}

struct emurmur{uint64_t i_; const uint64_t max_; const uint64_t * const data_ ;uint64_t * const h1_;uint64_t * const h2_;uint64_t k1_; uint64_t k2_; const uint64_t * block_;};  

TX_INTERNAL_INLINE
bool murmurHash3_x64_128_hash_(const void * const restrict v, const size_t len, t_hash_ex *const restrict out){

   if (v && len && out){
      const uint8_t * const  data = (const uint8_t*const)v;
      const uint64_t nblocks = len / 16;
      const uint64_t c1 = (0x87c37b91114253d5LLU);
      const uint64_t c2 = (0x4cf5ad432745937fLLU);
      uint64_t h1 = ((uint64_t*)out)[0];
      uint64_t h2 = ((uint64_t*)out)[1];
      uint_aligned_cast_t ucast={.in_uchar=data};
      CLU_
      for (struct emurmur e={
         .max_=nblocks,
         .data_=ucast.out64,
         .h1_=&h1,
         .h2_=&h2,
      };e.i_<e.max_;++e.i_){
         e.block_=e.data_+(e.i_*2);
         tx_safe_memcpy(&e.k1_,e.block_++,sizeof(uint64_t));
         tx_safe_memcpy(&e.k2_,e.block_,sizeof(uint64_t));
         e.k1_ *= c1; e.k1_  = ((e.k1_ << 31) | (e.k1_ >> (64 - 31))); e.k1_ *= c2; *e.h1_ ^= e.k1_;
         *e.h1_ = ((*e.h1_ << 27) | (*e.h1_ >> (64 - 27))); *e.h1_ += *e.h2_; *e.h1_*=5+0x52dce729;
         e.k2_ *= c2; e.k2_  = ((e.k2_ << 33) | (e.k2_ >> (64 - 33))); e.k2_ *= c1; *e.h2_ ^= e.k2_;
         *e.h2_ = ((*e.h2_ << 31) | (*e.h2_ >> (64 - 31))); *e.h2_ += *e.h1_; *e.h2_*=5+0x38495ab5;
      }
      
      const uint8_t * const  tail = (const uint8_t*const)(data + nblocks*16);
      uint64_t k1=0;
      uint64_t k2=0;
      
      switch(len & 15){
         case 15: k2 ^= ((uint64_t)tail[14]) << 48;
         case 14: k2 ^= ((uint64_t)tail[13]) << 40;
         case 13: k2 ^= ((uint64_t)tail[12]) << 32;
         case 12: k2 ^= ((uint64_t)tail[11]) << 24;
         case 11: k2 ^= ((uint64_t)tail[10]) << 16;
         case 10: k2 ^= ((uint64_t)tail[ 9]) << 8;
         case  9: k2 ^= ((uint64_t)tail[ 8]) << 0;
               k2 *= c2; k2  = ((k2 << 33) | (k2 >> (64 - 33))); k2 *= c1; h2 ^= k2;

         case  8: k1 ^= ((uint64_t)tail[ 7]) << 56;
         case  7: k1 ^= ((uint64_t)tail[ 6]) << 48;
         case  6: k1 ^= ((uint64_t)tail[ 5]) << 40;
         case  5: k1 ^= ((uint64_t)tail[ 4]) << 32;
         case  4: k1 ^= ((uint64_t)tail[ 3]) << 24;
         case  3: k1 ^= ((uint64_t)tail[ 2]) << 16;
         case  2: k1 ^= ((uint64_t)tail[ 1]) << 8;
         case  1: k1 ^= ((uint64_t)tail[ 0]) << 0;
               k1 *= c1; k1  =((k1 << 31) | (k1 >> (64 - 31))); k1 *= c2; h1 ^= k1;
      }

      h1 ^= len; h2 ^= len;

      h1 += h2;
      h2 += h1;
      h1 ^= h1 >> 33;
      h1 *= (0xff51afd7ed558ccdLLU);
      h1 ^= h1 >> 33;
      h1 *= (0xc4ceb9fe1a85ec53LLU);
      h1 ^= h1 >> 33;
      h2 ^= h2 >> 33;
      h2 *= (0xff51afd7ed558ccdLLU);
      h2 ^= h2 >> 33;
      h2 *= (0xc4ceb9fe1a85ec53LLU);
      h2 ^= h2 >> 33;

      h1 += h2;
      h2 += h1;

      ((uint64_t*const)out)[0] = h1;
      ((uint64_t*const)out)[1] = h2;
      return true;
   }
   return false;

}

TX_INTERNAL_INLINE
bool murmurHash3_x64_64_hash_(const void * const restrict v, const size_t len, t_hash *const restrict out){
   if (out){
      t_hash_ex outex=(t_hash_ex)*out;
      if (v && len && murmurHash3_x64_128_hash_(v,len,&outex)){
         *out=((const t_hash*const)(&outex))[0];
         return true;
      }
   }
   return false;
}


TX_INTERNAL_INLINE
bool crc32_hash_(const void * const restrict v, const size_t len, t_hash * const restrict  out){
   if (v && len && out){
      uint32_t crc=((uint32_t*const)out)[0];
      crc^=0xFFFFFFFF;
      size_t i=0;
      CLU_
      while(i<len){
         crc=(crc >> 8) ^ crcTable[ (crc ^ ((const u_char*const) v)[i++]) & 0xFF];
      }
      crc^=0xFFFFFFFF;
      ((uint32_t*const)out)[0]=crc;
      ((uint32_t*const)out)[1]=0;
      return true;
   }
   return false;
}


static 
bool merge_data_for_orchid_(t_lm_call * const restrict scall){
   if (scall->action==ia_run){
      SHA_CTX * const ctx=(SHA_CTX *const)scall->extra;
      SHA1_Update(ctx,scall->item->vi,scall->item->vilen);
   }
   return true;
}

static
bool merge_data_for_djb2_(t_lm_call * const restrict scall){
   (void)(scall->action==ia_run && djb2m_hash_(scall->item->vi,scall->item->vilen,(t_hash*const)(scall->extra)));
   return true;
}

static
bool merge_data_for_fnv_(t_lm_call * const restrict scall){
   (void)(scall->action==ia_run && fnv_hash_(scall->item->vi,scall->item->vilen,(t_hash*const)(scall->extra)));
   return true;
}

static
bool merge_data_for_oat_(t_lm_call * const restrict scall){
   (void)(scall->action==ia_run && oat_hash_(scall->item->vi,scall->item->vilen,(t_hash*const)(scall->extra)));
   return true;
}
////////////////////////////////////////////////////////////////////////////////

TX_INTERNAL_INLINE
bool init_out_data_(t_txhash_args * const restrict pArgs,const size_t pSize){
   if (pArgs->out_data){
      if (!pArgs->safe  || pSize>pArgs->out_data_safe_size){
         tx_safe_free(pArgs->out_data);
         pArgs->out_data=NULL;
      }
   }
   if (!pArgs->out_data){
      pArgs->out_data  = (u_char *)tx_safe_malloc(pSize);
      assert(pArgs->out_data && "init_out_data_ failed");
      pArgs->out_data_safe_size=pSize;
   } else{
      zm(pArgs->out_data, pArgs->out_data_len);
   }
   pArgs->out_data_len=pSize;
   return true;
}


TX_INTERNAL_INLINE
bool new_orchid_hash_(t_txhash_args * const restrict pArgs){
   if (pArgs && pArgs->in_data && al_count(pArgs->in_data) && init_out_data_(pArgs,ORCHID_OUT_SZ)){
      u_char         digest[20];
      u_char * const relevant_bytes = &(digest[3]);
      u_char * const orchid         = pArgs->out_data;
      SHA_CTX        ctx;
   SHA1_Init(&ctx);
      al_run(pArgs->in_data,&merge_data_for_orchid_,false,false,(void*)&ctx);
   SHA1_Final(digest, &ctx);

   /*
    * I unroll the loop completely without any duff device or something.
    * This function is especially for orchid generation and thus will
    * always deal with 16 bytes in the result.
    */
   orchid[3]  = (relevant_bytes[0]  << 2 & 0xFF) | (relevant_bytes[1]  >> 6);
   orchid[4]  = (relevant_bytes[1]  << 2 & 0xFF) | (relevant_bytes[2]  >> 6);
   orchid[5]  = (relevant_bytes[2]  << 2 & 0xFF) | (relevant_bytes[3]  >> 6);
   orchid[6]  = (relevant_bytes[3]  << 2 & 0xFF) | (relevant_bytes[4]  >> 6);
   orchid[7]  = (relevant_bytes[4]  << 2 & 0xFF) | (relevant_bytes[5]  >> 6);
   orchid[8]  = (relevant_bytes[5]  << 2 & 0xFF) | (relevant_bytes[6]  >> 6);
   orchid[9]  = (relevant_bytes[6]  << 2 & 0xFF) | (relevant_bytes[7]  >> 6);
   orchid[10] = (relevant_bytes[7]  << 2 & 0xFF) | (relevant_bytes[8]  >> 6);
   orchid[11] = (relevant_bytes[8]  << 2 & 0xFF) | (relevant_bytes[9]  >> 6);
   orchid[12] = (relevant_bytes[9]  << 2 & 0xFF) | (relevant_bytes[10] >> 6);
   orchid[13] = (relevant_bytes[10] << 2 & 0xFF) | (relevant_bytes[11] >> 6);
   orchid[14] = (relevant_bytes[11] << 2 & 0xFF) | (relevant_bytes[12] >> 6);
   orchid[15] = (relevant_bytes[12] << 2 & 0xFF) | (relevant_bytes[13] >> 6);

   orchid[0]  = 0x20;
   orchid[1]  = 0x01;
   orchid[2]  = 0x00;
   orchid[3] &= 0x0F;
   orchid[3] |= 0x10;

      return ((pArgs->ready = true));
   }
   return false;
}

TX_INTERNAL_INLINE
bool new_djb2_hash_( t_txhash_args * const restrict pArgs){
   return (pArgs && pArgs->in_data && al_count(pArgs->in_data) && al_run(pArgs->in_data,&merge_data_for_djb2_,false,false,(void*)&pArgs->out_data_hash) &&    pArgs->out_data_hash && (pArgs->ready = true));
}

TX_INTERNAL_INLINE
bool new_fnv_hash_( t_txhash_args * const restrict pArgs){
   return (pArgs && pArgs->in_data && al_count(pArgs->in_data) && al_run(pArgs->in_data,&merge_data_for_fnv_,false,false,(void*)&pArgs->out_data_hash) &&  pArgs->out_data_hash && (pArgs->ready = true));
}

TX_INTERNAL_INLINE
bool new_oat_hash_ ( t_txhash_args * const restrict pArgs){
   return (pArgs &&  pArgs->in_data && al_count(pArgs->in_data) && al_run(pArgs->in_data,&merge_data_for_oat_,false,false,(void*)&pArgs->out_data_hash) &&  pArgs->out_data_hash && (pArgs->ready = true));
}

TX_INTERNAL_INLINE
const char *  gethex_ex_(t_txhash_args * const restrict pArgs,size_t * const restrict pSize){
   if (pArgs){
      if (pSize) *pSize=(pArgs->out_data_hex && pArgs->ready?pArgs->out_data_hex->data_sz:ttn_hash_b16_encode(pArgs));
      if (!pSize || *pSize) return pArgs->out_data_hex->db;  
   }
   return NULL;
}

TX_INTERNAL_INLINE
bool upd_orchid_args_hex_(t_txhash_args *const restrict pArgs, const char *const restrict data_hex,const size_t pSize){
   if (!pArgs || !data_hex || !pSize) {return false;}
   if (pArgs->out_data_len){
      (void)clear_txhash_args(pArgs);
      pArgs->type  = txhh_orchid;
   }
   if (!init_out_data_(pArgs,ORCHID_OUT_SZ)){
      (void)free_txhash_args(pArgs);
      return false;
   }

   if (!pArgs->out_data_hex){
      pArgs->out_data_hex=data_buff_new(0);
      assert(pArgs->out_data_hex && "data_buff_new has failed");
   }

   if ((pSize+1)<pArgs->out_data_hex->db_sz || data_buff_grow(pArgs->out_data_hex,pSize+1)){
      assert(data_buff_write(pArgs->out_data_hex, data_hex,pSize));
   } else
      assert(0 && "data_buff_grow problem!");
   
   return true;
}

////////////////////////////////////////////////////////////////////////////////

bool new_txhash(t_txhash_args * const restrict pArgs){
   switch (pArgs->type){
      case txhh_oat:
         return new_oat_hash_(pArgs);
      case txhh_fnv:
         return new_fnv_hash_(pArgs);
      case txhh_djb2:
         return new_djb2_hash_(pArgs);
      case txhh_orchid:
         return new_orchid_hash_(pArgs);
      default:
         return false;
   }
}

t_txhash_args * new_orchid_hash_from_str(char * restrict pContext,char * restrict pData,const bool pSafe){
   t_txhash_args * const r=mk_orchid_args_from_str(pContext,pData,pSafe);
   if (r){
      if (new_txhash(r) && ttn_hash_b16_encode(r)) return r;
      free_txhash_args(r);
   }
   return NULL;
}

t_txhash_args * new_djb2_hash_from_str(char * restrict data,const bool safe){   
   t_txhash_args * const r=mk_djb2_args_from_str(data,safe);
   if (r){
      if (new_txhash(r)) return r;
      free_txhash_args(r);
   }
   return NULL;
}


t_txhash_args * new_fnv_hash_from_str(char * restrict data,const bool safe){
   t_txhash_args * const r=mk_fvn_args_from_str(data,safe);
   if (r){
      if (new_txhash(r)) return r;
      free_txhash_args(r);
   }
   return NULL;
}

t_txhash_args * new_oat_hash_from_str(char * restrict data,const bool safe){
   t_txhash_args * const r=mk_oat_args_from_str(data,safe);
   if (r){
      if (new_txhash(r)) return r;
      free_txhash_args(r);
   }
   return NULL;
}

t_txhash_args * new_murmur_hash_from_str(char * restrict data,const bool safe){
   t_txhash_args *const r=mk_Murmur_args_from_str(data,safe);
   if (r){
      if (new_txhash(r)) return r;
      free_txhash_args(r);
   }
   return NULL;
}

////////////////////////////////////////////////////////////////////////////////

t_txhash_args * new_orchid_hash_from_hex_ex(const char * const restrict pHex,const size_t pSize){
   t_txhash_args *const r=mk_orchid_args_from_hex_ex(pHex,pSize,false);
   if (r){
      if (new_txhash(r) && ttn_hash_b16_encode(r)) return r;
      free_txhash_args(r);
   }
   return NULL;
}

bool update_orchid_hash_from_hex_ex(t_txhash_args * const restrict pArgs,const char * const restrict pHex,const size_t pSize){
   if (upd_orchid_args_hex_(pArgs,pHex,pSize)){
      if (ttn_hash_b16_decode(pArgs)){
         pArgs->type  = txhh_orchid;
         return true;
      }
      free_txhash_args(pArgs);
   }
   return false;
}

const char * txhash_gethex_ex(t_txhash_args * const restrict pArgs,size_t * const restrict pSize){
   return (gethex_ex_(pArgs,pSize));
}

const char * txhash_gethex(t_txhash_args *const restrict pArgs){
   return (gethex_ex_(pArgs,NULL));
}

////////////////////////////////////////////////////////////////////////////////

bool murmurHash3_x64_64_hash_fex(const void * const restrict v, const size_t len, t_hash * const restrict out){
   if (out){
      t_hash_ex outex=*out;
      if (v && len && murmurHash3_x64_128_hash_(v,len,&outex)){
         *out=(((const t_hash*const)(&outex))[0] ^ ((const t_hash*const)(&outex))[1]);
         return true;
      }
   }
   return false;
}

t_hash str2sdbm(const char * const restrict in,const size_t sz){
   t_hash r=0;
   (void)sdbm_hash_(in,sz,&r);
   return r;
}

bool str2sdbm_ex(const char * const restrict in,const size_t sz,t_hash * const restrict out){   
   return sdbm_hash_(in,sz,out);
}


t_hash str2djb2(const char * const restrict in,const size_t sz){
   t_hash r=0;
   (void)djb2m_hash_(in,sz,&r);
   return r;
}

bool str2djb2_ex(const char * const restrict in,const size_t sz, t_hash * const restrict out){
   return djb2m_hash_(in,sz,out);
}

t_hash str2fnv(const char * const restrict in,const size_t sz){
   t_hash r=2166136261;
   (void)fnv_hash_(in,sz,&r);
   return r;
}

bool str2fnv_ex(const char * const restrict in,const size_t sz, t_hash * const restrict out){
   return fnv_hash_(in,sz,out);
}

t_hash str2oat(const char *const restrict in,const size_t sz){
   t_hash r=0;
   (void)oat_hash_(in,sz,&r);
   return r;
}

bool str2oat_ex(const char *const restrict  in,const size_t sz,t_hash * const restrict out){
   return oat_hash_(in,sz,out);
}

t_hash str2Murmur(const char * const restrict in,const size_t sz){
   t_hash r=0;
   (void)murmurHash3_x64_64_hash_(in,sz,&r);
   return r;
}

bool str2Murmur_ex(const char * const restrict in,const size_t sz,t_hash * const restrict out){
   return murmurHash3_x64_64_hash_(in,sz,out);
}

t_hash_ex str2Murmur128(const char * const restrict in,const size_t sz){
   t_hash_ex r=0;
   (void)murmurHash3_x64_128_hash_((const void * const)in,sz,&r);
   return r;
}

t_hash str2crc32(const char * const restrict in,const size_t sz){
   t_hash r=0;
   (void)crc32_hash_(in,sz,&r);
   return r;
}

t_txhash_args * mk_txhash_args(const bool pSafe) {
   t_txhash_args * const buf = (t_txhash_args* const)tx_safe_malloc(sizeof(t_txhash_args));
   if (buf){
      buf->safe=pSafe;
      return buf;
   }
   return NULL;
}

bool add_txhash_data_ex(t_txhash_args * const restrict pArgs, char * restrict pData, const size_t pSize){
   if (pArgs && pData){
      if (!pArgs->in_data) (void)al_simple_init(&pArgs->in_data,TXHASH_ARGS_DATA_SZ_);
   TXDEBLOG(printf("%s",pData);)
   if (pArgs->safe){
      (void)al_safe_push_ex(pArgs->in_data,pData,pSize);
   } else {
      (void)al_push_ex(pArgs->in_data,pData,(ssize_t)pSize);
      }
      return true;
   }
   return false;
}

bool add_txhash_data(t_txhash_args * const restrict pArgs, char *const restrict pData){
   if (pArgs && pData){
      if (!pArgs->in_data) (void)al_simple_init(&pArgs->in_data,TXHASH_ARGS_DATA_SZ_);
         TXDEBLOG(printf("%s",pData);)
      if (pArgs->safe){
         (void)al_safe_push_array(pArgs->in_data,pData);
      } else {
         (void)al_push_array(pArgs->in_data,pData);
      }
      return true;
   }
   return false;
}

t_txhash_args * mk_orchid_args(const bool pSafe){
   t_txhash_args * const buf = mk_txhash_args(pSafe);
   if (buf){
      buf->type= txhh_orchid;
      return buf;
   }
   return NULL;
}

t_txhash_args * mk_orchid_args_from_str(char * restrict pContext,char * restrict pData,const bool pSafe){
   t_txhash_args * const buf = mk_orchid_args(pSafe);
   if (buf){
      (void)add_txhash_data(buf,pContext);
      (void)add_txhash_data(buf,pData);
      return buf;
   }
   return NULL;
}

t_txhash_args * mk_djb2_args(const bool safe){
   t_txhash_args * const r = mk_txhash_args(safe);
   if (r){
      r->out_data_hash=0;
      r->out_data_len=16;
      r->type=txhh_djb2;
      return r;
   }
   return NULL;
}

t_txhash_args * mk_djb2_args_from_str(char * restrict data,const bool safe){
   t_txhash_args * const r = mk_djb2_args(safe);
   if (r){
      (void)add_txhash_data(r,data);
      return r;
   }
   return NULL;
}

t_txhash_args * mk_fnv_args(const bool safe){
   t_txhash_args * const r =mk_txhash_args(safe);
   if (r){
      r->type=txhh_fnv;
      r->out_data_hash=2166136261;
      r->out_data_len=16;
      return (r);
   }
   return NULL;
}

t_txhash_args * mk_fvn_args_from_str(char *restrict  data,const bool safe){
   t_txhash_args * const r = mk_fnv_args(safe);
   if (r){
      (void)add_txhash_data(r,data);
      return r;
   }
   return NULL;
}

t_txhash_args * mk_oat_args(const bool safe){
   t_txhash_args * const r = mk_txhash_args(safe);
   if (r){
      r->type=txhh_oat;
      r->out_data_hash=0;
      r->out_data_len=16;
      return r;
   }
   return NULL;
}

t_txhash_args * mk_oat_args_from_str(char * restrict data,const bool safe){
   t_txhash_args * const r =mk_oat_args(safe);
   if (r){
      (void)add_txhash_data(r,data);
      return r;
   }
   return NULL;
}

t_txhash_args * mk_Murmur_args(const bool safe){
   t_txhash_args * const r = mk_txhash_args(safe);
   if (r){
      r->type=txhh_murmur;
      r->out_data_hash=0;
      r->out_data_len=16;
      return r;
   }
   return NULL;
}

t_txhash_args * mk_Murmur_args_from_str(char * restrict data,const bool safe){
   t_txhash_args * const r = mk_txhash_args(safe);
   if (r){
      (void)add_txhash_data(r,data);
      return r;
   }
   return NULL;
}

bool clear_txhash_args(t_txhash_args * const restrict pArgs){
   if (pArgs->out_data){
      if (pArgs->safe){
         (void)zm(pArgs->out_data,pArgs->out_data_len);
      } else {
         tx_safe_free(pArgs->out_data);
         pArgs->out_data=0;
      }
   }
   pArgs->out_data_len=0;
   if (pArgs->safe){
      (void)al_clear_all(pArgs->in_data);
   } else {
      (void)al_release_all(&pArgs->in_data);
   }
   (void)data_buff_zero(pArgs->out_data_hex);
   
   pArgs->ready=false;
   pArgs->type=txhh_none;
   return true;
}

bool free_txhash_args(t_txhash_args * const restrict pArgs){
   (void)clear_txhash_args(pArgs);
   if (pArgs->safe && pArgs->out_data){
      tx_safe_free(pArgs->out_data);
   }
   (void)al_free_all_and_free_list(&pArgs->in_data,true);
   (void)data_buff_free(&pArgs->out_data_hex);
   tx_safe_free(pArgs);
   return true;
}

bool reinit_orchid_args_ex(t_txhash_args ** const restrict pArgs,const bool pSafe){
   if (!(*pArgs)){
      *pArgs=mk_orchid_args(pSafe);
   } else {
      clear_txhash_args((*pArgs));
      (*pArgs)->type=txhh_orchid;
      (*pArgs)->safe=pSafe;
   }
   return (*pArgs && (*pArgs)->type==txhh_orchid);
}

bool reinit_static_orchid_args_ex(t_txhash_args * const restrict pArgs,const bool pSafe){
   if (pArgs){
      (void)clear_txhash_args(pArgs);
      pArgs->type=txhh_orchid;
      pArgs->safe=pSafe;
      return true;
   }
   return false;

}

bool reinit_orchid_args(t_txhash_args *const restrict pArgs){
   if (pArgs){
      clear_txhash_args(pArgs);
      pArgs->type= txhh_orchid;
      return true;
   }
   return false;
}

t_txhash_args * mk_orchid_args_from_hex_ex(const char *const restrict data_hex,const size_t pSize, bool pSafe){
   if (data_hex && pSize){
   t_txhash_args * const buf = mk_orchid_args(pSafe);
      if (buf){
         if (upd_orchid_args_hex_(buf,data_hex,pSize)) return (buf);
         (void)free_txhash_args(buf);
      }
   }
   return  NULL;
}

t_txhash_args * mk_orchid_args_from_hex(const char * const restrict data_hex){   
   return (data_hex?mk_orchid_args_from_hex_ex(data_hex,strlen(data_hex),false):NULL);
}

t_txhash_args * new_orchid_hash_from_hex(const char *const restrict pHex){
   return  (pHex?new_orchid_hash_from_hex_ex(pHex,strlen(pHex)):NULL);
}

bool update_orchid_hash_from_hex(t_txhash_args * const restrict pArgs ,const char * const restrict pHex){
   return (pArgs && pHex && update_orchid_hash_from_hex_ex(pArgs,pHex,strlen(pHex)));
}

bool cmp_txhash(t_txhash_args * const restrict pLeft, t_txhash_args * const restrict pRight){
   if (pLeft->ready && pRight->ready && pLeft->type==pRight->type && pLeft->out_data_len==pRight->out_data_len){
      switch (pLeft->type){
         case txhh_orchid:{
            u_char *  ld=pLeft->out_data;
            u_char *  rd=pRight->out_data;
            const size_t max=pLeft->out_data_len;
            uint32_t l=0;
            //The build-in loop unroller might do better job in optimizing this loop
            CLU_
            while (l<max){
               if (!((uint32_t)(*ld++==*rd++) && (++l))) return (false);
            }
            return true;
         }
         case txhh_sdbm:
         case txhh_djb2:
         case txhh_fnv:
         case txhh_oat:
         case txhh_murmur: {
            return (pLeft->out_data_hash==pRight->out_data_hash);
         }
         default:{
            return false;
         }
      }
   }
   return false;
}


size_t ttn_hash_b16_encode(t_txhash_args * const restrict pIO){   
   if (pIO->ready){
      t_data_buff * outhex_=pIO->out_data_hex; 
      if (!outhex_ && (pIO->out_data_hex=data_buff_new(0))) outhex_=pIO->out_data_hex;
      assert(outhex_);
      size_t l_=(outhex_->db_sz?:0);
      size_t r_=(pIO->out_data_len<<1);
      if(!l_ || l_<r_) assert(data_buff_grow(outhex_,r_+1)); 
      r_=ttn_base16_encode(
               pIO->out_data,
               pIO->out_data_len,
               outhex_->db,
               outhex_->db_sz);
      assert(outhex_->db && "ttn_hash_b16_encode failed1");
      const bool status=((outhex_->data_sz=r_) && r_==strlen(outhex_->db));
      assert(status  && "ttn_hash_b16_encode has failed2");
      return r_;
   }
   return 0;
}

size_t ttn_hash_b16_decode(t_txhash_args * const restrict pIO){
   size_t r_;
   size_t decoded=0;
   t_data_buff * const inhex_=pIO->out_data_hex;           
   if (pIO->out_data && inhex_ && (r_=inhex_->data_sz) && pIO->out_data_len==(r_>>1)) 
      pIO->ready=(decoded = ttn_base16_decode(
         inhex_->db,
         r_,
         pIO->out_data,
         pIO->out_data_len));
   return (decoded);
}
