/*
 * $Id$
 */
#ifndef TXHASH_H_
#define TXHASH_H_

#ifdef __cplusplus
extern "C" {
#endif
#include "global.h"
#include "txal.h"


#define TXHASH_ARGS_DATA_SZ_ 64

#define ORCHID_BIT100      14
#define ORCHID_OUT_SZ      16

typedef struct {
   t_txhh            type;
   bool              ready;
   bool              safe;
   t_hash            out_data_hash;
   size_t            out_data_len;
   size_t            out_data_safe_size; 
   t_a_items_list *  in_data;   
   uint8_t        *  out_data;
   t_data_buff    *  out_data_hex;
} t_txhash_args;


#ifdef __cplusplus
}
#endif

TXATR bool murmurHash3_x64_64_hash_fex(const void * const , const uint64_t, t_hash * const );
TXATR t_hash str2sdbm(const char * const ,const size_t);
TXATR bool  str2sdbm_ex(const char * const,const size_t,t_hash * const);
TXATR t_hash str2djb2(const char * const ,const size_t);
TXATR bool str2djb2_ex(const char * const ,const size_t,t_hash * const);
TXATR t_hash str2fnv(const char * const ,const size_t);
TXATR bool str2fnv_ex(const char * const ,const size_t,t_hash * const);
TXATR t_hash str2oat(const char *const ,const size_t);
TXATR bool str2oat_ex(const char *const ,const size_t,t_hash * const);
TXATR t_hash str2Murmur(const char * const ,const size_t);
TXATR bool str2Murmur_ex(const char * const ,const size_t,t_hash * const);
TXATR t_hash_ex str2Murmur128(const char * const ,const size_t);
TXATR t_hash str2crc32(const char * const ,const size_t);
TXATR t_txhash_args * mk_txhash_args(const bool);
TXATR bool add_txhash_data_ex(t_txhash_args * const, char * const, const size_t);
TXATR bool add_txhash_data(t_txhash_args * const, char *const);
TXATR t_txhash_args * mk_orchid_args(const bool);
TXATR t_txhash_args * mk_orchid_args_from_str(char * ,char *,const bool );
TXATR t_txhash_args * mk_djb2_args(const bool);
TXATR t_txhash_args * mk_djb2_args_from_str(char * ,const bool);
TXATR t_txhash_args * mk_fnv_args(const bool);
TXATR t_txhash_args * mk_fvn_args_from_str(char *,const bool);
TXATR t_txhash_args * mk_oat_args(const bool);
TXATR t_txhash_args * mk_oat_args_from_str(char *,const bool);
TXATR t_txhash_args * mk_Murmur_args(const bool);
TXATR t_txhash_args * mk_Murmur_args_from_str(char * ,const bool);
TXATR bool clear_txhash_args(t_txhash_args * const);
TXATR bool free_txhash_args(t_txhash_args * const);
TXATR bool reinit_orchid_args_ex(t_txhash_args ** const ,const bool);
TXATR bool reinit_static_orchid_args_ex(t_txhash_args * const ,const bool);
TXATR bool reinit_orchid_args(t_txhash_args *const  );
TXATR t_txhash_args * mk_orchid_args_from_hex_ex(const char *const ,const size_t, bool);
TXATR t_txhash_args * mk_orchid_args_from_hex(const char * const ); 
TXATR bool new_txhash(t_txhash_args *const);
TXATR t_txhash_args * new_orchid_hash_from_str(char *,char *,const bool);
TXATR t_txhash_args *new_orchid_hash_from_hex_ex(const char *const ,const size_t);
TXATR bool update_orchid_hash_from_hex_ex(t_txhash_args *const ,const char *const ,const size_t);
TXATR t_txhash_args * new_djb2_hash_from_str(char * ,const bool);
TXATR t_txhash_args * new_fnv_hash_from_str(char *,const bool);
TXATR t_txhash_args * new_oat_hash_from_str(char * ,const bool);
TXATR t_txhash_args * new_murmur_hash_from_str(char *,const bool);
TXATR t_txhash_args * new_orchid_hash_from_hex(const char *const );
TXATR bool update_orchid_hash_from_hex(t_txhash_args * const  ,const char * const );
TXATR bool cmp_txhash(t_txhash_args * const  , t_txhash_args * const );
TXATR const char * txhash_gethex_ex(t_txhash_args * const ,size_t * const );
TXATR const char * txhash_gethex(t_txhash_args * const );
TXATR size_t ttn_hash_b16_encode(t_txhash_args * const);
TXATR size_t ttn_hash_b16_decode(t_txhash_args * const);

#endif /* TXHASH_H_ */
