/*
 * $Id$
 *
 */
#ifndef B16_H_
#define B16_H_
#include "global.h"
#include <sys/endian.h>

/**
 * @name ttn_base16_encode
 * @abstract hex encode the src data into the dst buffer
 * @param src
 * @param srcsz
 * @param dst
 * @param dstsz
 * @return encoded size
 */
TXATR size_t ttn_base16_encode(const void * const , const size_t, char * const , const size_t);
/**
 * @name ttn_base16_decode
 * @abstract hex decode the src data into the dst buffer 
 * @param src
 * @param srcsz
 * @param dst
 * @param dstsz
 * @return decoded size
 */
TXATR size_t ttn_base16_decode(const char * const , const size_t, void * const , const size_t);
/**
 * @name ttn_base16_encode_uint32
 * @abstract hex encode the src data (uint32_t value) into the dst buffer
 * @param src
 * @param dst
 * @param dstsz
 * @return t/f
 */
TXATR bool ttn_base16_encode_uint32(uint32_t,char * const , const size_t);
/**
 * @name ttn_base16_decode_uint32
 * @abstract hex decode the src data into the dst buffer (uint32_t ptr)
 * @param src
 * @param srcsz
 * @param dst
 * @return t/f
 */
TXATR bool ttn_base16_decode_uint32(const char * const , const size_t,uint32_t * const );
/**
 * @name ttn_base16_encode_uint64
 * @abstract hex encode the src data (uint64_t value) into the dst buffer
 * @param src
 * @param dst
 * @param dstsz
 * @return t/f
 */
TXATR bool ttn_base16_encode_uint64(uint64_t,char * const , const size_t);
/**
 * @name ttn_base16_decode_uint64
 * @abstract hex decode the src data into the dst buffer (uint64_t ptr)
 * @param src
 * @param srcsz
 * @param dst
 * @return t/f
 */
TXATR bool ttn_base16_decode_uint64(const char * const , const size_t,uint64_t * const );

#endif /* B16_H_ */
