/**
 * $Id$
 */

#ifndef TTN_BSWAP_HXX
#define  TTN_BSWAP_HXX

#include <sys/endian.h>
#include "global.h"

namespace titan_v3{

   namespace tools{

      /**
       * @fn bswap128
       * @abstract bswap for uint128_t
       * @note currently freebsd doesn't provide native function such as this so remove it when necessary
       */
      TX_CPP_INLINE_LIB
      uint128_t bswap128( uint128_t x ) noexcept {
         uint64_t * const s= reinterpret_cast< uint64_t* const>( & x );
         s[1]=(s[1] + s[0]);
         s[0]=(s[1] - s[0]);
         s[1]=be64toh(s[1] - s[0]);
         s[0]=be64toh(s[0]);
         return x;
      }

   } /* tools namespace */

} /* titan_v3 namespace */

#endif /* TTN_BSWAP_HXX */

/* vim: set ts=4 sw=4 et : */

