/**
 * $Id$
 */

#ifndef TTN_TOOLS_STD_HXX
#define TTN_TOOLS_STD_HXX
#include <memory>
#include <sys/param.h>
#include "global.h"
#include "ttn_cidr_types.hxx"
#include "ttn_uuid.hxx"
#include "ttn_bswap.hxx"

namespace std
{

    /* @ref http://en.cppreference.com/w/cpp/language/extending_std */

#if ( __cplusplus <= 201103L )
    /**
     * @abstract add missing in c++11 make_unique
     */
    template<typename T, typename... Args>
    constexpr std::unique_ptr<T> make_unique(Args&&... args){

        return std::unique_ptr<T>(new T(std::forward<Args>(args)...));
    };

#endif 


   /**
    * @abstract expand std hash to include raw_ipaddr_t
    */
    template <> struct hash<titan_v3::cidr::raw_ipaddr_t> {
        t_hash_ex  operator()(const titan_v3::cidr::raw_ipaddr_t & x) const noexcept {
            return titan_v3::tools::bswap128(x);
        }
    };

   /**
    * @abstract expand std hash to include raw_ipaddr_t
    */
    template <> struct hash<titan_v3::tools::ttn_uuid_t> {
        const t_uuid & operator()(const titan_v3::tools::ttn_uuid_t & uuid) const noexcept {
            return uuid;
        }
    };

#if ( __FreeBSD_version < MIN_OS_FB_11_1 )
   /* on FB 11.1 and up this type of specialization is already defined */

   /**
    * @abstract expand std hash to include raw_ipaddr_t
    */

   template <> struct hash<t_uuid> {
      t_hash_ex  operator()(const t_uuid & uuid) const noexcept {
         return uuid;
      }
   };

#endif 

} /* std ns */

#endif /* TTN_TOOLS_STD_HXX */

/* vim: set ts=4 sw=4 et : */

