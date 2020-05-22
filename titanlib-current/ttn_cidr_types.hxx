/**
 * $Id$
 */

#ifndef TTN_CIDR_TYPES_HXX
#define TTN_CIDR_TYPES_HXX

#include <string>
#include <iostream>
#include <iomanip>
#include <vector>
#include <utility>
#include <cstdint>
#include <cmath>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/endian.h>
#include <netdb.h>
#include "ttn_tools.hxx"
#include "ttn_traits.hxx"
#include "global.h"
#include "txbase16.h"
#include <unordered_set>
#include <unordered_map>

/* C++17 might simplify nested namespace definition */
namespace titan_v3 { namespace cidr {
    /**
     * Intent: Model ipv6/ipv4 addresses and ranges of the same
     */

    /* consts */
    constexpr ipv6_t        IPV6_MAX_ADDR           { (~(ipv6_t{})) };
    constexpr ipv6_t        IPV6_MIN_ADDR           { ((ipv6_t{(1UL<<56)}<<64)) };
    constexpr prefix_t      IPV6_MAX_PREFIX         { sizeof( ipv6_t ) << 3 };
    constexpr prefix_t      IPV4_MAX_PREFIX         { sizeof( ipv4_t ) << 3 } ;
    constexpr ipv4_t        ipv4_netmask_31b        { INADDR_BROADCAST - INT_FAST32_MAX };
    constexpr ipv6_t        ipv6_netmask_127b       { ipv6_t{(UINT_FAST64_MAX - INT_FAST64_MAX)} << 64 }; 
    constexpr ipv4_t        IPV4_MIN_ADDR           { (0x01<<24) };

    /* consts for cidr_checks */
    constexpr struct in6_addr   ip6_loopback   = IN6ADDR_LOOPBACK_INIT;

    constexpr struct in6_addr   ip6_anyaddr = IN6ADDR_ANY_INIT;

    constexpr struct in6_addr   ip6_v4_anyaddr = {{{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 }}};

    constexpr struct in6_addr   ip6_v4_noaddr = {{{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}};

    constexpr struct in6_addr   ip6_v4_localhost = {{{
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0xff, 0xff, 0x7f, 0x00, 0x00, 0x01 }}};

    constexpr struct in6_addr   ip6_noaddr = {{{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }}};

    namespace factory
    {
        /**
         * @fn make_ipaddr (template spec)
         * @abstract make raw_ipaddr_t
         * @param v[in] struct inet_addr & 
         * @return raw_ipaddr_t
         */
        extern raw_ipaddr_t make_ipaddr(const struct in_addr &) noexcept;

        /**
         * @fn make_ipaddr (template spec)
         * @abstract make raw_ipaddr_t
         * @param v[in] struct in6_addr & 
         * @return raw_ipaddr_t
         */
        extern raw_ipaddr_t make_ipaddr(const struct in6_addr &) noexcept;

    } /* factory ns */

    /**
     * @struct raw_addr_t
     * @abstract raw addr (ipv4/ipv6) : Model only the essential data
     * @NOTE it implies the host byte order 
     */
    struct raw_ipaddr_t:c_raw_ipaddr_t 
    {
         /**
          * Keep this as a POD (the base type c_raw_ipaddr_t is actually a union)
          * data MUST be in host byte order
          */
         using c_raw_ipaddr_t::v6;
         using c_raw_ipaddr_t::v4;

        /**
         * @abstract default constructor
         */
        constexpr raw_ipaddr_t() noexcept : c_raw_ipaddr_t{/*zero*/}
        {
            v6 = 0;
        }

        /**
         * @abstract template constructor
         * @param v[in] of type [ipv4_t,ipv6_t]
         * @note it is a type (T) based template ctor don't make it explicit
         */
        template <typename T, typename std::enable_if<tools::traits::is_ip_pod<T>::value>::type* = nullptr>
        constexpr raw_ipaddr_t(const T & v) noexcept : raw_ipaddr_t{/*zero*/}
        {
            v6 = v;/* assign */
        }

        /**
         * @abstract template constructor
         * @param v[in] of type inet_structs
         * @note it is a type (T) based template ctor don't make it explicit
         */
        template <typename T, typename std::enable_if<tools::traits::is_inet_struct<T>::value>::type* = nullptr>
        constexpr raw_ipaddr_t(const T & a ) noexcept : raw_ipaddr_t{factory::make_ipaddr(a)}
        {
            /* empty */
        }

        /**
         * @abstract cpy constructor (required)
         */
        constexpr raw_ipaddr_t(const raw_ipaddr_t & v) noexcept : c_raw_ipaddr_t{/*zero*/}
        {
            v6 = v.v6;
        }

        /**
         * @abstract converting cpy constructor
         * @note don't make it explicit
         */
        constexpr raw_ipaddr_t(const c_raw_ipaddr_t & v) noexcept : c_raw_ipaddr_t{/*zero*/}
        {
            v6 = v.v6;
        }

        /**
         * @abstract move constructor (required)
         */
        raw_ipaddr_t(raw_ipaddr_t && v ) noexcept : c_raw_ipaddr_t{/*zero*/}
        {
            v6 = std::move(v.v6);
        }

        /**
         * @abstract converting move constructor
         * @note don't make it explicit
         */
        raw_ipaddr_t(c_raw_ipaddr_t && v ) noexcept : c_raw_ipaddr_t{/*zero*/}
        {
            v6 = std::move(v.v6);
        }

        /**
         * @abstract copy assignment operator
         */
        inline raw_ipaddr_t& operator=(const raw_ipaddr_t & a) noexcept
        {
            this->v6 = a.v6;
            return *this;
        }

        /**
         * @abstract conv/copy assignment operator
         */
        inline raw_ipaddr_t& operator=(const c_raw_ipaddr_t & a) noexcept
        {
            this->v6 = a.v6;
            return *this;
        }

        /**
         * @abstract move assignment operator
         */
        inline raw_ipaddr_t& operator=(raw_ipaddr_t && a) noexcept
        {
            this->v6 = std::move(a.v6); 
            return *this;
        }

        /**
         * @abstract implicit typecast operator
         * @return ipv6_t
         */
        inline operator ipv6_t() const noexcept
        {
            return this->v6; 
        }

        /**
         * @abstract compare eq
         */
        inline bool operator==( const raw_ipaddr_t & rh ) const noexcept
        {
            return (v6 == rh.v6);
        }

        /**
         * @abstract compare ne
         */
        inline bool operator!=( const raw_ipaddr_t & rh ) const noexcept
        {
            return (v6 != rh.v6);
        }

    }; /* raw_addr_t */

    /**
    * @struct cidr_t
    * @abstract CIDR type : Use CIDR concept for addr plus prefix
    * @NOTE it implies the host byte order 
    */
    struct cidr_t
    {
        /* data MUST be in host byte order */
        raw_ipaddr_t  addr{};
        prefix_t      prefix{ IPV4_MAX_PREFIX };   /* 0 -> 128 */

        /**
         * @abstract default ctor
         */
        constexpr cidr_t() = default;

        /**
         * @template constructor
         * @abstract template constructor
         * @param a[in] of type [ipv4_t,ipv6_t,raw_ipaddr_t, struct inet_addr,struct in6_addr]
         * @param m[in] prefix_t
         */
        template <typename T, typename std::enable_if<tools::traits::is_valid_cidr_value<T>::value>::type* = nullptr>
        constexpr cidr_t(const T & a, const prefix_t & p ) noexcept :    addr {a},
                                                                        prefix{p}
        {
            /* empty */
        }

        template <typename T, typename std::enable_if<tools::traits::is_valid_cidr_value<T>::value>::type* = nullptr>
        constexpr cidr_t(T && a, const prefix_t & p ) noexcept :    addr {std::move(a)},
                                                                    prefix{p}
        {
            /* empty */
        }

        /**
         * @abstract cpy ctor (required) 
         */
        constexpr cidr_t(const cidr_t & a) noexcept : addr{a.addr}, 
                                                      prefix{a.prefix}
        {
            /* empty */
        }

        /**
         * @abstract conv cpy ctor
         */
        constexpr explicit cidr_t(const c_cidr_t & a) noexcept : addr{a.addr}, 
                                                                 prefix{a.prefix}
        {
            /* empty */
        }

        /**
         * @abstract mov ctor (required) 
         */
        cidr_t(cidr_t && a) noexcept : addr{std::move(a.addr)}, 
                                       prefix{std::move(a.prefix)}
        {
            /* empty */
        }

        /**
         * @abstract copy assignment operator
         */
        inline cidr_t & operator=(const cidr_t & c) noexcept 
        {
            addr = c.addr;
            prefix = c.prefix;
            return *this;
        }

        /**
         * @abstract move assignment operator
         */
        inline cidr_t & operator=(cidr_t && c) noexcept
        {
            addr = std::move(c.addr);
            prefix = std::move(c.prefix);
            return *this;
        }

        /**
         * @abstract implicit typecast operator 
         */
        inline operator const raw_ipaddr_t&() const noexcept
        {
            return this->addr;
        }

        /**
         * @abstract implicit typecast operator 
         */
        inline operator const c_cidr_t*() const noexcept
        {
            return reinterpret_cast<const c_cidr_t*>(this);
        }

        /**
         * @abstract compare eq
         */
        inline bool operator==( const c_cidr_t & rh ) const noexcept
        {
            return ( addr == rh.addr && 
                     prefix == rh.prefix );
        }

        /**
         * @abstract compare ne
         */
        inline bool operator!=( const c_cidr_t & rh ) const noexcept
        {
            return ( addr != rh.addr ||
                     prefix != rh.prefix );
        }

    }; /* cidr_t */


    /**
     * @template status_pair_t
     * @abstract provides a basis for the return type: a pair of  <status_of_exec, result>
     */
    using raw_ipaddr_pair_t =   tools::status_pair_t<raw_ipaddr_t>;
    using cidrs_t =             std::vector<cidr_t>;
    using cidrs_pair_t =        tools::status_pair_t<cidrs_t>;
    using cidr_pair_t =         tools::status_pair_t<cidr_t>;
    using lookup_pair_t =       tools::status_pair_t<raw_ipaddr_t>; /*optional<t>*/
    using raw_addr_uset_t =     std::unordered_set<raw_ipaddr_t>;
    using raw_addr_map_uuid_t = std::unordered_map<raw_ipaddr_t, titan_v3::tools::ttn_uuid_t>;
    enum class raw_ipaddr_hint
    {
        ipv4,
        ipv6,
        hex,
    };


} /* cidr namespace */

} /* titan_v3 namespace */

#endif /* TTN_CIDR_TYPES_HXX */
/* vim: set ts=4 sw=4 et : */

