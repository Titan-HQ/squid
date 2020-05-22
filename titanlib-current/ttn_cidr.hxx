/**
 * $Id$
 */

#ifndef TTN_CIDR_HXX
#define TTN_CIDR_HXX

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
#include "ttn_cidr_types.hxx"

/* C++17 might simplify nested namespace definition */
namespace titan_v3 { namespace cidr {

    /**
     * @warning all cidrs and raw_ipaddrs MUST be in the host byte order 
     * see ttn_cidr_types.hxx
     */

    /** 
     * @namespace checks
     * @abstract Validation and is_XXXX metrhods for cidr_t and raw_ipaddr_t instances. 
     * @todo: this namespace (and/or class) is redundant, it clutters the name path
     */
    namespace checks
    {
        /**
         * @template calc_netmask
         * @abstract calculate netmask (either in the host <default> or network order)
         * @param p[in]: prefix_t
         * @return netmask 
         * @note : C++11[n3337:5.8] && RFC3021 
         * http://www.open-std.org/jtc1/sc22/wg21/docs/papers/2012/n3337.pdf
         */
        template <  typename R,
                    const bool network_order=false,
                    typename std::enable_if<tools::traits::is_ip_t<R>::value>::type* = nullptr,
                    const prefix_t max_=( sizeof( R ) << 3 ),
                    const bool IPV4=tools::traits::is_ipv4_t<R>::value,
                    const R netmask=( IPV4 ? INADDR_BROADCAST : IPV6_MAX_ADDR ),
                    const R netmask_rfc3021=( IPV4 ? ipv4_netmask_31b : ipv6_netmask_127b ) >
        TX_CPP_INLINE_LIB
        R calc_netmask(const prefix_t p) noexcept 
        {

            switch ( p ){
                case 0: 
                    return 0;

                case 1 ... ( max_-1 ) : {

                    if (! network_order ){
                        const prefix_t px_{ static_cast<prefix_t>( max_ - p ) };
                        /**
                         * C++11[n3337:5.8]
                         * see also RFC 3021
                         */
                        return (    ( max_ - 2 ) >= px_  ?
                                    ( netmask << px_ )   :
                                    ( netmask_rfc3021 )    );

                    }

                    /**
                     * C++11[n3337:5.8]
                     * see also RFC 3021
                     */
                    return (    ( max_ - 2 ) >= p   ?
                                ( netmask << p )    :
                                ( netmask_rfc3021 )   ); 
                }

                case max_: 
                    return ( netmask );

                default: 
                    return 0;
            }
        }
        /** 
         * @fn is_AnyAddr()
         * @abstract any addr is simply 0 
         * @param a_ip[in] : value of type of raw_ipaddr_t or c_raw_ipaddr_t and it must be in host byte order
         * @return bool
         */
        template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr>
        TX_CPP_INLINE_LIB bool is_AnyAddr(T a_ip ) noexcept
        {
            struct in6_addr pin6={};

            memcpy( &pin6, &a_ip.v6, sizeof(struct in6_addr) );

            return static_cast<bool>( IN6_IS_ADDR_UNSPECIFIED( &pin6 ) );
        }

        /** 
         * @fn is_AnyAddr()
         * @abstract any addr is simply 0 
         * @param c[in] : value of type of cidr_t and it must be in host byte order
         * @return bool
         */
        TX_CPP_INLINE_LIB  bool is_AnyAddr(cidr_t  c) noexcept
        {
            return (is_AnyAddr(c.addr));
        }

        /**
         * @abstract is non zero/empty
         * @param a[in] : value of type of raw_ipaddr_t or c_raw_ipaddr_t
         * @return bool
         */
        template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr> 
        TX_CPP_INLINE_LIB bool is_nz(T a) noexcept 
        {
            return (!is_AnyAddr(a)); 
        }

        /** 
         * @fn is_localhost()
         * ip_v6: ::1
         */
        TX_CPP_INLINE_LIB bool is_localhost( const struct in6_addr * const addr ) noexcept 
        {
            if ( addr ) { 

                return (    IN6_IS_ADDR_LOOPBACK( addr ) ||
                            IN6_ARE_ADDR_EQUAL( addr, &ip6_v4_localhost ) );
            }

            /* error is not the same as not a loopback */
            return false;
        }

        /** 
         * @fn is_localhost()
         * ip_v4: 127.0.0.1
         */
        TX_CPP_INLINE_LIB bool is_localhost( const struct in_addr * const addr ) noexcept 
        {
            if ( addr ) {

                return IN_LOOPBACK(addr->s_addr);
            }

            /* error is not the same as not a loopback */
            return false;
        }

        /**
         * @fn is_ipv4
         * @abstract checks if current raw_ipaddr is ipv4
         * @param a[in] : value of type of raw_ipaddr_t or c_raw_ipaddr_t and it must be in host byte order
         * @return bool
         */
        template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr> 
        TX_CPP_INLINE_LIB bool is_ipv4(T a) noexcept 
        {
           /**
            * We have to use this test to exclude addresses from the 0.0.0.0/8 address block
            * as invalid for our use
            * https://tools.ietf.org/html/rfc5735 
            *
            * Also, we have to use htonl (bswap) cause 
            * 67305984d is always greater than 1d
            * but 67305984d in network notation stands for 131844d (0.1.2.3)
            * and 1d        in network notation stands for 16777216d (1.0.0.0)
            * INADDR_BROADCAST stands for 0xffffffff (255.255.255.255) 
            */
            
            return ( (a.v6 <= INADDR_BROADCAST) && (htonl(a.v4) >= IPV4_MIN_ADDR ) );
        }

        /**
         * @fn is_ipv4  
         * @abstract checks if a given CIDR contain an ipv4 address 
         * @param c[in] cidr_t it must be in host byte order
         * @return bool
         */
        TX_CPP_INLINE_LIB bool is_ipv4(cidr_t c) noexcept 
        {
            return is_ipv4(c.addr);
        }

        /**
         * @fn is_ipv6
         * @abstract checks if current raw_ipaddr is ipv6
         * @param a[in] : value of type of raw_ipaddr_t or c_raw_ipaddr_t and it must be in host byte order
         * @return bool
         * @note the ipv6 loopback address is also a valid ipv6 address similarly 
         * as in case of the ipv4 loopback addresses
         */
        template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr> 
        TX_CPP_INLINE_LIB bool is_ipv6(T a ) noexcept
        {
            if (  !is_AnyAddr(a) && !is_ipv4(a) ) {

                struct in6_addr ip6{};
                memcpy( &ip6, &a.v6, sizeof ip6 );

                return (    IPV6_MIN_ADDR <= tools::bswap128(a.v6) || 
                            is_localhost( &ip6 )    );
            }

            return false ;
        }

        /**
         * @fn is_ipv6
         * @abstract checks if a given CIDR contain an ipv6 address 
         * @param c[in] cidr_t it must be in host byte order
         * @return bool
         */
        TX_CPP_INLINE_LIB bool is_ipv6(cidr_t c) noexcept
        {
            return is_ipv6(c.addr);
        }

        /**
         * @fn is_valid
         * @abstract checks if current raw_ipaddr is valid :
         *      - ipv4 >0x01000000 && <=INADDR_BROADCAST
         *      - ipv6 >0
         * @param a[in] : value of type of raw_ipaddr_t or c_raw_ipaddr_t and it must be in host byte order
         * @return bool
         */
        TX_CPP_INLINE_LIB bool is_valid(raw_ipaddr_t a) noexcept 
        {
            return ( is_ipv4( a ) || is_ipv6( a ) );
        }

        /**
         * @fn is_host
         * @param c[in] : value of type of cidr_t and it must be in host byte order
         */
        TX_CPP_INLINE_LIB  bool is_host(cidr_t c) noexcept 
        {
            return (    is_ipv4( c )                    ?

                        ( IPV4_MAX_PREFIX==c.prefix )   :

                        ( IPV6_MAX_PREFIX==c.prefix )       );
        }

        /**
         * @fn is_network
         * @param c[in] : value of type of cidr_t and it must be in host byte order
         */
        TX_CPP_INLINE_LIB  bool is_network(cidr_t c) noexcept 
        {
            return !is_host(c);
        }

        /**
         * @fn get_netmask
         * @abstract returns a netmask of a given CIDR 
         * @param c[in] cidr_t it must be in host byte order
         * @return raw_ipaddr_t
         */
        TX_CPP_INLINE_LIB raw_ipaddr_t get_netmask(cidr_t c) noexcept 
        {
            return (    is_ipv4( c )                                        ?

                        htonl(calc_netmask<ipv4_t>( c.prefix ) )            :

                        tools::bswap128(calc_netmask<ipv6_t>( c.prefix ) )   );
        }

        /**
         * @fn get_network
         * @abstract returns a network address of a given CIDR
         * @param c[in] cidr_t it must be in host byte order
         * @return raw_ipaddr_t
         */
        TX_CPP_INLINE_LIB raw_ipaddr_t get_network(cidr_t c) noexcept 
        {
            return ( c.addr & get_netmask(c));
        }

        /**
         * @fn get_broadcast
         * @abstract returns a broadcast address of a given CIDR (aka max range)
         * @param c[in] cidr_t it must be in host byte order
         * @return raw_ipaddr_t
         */
        TX_CPP_INLINE_LIB raw_ipaddr_t get_broadcast(cidr_t  c) noexcept 
        {
            return (    is_ipv4( c )                                                            ?

                        ( c.addr.v4 | htonl( ~( calc_netmask<ipv4_t>( c.prefix ) ) ) )          :

                        ( c.addr.v6 | tools::bswap128( ~(calc_netmask<ipv6_t>( c.prefix ) ) ) )     );
        }


        /**
         * @fn belongs_to
         * @abstract checks if a r network belongs to the wider l network
         * @param l[in] cidr_t it must be in host byte order
         * @param r[in] cidr_t it must be in host byte order
         * @return bool
         */
        template<typename A=raw_ipaddr_t>
        TX_CPP_INLINE_LIB 
        bool belongs_to(    const cidr_t & l_,
                            const A & r_        ) noexcept
        {
            return  (   belongs_to( l_,  get_network(r_) )     && 

                        get_broadcast(l_) >= get_broadcast(r_)  /* it is not absolutely necessary */  );
        }

        /**
         * @fn belongs_to
         * @abstract checks if a given address belongs to the network defined by a given CIDR
         * @param l[in] cidr_t it must be in host byte order
         * @param r[in] raw_ipaddr_t it must be in host byte order
         * @return bool
         */
        template <>
        inline 
        bool belongs_to(   const cidr_t &  l_,
                           const raw_ipaddr_t & r_ ) noexcept
        {
            return ( (static_cast<ipv6_t>(r_) & get_netmask(l_)) == get_network(l_) );
        }

        /** 
         * @fn is_broadcast
         * ip_v4: 0xffffffff : broadcast
         * ip_v6: ::ffff:ffff:ffff   ..... which is the ipv4 broadcast mapped to Ipv6
         */
        TX_CPP_INLINE_LIB
        bool is_broadcast( const raw_ipaddr_t & a_ip ) noexcept 
        {

            if (    is_ipv4(a_ip)               &&

                    INADDR_BROADCAST == a_ip.v4     ) {

                return true;
            }

            struct in6_addr pin6{};

            memcpy( &pin6, &a_ip.v6, sizeof(struct in6_addr) );

            return (    IN6_ARE_ADDR_EQUAL( &pin6, &ip6_noaddr )    ||

                        IN6_ARE_ADDR_EQUAL( &pin6, &ip6_v4_noaddr )     );

        }

        /** 
         * @fn is_localhost()
         * ip_v4: 127.0.0.1
         * ip_v6: ::1
         */
        TX_CPP_INLINE_LIB
        bool is_localhost( const raw_ipaddr_t & a_ip ) noexcept 
        {
            if ( is_ipv4(a_ip) ) {

                return IN_LOOPBACK( ntohl(a_ip.v4) );
            }

            struct in6_addr pin6{};

            memcpy( &pin6, &a_ip.v6, sizeof( struct in6_addr ) );

            return is_localhost( &pin6 );
        }

        bool is_ipv6_sitelocal( const raw_ipaddr_t &);
        bool is_ipv6_auto_sitelocal( const raw_ipaddr_t &); 

        template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr>
        TX_CPP_INLINE_LIB void reset(T & a) noexcept
        {
            a.v6=0;
        }

        TX_CPP_INLINE_LIB void reset(cidr_t & c) noexcept
        {
            reset(c.addr);
            c.prefix=IPV4_MAX_PREFIX;
        }
    }; /* checks */

    /**
     * @namespace  factory
     * @abstract a bundle of tool methods 
     * @todo: this namespace (and/or class) is redundant, it clutters the name path
     */
    namespace factory
    {
        /**
         * @abstract convert to hex string without the 0x prefix
         * @param a[in] : value of type of raw_ipaddr_t or c_raw_ipaddr_t and it must be in host byte order
         * @todo: unify convertion, use the same c++ interface
         */
        template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr> 
        TX_CPP_INLINE_LIB  std::string to_hex(T a) noexcept 
        {
            if (checks::is_ipv4(a)){

               char iphex[9]={};

               ttn_base16_encode_uint32( bswap32(a.v4), iphex, sizeof(iphex) );

               return iphex;
            } 

            return tools::functors::tos{tools::bswap128(a.v6),false};
        }

        /**
        * @fn to_string
        * @abstract returns a string representation of a given ip addr
        * @param a[in] : value of type of raw_ipaddr_t or c_raw_ipaddr_t and it must be in host byte order
        * @return std::string
        */
        template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr>
        TX_CPP_INLINE_LIB std::string to_string(T a) noexcept
        {
            char l_buff[ INET6_ADDRSTRLEN ]={};

            const auto af = (   checks::is_ipv4(a)  ?
                                AF_INET             :
                                AF_INET6                );

            if ( inet_ntop( af, &a.v6, l_buff, sizeof( l_buff) ) ) {

                return l_buff;
            }

            return {};
        }

        /**
        * @fn to_string
        * @abstract returns a string representation of a given CIDR
        * @param c[in] cidr_t it must be in host byte order
        * @return std::stirng 
        */
        TX_CPP_INLINE_LIB std::string to_string(cidr_t c) noexcept 
        {
            std::string ret_str = to_string(static_cast<const raw_ipaddr_t&>(c));

            if (ret_str.size()) {

                ret_str+="/"+std::to_string(c.prefix );
            }

            return ret_str;
        }

        /* anonymous namespace / private */
        namespace 
        {
            /**
             * @fn get_prefix
             * @abstract get network prefix from the netmask
             * Assumption that "mask" really is a mask, the subnet addres part is all zeros
             * @param mask[in] : value of type of raw_ipaddr_t and it must be in host byte order
             */
            TX_CPP_INLINE_LIB prefix_t get_prefix(raw_ipaddr_t mask) noexcept
            {
                if ( checks::is_ipv4(mask) ) {

                    return static_cast<prefix_t>( ttn_bitcount32( mask.v4 ) );
                }

                std::array<uint64_t, sizeof( ipv6_t ) / sizeof( uint64_t )> raw{};

                memcpy( raw.data(), &mask.v6, std::min( sizeof(ipv6_t), raw.max_size() * sizeof(decltype(raw)::value_type) ) );

                /*Q: what about upper 64 bits in this final case?*/
                /* TODO: Create tests for ipv6 case*/
                return  static_cast<prefix_t>(  raw[0] == UINT64_MAX                                ?

                                                ( IPV6_MAX_PREFIX >> 1 ) + ttn_bitcount64( raw[1] ) :

                                                ttn_bitcount64( raw[0] )                                  );
            }

        }; /* namespace anonymous */

        /**
         * @fn make_ipaddr (template spec)
         * @abstract make raw_ipaddr_t
         * @param v[in] struct inet_addr & 
         * @return raw_ipaddr_t
         */
        TX_CPP_INLINE_LIB raw_ipaddr_t make_ipaddr(const struct in_addr & v) noexcept
        {
            ipv4_t a{};

            memcpy( &a, &v, std::min( sizeof( struct in_addr ), sizeof( ipv4_t ) ) );

            return a;
        }

        /**
         * @fn make_ipaddr (template spec)
         * @abstract make raw_ipaddr_t
         * @param v[in] struct in6_addr & 
         * @return raw_ipaddr_t
         */
        TX_CPP_INLINE_LIB raw_ipaddr_t make_ipaddr(const struct in6_addr & v) noexcept
        {
            c_raw_ipaddr_t a{};

            memcpy( &a.v6, &v, std::min( sizeof( struct in6_addr ), sizeof( ipv6_t ) ) );

            if ( !IN6_IS_ADDR_V4MAPPED(&v) ) {

                if ( checks::is_ipv4( a ) ) {

                        return a.v4;
                }

                return a.v6;
            }

            /* we will strip the mapping word [0xff,0xff] and effectively turn it into the v4 */

            a.v6 = tools::bswap128( a.v6 );

            a.v4 = htonl( a.v4 );

            a.v6 &= 0x0ffffffff;

            return a;
        }

        /**
         * @fn make_ipaddr
         * @abstract make raw_ipaddr_t
         * @param v[in] struct sockaddr_in6 & 
         * @return raw_ipaddr_t
         */
        TX_CPP_INLINE_LIB raw_ipaddr_t make_ipaddr(const struct sockaddr_in6 & v) noexcept
        {
            return make_ipaddr(v.sin6_addr);
        }

        /**
         * @fn make_ipaddr
         * @abstract make raw_ipaddr_t
         * @param v[in] struct sockaddr_in & 
         * @return raw_ipaddr_t
         */
        TX_CPP_INLINE_LIB raw_ipaddr_t make_ipaddr(const struct sockaddr_in & v) noexcept
        {
            return make_ipaddr(v.sin_addr);
        }

        /**
         * @fn make_ipaddr
         * @abstract make raw_ipaddr_t
         * @param v[in] struct addrinfo & 
         * @return raw_ipaddr_t
         */
        TX_CPP_INLINE_LIB raw_ipaddr_t make_ipaddr(const struct addrinfo & v) noexcept 
        {

            if ( v.ai_addr ) {

               switch (v.ai_family){

                   case AF_INET:
                   {
                       struct sockaddr_in addr{};

                       memcpy( &addr, v.ai_addr, sizeof(struct sockaddr_in) );

                       return make_ipaddr( addr );
                   }

                   case AF_INET6: 
                   {
                       struct sockaddr_in6 addr{};

                       memcpy( &addr, v.ai_addr, sizeof(struct sockaddr_in6) );

                       return make_ipaddr( addr );
                   }

                   default: break;
               }
            }

            return {};
        }

        TX_CPP_INLINE_LIB 
        raw_ipaddr_pair_t make_ipaddr(  const std::string & str, 
                                        const raw_ipaddr_hint hint=raw_ipaddr_hint::ipv4    ) noexcept 
        {
            if ( str.size() ) {

                raw_ipaddr_t r_{};
                bool error{};

                if (hint!=raw_ipaddr_hint::hex){

                    struct in6_addr i6{};

                    const auto af = (   hint == raw_ipaddr_hint::ipv4   ?
                                        AF_INET                         :
                                        AF_INET6                            );

                    if ( 0 < inet_pton( af , str.c_str(), &i6 ) ) {

                        r_=make_ipaddr(i6);
                    }
                    else
                        error = true;

                } else {

                    const bool ipv4{ ( 8 >= str.size() ) };

                    char *  const buff = (  ipv4                                        ?

                                            reinterpret_cast<char* const >( &r_.v4 )    :

                                            reinterpret_cast<char* const >( &r_.v6 )        );

                    const size_t sz{    ipv4            ?

                                        sizeof(ipv4_t)  :

                                        sizeof(ipv6_t)      };
                    /* is swiped ? */
                    if ( !ttn_base16_decode(    str.c_str(), 
                                                str.size(),
                                                buff, 
                                                sz              ) ) {
                        checks::reset(r_);
                        error = true;
                    }
                }

                if ( !error  && ( checks::is_valid(r_) || checks::is_AnyAddr(r_) ) ) {

                    return raw_ipaddr_pair_t::success(r_);
                }
            }

            return raw_ipaddr_pair_t::failure();
        }

        /* Lookup and IP address */

        /**
        * @fn make_cidr
        * @abstract make cidr from addr/netmask
        * @param a[in] raw_ipaddr_t ip address it must be in host byte order (e.g. 192.168.0.1) 
        * @param m[in] raw_ipaddr_t ip netmask it must be in host byte order (e.g. 255.255.255.0)
        * @return cidr_pair_t <bool,cidr_t>
        */
        TX_CPP_INLINE_LIB cidr_pair_t make_cidr(    raw_ipaddr_t a,
                                                    raw_ipaddr_t m  ) noexcept
        {
            /* for now it's always true, but later we could add some validation */
            return cidr_pair_t::success(cidr_t{ a, get_prefix( m ) });
        }
        /** 
         * @abstract Ipv4: Get the largest classless block for an ipv4 address 
         * largest cidr prefix
         */
        TX_CPP_INLINE_LIB prefix_t ipv4_get_largest_classless_block(ipv4_t a_ipv4_addr) noexcept  
        {
            prefix_t l_prefix{};
            while( l_prefix < IPV4_MAX_PREFIX )
            {
                const ipv4_t l_mask{ checks::calc_netmask<ipv4_t,true>( l_prefix + 1 ) };
                const ipv4_t l_ipv4_masked{ (a_ipv4_addr & l_mask) };
                if (l_ipv4_masked != a_ipv4_addr) {
                    /* exit now */
                    return l_prefix;
                }

                l_prefix++;
            }
            return l_prefix;
        }
        /**
         * @fn make_cidrs
         * @abstract make cidrs from the range of addresses for IPv4 addresses ONLY
         * There will be a cidr for each max classles block between the addresses
         * @param a_begin[in] ipv4_t 
         * @param a_end[in] ipv4_t
         * @return cidrs_pair_t <bool, cidrs_t>
         */
        TX_CPP_INLINE_LIB cidrs_pair_t make_cidrs(  ipv4_t a_begin,
                                                    ipv4_t a_end    ) noexcept
        {
            /* Check for zero addresses */
            if ( (a_begin == 0) || (a_end == 0) ||  (a_begin > a_end)) {
                return cidrs_pair_t::failure();
            }

            /* single address cidr */
            if ( a_begin == a_end){
                return cidrs_pair_t::success(cidrs_t{{a_begin,IPV4_MAX_PREFIX}});
            }

            constexpr size_t l_max_cidrs{1024};    /* To prevent run-away */
            /* Check for address mismatches */
            cidrs_t l_rv{};
            while( a_begin <= a_end )
            {
                const double l_fl{ std::log1p(a_end - a_begin) / std::log( 2 ) };
                const double l_diff{ std::floor( IPV4_MAX_PREFIX - std::floor(l_fl) ) };
                const prefix_t maxdiff{ static_cast<prefix_t>(l_diff) };

                if (maxdiff == 0) {
                    break;
                }

                prefix_t l_max_cidr_prefix{ static_cast<prefix_t>(  IPV4_MAX_PREFIX  - 
                                                                    ipv4_get_largest_classless_block( a_begin ) ) };
                if ( l_max_cidr_prefix < maxdiff ) {

                    l_max_cidr_prefix = maxdiff;
                }
                /*create cidr*/
                l_rv.emplace_back(htonl(a_begin), l_max_cidr_prefix);

                /* adjust a_start*/
                a_begin += static_cast<ipv4_t>( floor( std::pow( 2, (IPV4_MAX_PREFIX - l_max_cidr_prefix) ) ) );

                if (l_rv.size() > l_max_cidrs) {
                    break;
                }
            }

            if (l_rv.size() <= l_max_cidrs) {
                return cidrs_pair_t::success(l_rv);
            }

            return cidrs_pair_t::failure();
        }
        /**
         * @fn make_cidr 
         * @abstract make new cidr from str
         * @param a_str[in] std::string in one of the following forms
         * - ipv4
         * - ipv4/prefix
         * - ipv6
         * - ipv6/prefix
         * @return cidr_pair_t <bool,cidr_t>
         */
        TX_CPP_INLINE_LIB cidr_pair_t make_cidr(const std::string & a_str) noexcept
        {

            uint32_t paresed_prefix_{};
            const size_t l_pos{ a_str.find('/') };

            if ( l_pos != std::string::npos ) {

                if (    !tx_safe_atoui( a_str.substr(l_pos+1).c_str(), &paresed_prefix_ )   || 
                        ( paresed_prefix_ > IPV6_MAX_PREFIX )                                   ) {


                    return cidr_pair_t::failure();
                }
            }

            const bool is_cidr{ l_pos!=std::string::npos };
            /* use reference - no copy */
            const std::string & l_addr = (  !is_cidr                ?

                                            a_str                   :

                                            a_str.substr(0, l_pos)      );

            const bool l_is_ipv6_string{ (l_addr.find(':') != std::string::npos) };

            if (    l_is_ipv6_string                    ||

                    paresed_prefix_<=IPV4_MAX_PREFIX        ) {

                /* optimized for IPV4 */
                raw_ipaddr_pair_t ipaddr_stat{  make_ipaddr(    l_addr,

                                                                (   !l_is_ipv6_string       ?

                                                                    raw_ipaddr_hint::ipv4   :

                                                                    raw_ipaddr_hint::ipv6       )   )   };
                if (ipaddr_stat.second){

                    if (!paresed_prefix_){

                        return cidr_pair_t::success( cidr_t{    ipaddr_stat.first, 
                                                                                            /* optimized for IPV4 */
                                                                static_cast<prefix_t>( (    !l_is_ipv6_string   ? 

                                                                                            IPV4_MAX_PREFIX     : 

                                                                                            IPV6_MAX_PREFIX         ) ) } );
                     }

                     /* make sure we always return valid cidr/network */
                     return cidr_pair_t::success(   cidr_t  { 
                                                                checks::get_network( {  ipaddr_stat.first, 
                                                                                        static_cast<prefix_t>(paresed_prefix_)  } ),

                                                                static_cast<prefix_t>(paresed_prefix_) 
                                                            } );

                }
            }
            return cidr_pair_t::failure();

        }

        /**
        * @fn make_cidr
        * @abstract make cidr from addr with the default prefix for the host either for ipv4(32) or ipv6(128) 
        * @param address[in] raw_ipaddr_t ip address it must be in host byte order (e.g. 192.168.0.1) 
        * @return cidr_pair_t <bool,cidr_t>
        */
        TX_CPP_INLINE_LIB cidr_pair_t make_cidr( raw_ipaddr_t address ) noexcept
        {

            if ( checks::is_valid( address )  ) {

                /* for now it's always true, but later we could add some validation */
                return cidr_pair_t::success(cidr_t{ address, 

                                                    (   checks::is_ipv4( address )  ?

                                                        IPV4_MAX_PREFIX             :

                                                        IPV6_MAX_PREFIX                 )   });
            }

            return cidr_pair_t::failure();
        }

        /**
         *  @fn lookup_host_ip_addr
         *  @abstract resolving domain to ip address 
         *  (so it could also be renamed into make_addr as it "convers" a string/domain into ip address)
         *  TODO: this function could return the status_pair<vector<raw_ipaddr_t>>
         */
        extern lookup_pair_t lookup_host_ip_addr(const std::string &, const bool);

    }; /* factory namespace */

    /**
    * @fn rel_ops less
    * @abstract checks if byte swapped value of the lhs is less than byte swapped value of the rhs.
    * By using the bswap128 method it swaps values from the network to the host notation.
    */
    using namespace titan_v3::tools;
    template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr>
    inline bool operator<(const T & lhs,const T & rhs) noexcept 
    {
       return (bswap128(lhs)<bswap128(rhs));
    }

    /**
    * @fn rel_ops eq
    * @abstract checks if byte swapped value of the lhs is eq to byte swapped value of the rhs.
    * By using the bswap128 method it swaps values from the network to the host notation.
    */
    template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr>
    inline bool operator==(const T & lhs,const T & rhs) noexcept 
    {
       return (bswap128(lhs)==bswap128(rhs));
    }

    /**
    * @fn rel_ops eq
    * @abstract checks if the lhs is eq to the rhs.
    */
    template< typename T, typename std::enable_if<tools::traits::is_cidr_t<T>::value>::type* = nullptr>
    inline bool operator==(const T & lhs,const T & rhs) noexcept 
    {
        return  (lhs.addr==rhs.addr && lhs.prefix==rhs.prefix);
    }

    /**
     * @operator <<
     */
    template< typename T, typename std::enable_if<tools::traits::is_raw_ipaddr<T>::value>::type* = nullptr>
    inline std::ostream& operator<<(std::ostream & out,const T& obj ) noexcept 
    { 
        return (out<<factory::to_string(obj));
    }

    /**
     * @operator <<
     */
    inline std::ostream& operator<<(std::ostream & out,const cidr_t& obj ) noexcept 
    {
        return (out<<factory::to_string(obj));
    }

} /* cidr namespace */

} /* titan_v3 namespace */

#endif /* TTN_CIDR_HXX */
/* vim: set ts=4 sw=4 et : */


