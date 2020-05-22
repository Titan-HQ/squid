/* $Id$  */

#include "ttn_cidr.hxx"
#include "TAPE.h"
#include <arpa/inet.h>
#include <netdb.h>
#include <string>
#include <sys/socket.h>

using namespace  titan_v3::cidr;


/**
 * factory
 *--------------------------------------------------------------------------------------
 *
 */

lookup_pair_t factory::lookup_host_ip_addr(const std::string & a_s, const bool a_nodns)
{
    if ( a_s.size() ) {

         struct addrinfo l_addrinfo_hints{};

         if (a_nodns ) {

            l_addrinfo_hints.ai_flags = AI_NUMERICHOST; // squid: prevent DNS lookup
         }

         // Invoke getaddrinfo()
         struct addrinfo * l_result{};

         const int l_error = ::getaddrinfo( a_s.c_str(), nullptr, &l_addrinfo_hints, &l_result);

         if ( !l_error && l_result ) {
             //A sucessfull lookup
             const auto ip = make_ipaddr(*l_result);

             const int family{ l_result->ai_family };

             freeaddrinfo( l_result );

             if ( checks::is_valid(ip) && (family==AF_INET ||family==AF_INET6) ) {

                return lookup_pair_t::success(ip);
             }
        }
        else if (l_result) {

            freeaddrinfo( l_result );
        }

        //error
        std::cout << gai_strerror( l_error ) << "\n";
    }

    return lookup_pair_t::failure();
}

/**
 * checks 
 *--------------------------------------------------------------------------------------
 *
 */


bool checks::is_ipv6_sitelocal( const raw_ipaddr_t & a_ip )
{
    if ( !is_ipv4(a_ip) ){

        struct in6_addr pin6{};

        memcpy( &pin6, & a_ip.v6, sizeof( struct in6_addr ) );

        return IN6_IS_ADDR_SITELOCAL( &pin6 );
    }

    return false;
}

bool checks::is_ipv6_auto_sitelocal( const raw_ipaddr_t & a_ip )
{
    if ( !is_ipv4(a_ip) ) {

        struct in6_addr pin6{};

        memcpy( &pin6, & a_ip.v6, sizeof( struct in6_addr ) );

        return IN6_IS_ADDR_LINKLOCAL( &pin6 );
    }

    return false;
}

/*
 *-------------------------------------------------------------------------------------------
 * C interface 
 */

constexpr bool str_2_cidr_( const char* const __restrict ip,
                            const size_t sz,
                            c_cidr_t * const __restrict out     )
{
    if ( ip && sz && out ){

        const auto & stat = factory::make_cidr( std::string{ ip, sz } );

        if ( stat.second ) {

            memcpy( out, static_cast<const c_cidr_t*const>(stat.first), sizeof(c_cidr_t) );
            return true;
        }
    }

    return false;
}

bool ttn_raw_ipaddr2str_ipaddr_ex(  const c_raw_ipaddr_t * const __restrict addr,
                                    char * const __restrict out,
                                    const size_t osz    )
{
    if ( out && osz && addr && checks::is_valid( *addr ) ) {

        std::string str = factory::to_string( *addr );

        if ( osz > str.size() ) {

            strlcpy( out, str.c_str(), osz );
            return true;
        }
    }

    return false;
}

bool ttn_str_ipaddr2cidr_ex(    const char* const __restrict ip,
                                const size_t sz,
                                c_cidr_t * const __restrict out     )
{
    return str_2_cidr_( ip, sz, out );
}

bool ttn_str_ipaddr2raw_ipaddr_ex(  const char* const __restrict ip,
                                    const size_t sz,
                                    c_raw_ipaddr_t * const __restrict out   )
{
    if ( ip && sz && out ) {

        c_cidr_t c{};
        if (str_2_cidr_(ip,sz,&c)){

            memcpy( out, &(c.addr), sizeof(c_raw_ipaddr_t) );
            return true;
        }
    }

    return false;
}


c_raw_ipaddr_t ttn_str_ipaddr2raw_ipaddr( const char* const __restrict ip,
                                          const size_t sz   )
{
    if ( ip && sz ) {

        c_cidr_t c{};

        if ( str_2_cidr_( ip, sz, &c ) ) {

            return c.addr;
        }
    }

    return {};
}

bool ttn_is_valid_str_ipaddr( const char * const __restrict ip )
{
    if ( ip && *ip ) {

        if ( const size_t sz = strlen( ip ) ) {

            c_cidr_t c{};

            if ( str_2_cidr_( ip, sz, &c ) ) {

                return checks::is_valid( c.addr );
            }
        }
    }

    return false;
}

bool ttn_is_valid_raw_ipaddr( const c_raw_ipaddr_t * const __restrict addr )
{
    if ( addr ) {

        return checks::is_valid( *addr );
    }

    return false;
}

bool ttn_is_raw_ipaddr_ipv4( const c_raw_ipaddr_t * const __restrict addr )
{
    if ( addr ) {

        return checks::is_ipv4( *addr );
    }

    return false;
}

bool ttn_is_raw_ipaddr_ipv6( const c_raw_ipaddr_t * const __restrict addr )
{
    if ( addr ) {

        return checks::is_ipv6( *addr );
    }

    return false;
}

bool ttn_in6_addr2raw_ipaddr(   const struct in6_addr * const __restrict addr,
                                c_raw_ipaddr_t * const __restrict out )
{
    if ( addr && out ) {

        const auto & ip_ = factory::make_ipaddr( *addr );
        
        if ( checks::is_valid( ip_ ) ) {

            out->v6 = ip_.v6;

            return true;
        }
    }

    return false;
}

bool ttn_in4_addr2raw_ipaddr(   const struct in_addr * const __restrict addr, 
                                c_raw_ipaddr_t * const __restrict out  )
{
    if ( addr && out ) {

        const auto & ip_ = factory::make_ipaddr( *addr );
        if ( checks::is_valid( ip_ ) ){

            out->v6 = ip_.v6;
            return true;
        }
    }

    return false;
}

bool ttn_is_ipaddr_anyaddr( const c_raw_ipaddr_t * const __restrict addr )
{
    if ( addr ) {

        return checks::is_AnyAddr( *addr );
    }

    return false;
}

void ttn_print_raw_ipaddr( const c_raw_ipaddr_t * const __restrict addr )
{
    if ( addr ) {

        std::cout<<(*addr)<<std::endl;
    }
}

int ttn_is_in6_addr_local( const struct in6_addr * const __restrict addr )
{
    if ( addr ) {

        const auto & ip_ = factory::make_ipaddr( *addr );

        return static_cast<int>( checks::is_localhost( ip_ ) );
    }

    return -1;
}

int ttn_is_ipaddr_local( const c_raw_ipaddr_t * const __restrict addr )
{
    if ( addr ) {

        return static_cast<int>( checks::is_localhost( *addr ) );
    }

    return -1;
}

int ttn_is_ipaddr_any( const c_raw_ipaddr_t * const __restrict addr )
{
    if ( addr ) {

        return static_cast<int>( checks::is_AnyAddr( *addr ) );
    }

    return -1;
}

int ttn_is_in6_addr( const struct in6_addr * const __restrict addr,
                     c_raw_ipaddr_t * const __restrict out   )
{
    if ( addr ) {

        const auto & ip_ = factory::make_ipaddr( *addr );

        if ( out ) {

            out->v6=ip_.v6;
        }

        return static_cast<int>( checks::is_ipv6( ip_ ) );
    }

    return -1;
}

bool ttn_in6_addr2str_ipaddr_ex(    const struct in6_addr * const __restrict addr,
                                    char * const __restrict out,
                                    const size_t osz    )
{
    if ( out && osz && addr ) {

        const auto & ip_ = factory::make_ipaddr( *addr );

        if ( checks::is_valid( ip_ ) ){

            std::string str = factory::to_string( ip_ );

            if ( osz > str.size() ) {

                strlcpy( out, str.c_str(), osz );

                return true;
            }
        }
    }

    return false;
}

bool ttn_in4_addr2str_ipaddr_ex(    const struct in_addr * const __restrict addr,
                                    char * const __restrict out,
                                    const size_t osz    )
{
    if ( out && osz && addr ) {

        const auto & ip_ = factory::make_ipaddr( *addr );

        if ( checks::is_valid( ip_ ) ){

            std::string str = factory::to_string( ip_ );

            if ( osz > str.size() ) {

                strlcpy( out, str.c_str(), osz );

                return true;
            }
        }
    }

    return false;
}

/* vim: set ts=4 sw=4 et : */
