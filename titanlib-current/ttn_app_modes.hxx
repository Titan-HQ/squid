/**
 * $Id$
 */

#ifndef TTN_APP_MODE_HXX
#define TTN_APP_MODE_HXX
#include <string>
#include "global.h"
#include "edgelib.h"
#include "ttn_str_tools.hxx"
#include "ttn_algorithms.hxx"
#include "log.h"

namespace titan_v3
{

   namespace tools
   {

      namespace /* anonymous NS */
      {
         constexpr struct key_value_t {

            const char * const key{};

            const char * const value{};

            constexpr key_value_t(  const char * const k_,
                                    const char * const v_   ) noexcept :   key{k_},
                                                                           value{ v_ }
            {
               /* empty */
            }

            constexpr key_value_t() noexcept 
            {
               /* empty */
            }

            constexpr inline bool is_valid () const noexcept 
            {
                return ( key && value );
            }

         } INVALID_KV { /* no key & no value */ };

         using kv_array_t = std::array<key_value_t,3>;

         constexpr kv_array_t app_mode_kv{ { { "WT",   "gateway"  },
                                             { "WTC",  "cloud"    },
                                             { "DNSP", "dnsproxy" } } };
         template<typename T>
         constexpr typename std::enable_if< std::is_enum<T>::value, const key_value_t & >::type 
         find( const T & a ) noexcept 
         {
            if ( UWITHIN_( app_mode_kv.max_size(), static_cast<kv_array_t::size_type>( a ) ) ) {

               return app_mode_kv[ a ];
            }

            titax_log(  LOG_WARNING,
                        "%s:%d :: boundary check :: invalid input arg [%u]\n",
                        __func__,
                        __LINE__,
                        a                                                     );

            return INVALID_KV;
         }

         template <typename T>
         inline typename std::enable_if<std::is_enum<T>::value,std::string>::type
         to_string( const T & rh ) noexcept
         {
            const auto & fnd = find( rh );

            return   (  fnd.is_valid()  ?

                        fnd.value       :

                        ""                  );
         }

      } /* anonymous NS */

      struct app_mode_t: app_t 
      {
         using app_t::gateway;   /* 0x00 */

         using app_t::cloud;     /* 0x01 */

         using app_t::dnsproxy;  /* 0x02 */

         using app_t::mode;

         constexpr app_mode_t() noexcept : app_t{ .mode=app_t::gateway }
         {
         }

         constexpr app_mode_t( const app_t & a ) noexcept : app_t{ .mode=a.mode }
         {
         }

         constexpr app_mode_t( const app_mode_t & a ) noexcept : app_t{ .mode=a.mode }
         {
         }

         template<typename T,typename std::enable_if<std::is_enum<T>::value>::type* = nullptr>
         constexpr app_mode_t( const T & a ) noexcept : app_t{ .mode=a }
         {
         }

         inline app_mode_t & operator=( const app_mode_t & a ) noexcept 
         {  
            mode = a.mode;
            return *this;
         }

         template<typename T>
         inline typename std::enable_if< std::is_enum<T>::value, app_mode_t&>::type 
         operator=( const T & a ) noexcept 
         {  
            mode = a;
            return *this;
         }

         inline operator std::string() const noexcept 
         {
            return to_string( mode );
         }

      }; /* app_mode_t struct */

      constexpr const char mode_probe[]="/blocker/bin/whatami.sh";

      namespace {
         template <typename T> struct is_app_mode {
            static constexpr bool const value = ( std::is_same< T, app_t >::value || std::is_same< T, app_mode_t >::value  );
         };
      }

      template< typename L, typename R >
      constexpr typename std::enable_if< std::is_enum<R>::value && is_app_mode<L>::value, bool>::type
      operator==( const L & lh, const R & rh ) noexcept
      {
         return ( lh.mode == rh );
      }

      template< typename L, typename R >
      constexpr typename std::enable_if< std::is_enum<L>::value && is_app_mode<R>::value, bool>::type
      operator==( const L & lh, const R & rh ) noexcept
      {
         return ( lh == rh.mode );
      }

      template<typename L, typename R >
      constexpr typename std::enable_if< std::is_enum<R>::value && is_app_mode<L>::value, bool>::type
      operator!=( const L & lh, const R & rh ) noexcept
      {
         return ( lh.mode != rh );
      }

      template<typename L, typename R >
      constexpr typename std::enable_if< std::is_enum<L>::value && is_app_mode<R>::value, bool>::type
      operator!=( const L & lh, const R & rh ) noexcept
      {
         return ( lh != rh.mode );
      }

      template<typename L, typename R >
      constexpr typename std::enable_if< is_app_mode<L>::value && is_app_mode<R>::value, bool>::type
      operator==( const L & lh, const R & rh ) noexcept
      {
         return ( lh.mode == rh.mode );
      }

      template<typename L, typename R >
      constexpr typename std::enable_if< is_app_mode<L>::value && is_app_mode<R>::value, bool>::type
      operator!=( const L & lh, const R & rh ) noexcept
      {
         return ( lh.mode != rh.mode );
      }

      template< typename T >
      inline typename std::enable_if< is_app_mode<T>::value, std::ostream & >::type
      operator<<(std::ostream & lh, const T & rh ) noexcept
      {
         return lh << to_string( rh.mode );  
      }

      namespace /* anonymous NS */
      {
         struct base_parser
         {
            static inline app_mode_t parse( std::string str ) noexcept
            {
               if ( str.size() ) {

                  auto check = [ & ](const decltype(app_mode_t::gateway) & rh) noexcept 
                  {
                     const auto & fnd = find( rh );

                     if ( fnd.is_valid() ) {

                        return ( str == fnd.key );
                     }

                     return false;
                  }; /* lmbd */

                  if ( check( app_mode_t::cloud ) ) {

                     return app_mode_t::cloud;
                  }

                  if ( check( app_mode_t::gateway ) ) {

                     return app_mode_t::gateway;
                  }

                  if ( check( app_mode_t::dnsproxy ) ) {

                     return app_mode_t::dnsproxy;
                  }
               }

               return app_t::gateway;
            }

         }; /* struct */

      } /* anonymous ns */

      template <bool UT=false> struct parse_app_mode_fn_t{};

      /**
       * @functor parse_app_mode_fn
       * @abstract runtime test : parse output from mode_probe and compare with known modes 
       * gateway  (WT)
       * cloud    (WTC)
       */
      template<>
      struct parse_app_mode_fn_t<false> : base_parser
      {
         inline app_mode_t operator()() const noexcept
         {
            char str[16]{};
            if ( exbin( mode_probe, sizeof(str), str ) ) {

               return base_parser::parse( trim(str) );
            }

            return app_mode_t::gateway;
         }

      }; /* parse_app_mode_t functor */

      template<>
      struct parse_app_mode_fn_t<true> : base_parser
      {
         inline app_mode_t operator()(std::string str) const noexcept
         {
            return base_parser::parse( str );
         }

      }; /* parse_app_mode_t DEBUG functor */

      using parse_app_mode_fn = parse_app_mode_fn_t<false>;

   } /* tools namespace */

} /* titan_v3 namespace */

#endif /* TTN_APP_MODE_HXX */

