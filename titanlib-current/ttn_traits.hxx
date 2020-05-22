/*
 * $Id$
 *
 */
#ifndef TTN_TRAITS_HXX
#define TTN_TRAITS_HXX
#include <vector>
#include <map>
#include <array>
#include <type_traits>
namespace titan_v3 {

   /* forward declaration */
   namespace cidr{
        struct raw_ipaddr_t;
        struct cidr_t;
   };

   namespace tools{ 

      namespace traits{
         template <typename T> struct is_stl_continer:std::false_type{};
         template <typename T, std::size_t N> struct is_stl_continer<std::array<T,N> >:std::true_type{};
         template <typename... Args> struct is_stl_continer<std::vector <Args...> >:std::true_type{};
         template <typename... Args> struct is_stl_continer<std::map <Args...> >:std::true_type{};

         template <typename T> struct is_container {
            static constexpr bool const value = is_stl_continer<typename std::decay<T>::type>::value;
         };

         template <typename... Args> struct is_aknown_pair:std::false_type{};
         template <typename... Args> struct is_aknown_pair<std::pair<Args...> >:std::true_type{};

         /**
          * @template   is given type a pair
          */
         template <typename T> struct is_pair {
            static constexpr bool const value = is_aknown_pair<typename std::decay<T>::type>::value;
         };

         /**
          * @template   is given type a pointer or nullptr
          */
         template <typename T> struct is_ptr {
            static constexpr bool const value = (std::is_pointer<T>::value || std::is_same<T, std::nullptr_t>::value);
         };


         template <class TS> 
         struct is_ostringstream : public std::integral_constant<bool,std::is_same<std::ostringstream,TS>::value || std::is_base_of<std::ostringstream,TS>::value>{};

         template <class TS> 
         struct is_stringstream : public std::integral_constant<bool,std::is_same<std::stringstream,TS>::value || std::is_base_of<std::stringstream,TS>::value>{};

         template <class TS> 
         struct is_known_stream : public std::integral_constant<bool,is_ostringstream<TS>::value || is_stringstream<TS>::value>{};

         template <class TS> 
         struct is_int128 : public std::integral_constant<bool,   std::is_same<TS,__int128>::value ||
                                                                  std::is_same<TS,unsigned __int128>::value ||
                                                                  std::is_same<TS,__int128_t>::value ||
                                                                  std::is_same<TS,__uint128_t>::value>
         {

         };

         /**
          * @abstract private accessor template
          * provides access to protected members of CRTP
          * F = freind
          * AC = access
          */
         template <typename F, typename AC>
         struct friendly_access:AC{
            friend F;
         };

         /**
          * G = tag
          * D = crtp
          * F = friend
          * R = result
          */
         template<typename G, typename D, typename F, typename R=friendly_access<F,G> >
         constexpr R * selfie(F * f) noexcept {
            return static_cast<R*>( static_cast<G*>(static_cast<D*>(f)));
         }

         template<typename G, typename D, typename F, typename R=friendly_access<F,G> >
         constexpr const R * selfie(const F * f) noexcept {
            return static_cast<const R*>( static_cast<const G*>(static_cast<const D*>(f)));
         }

         /**
          * D = crtp
          * F = friend
          * R = result
          */
         template<typename D, typename F, typename R=friendly_access<F,D> >
         constexpr R * selfie(F * f) noexcept {
            return static_cast<R*>(static_cast<D*>(f));
         }

         template<typename D, typename F, typename R=friendly_access<F,D> >
         constexpr const R * selfie( const F * f) noexcept {
            return static_cast<const R*>(static_cast<const D*>(f));
         }
         /**
          * G = tag
          * D = crtp
          * F = friend
          * R = result
          */
         template<typename G, typename F, typename D, typename R=friendly_access<F,G> >
         constexpr const R& selfie(const D & d) noexcept {
            return static_cast<const R&>(static_cast<const G&>(d));
         }

         template <typename T, typename R=typename std::remove_reference<typename std::remove_const<T>::type>::type> 
         struct is_ip_pod : std::integral_constant<bool, std::is_same<R,::ipv4_t>::value || std::is_same<R,::ipv6_t>::value>{};

         template <typename T, typename R=typename std::remove_reference<typename std::remove_const<T>::type>::type>
         struct is_raw_ipaddr : std::integral_constant<bool, std::is_same<R,cidr::raw_ipaddr_t>::value || std::is_same<R,::c_raw_ipaddr_t>::value>{};

         template <typename T, typename R=typename std::remove_reference<typename std::remove_const<T>::type>::type>
         struct is_cidr_t : std::integral_constant<bool, std::is_same<R,cidr::cidr_t>::value || std::is_same<R,::c_cidr_t>::value>{};

         template <typename T>
         struct is_inet_struct : std::integral_constant<bool, std::is_same<T,struct in_addr>::value || std::is_same<T,struct in6_addr>::value >{};

         template <typename T>
         struct is_valid_cidr_value : std::integral_constant<bool, is_ip_pod<T>::value || is_raw_ipaddr<T>::value || is_inet_struct<T>::value>{};
        
         template < typename T  >
         using is_ipv4_t=std::is_same<T,ipv4_t>;
         
         template < typename T  >
         using is_ipv6_t=std::is_same<T,ipv6_t>;
         
         template< typename T>
         using is_ip_t=std::integral_constant<bool, ( is_ipv4_t<T>::value || is_ipv6_t<T>::value ) >;


         template <typename T> struct is_stl_string_t:std::false_type{};
         template <> struct is_stl_string_t<std::string>:std::true_type{};
         template <> struct is_stl_string_t<const char * const>:std::true_type{};
         template <> struct is_stl_string_t<const char *>:std::true_type{};
         template <> struct is_stl_string_t<char * const>:std::true_type{};
         template <typename T> struct is_string {
            static constexpr bool const value = is_stl_string_t<typename std::decay<T>::type>::value;
         };

         template< typename L, typename R >
         struct is_same_base_type : std::is_same< typename std::remove_all_extents< L >::type, R>::type
         {};

        template< bool B >
        using enable_if_true_t = typename std::enable_if<B,bool>::type;

        template< typename T  >
        using enable_if_pod_t = typename std::enable_if<
                                    std::is_standard_layout<T>::value &&
                                    std::is_trivial<T>::value,
                                    bool
                                >::type;

        template< typename T  >
        using enable_if_not_pod_t = typename std::enable_if<
                                        !( std::is_standard_layout<T>::value &&
                                           std::is_trivial<T>::value            ),
                                        bool
                                    >::type;


      } /* traits namespace */

   } /* tools namespace */

} /* titan_v3 namespace */


#endif /* TTN_TRAITS_HXX */

