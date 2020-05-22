/**
 * $Id$
 */

#ifndef TTN_UNIQIP_HXX
#define TTN_UNIQIP_HXX

#include <tuple>
#include <thread>
#include <chrono>
#include <unordered_map>
#include <iostream>
#include "global.h"
#include "ttn_tools.hxx"
#include "ttn_crtps.hxx"
#include "ttn_cidr.hxx"

namespace titan_v3{

   namespace uniqip{

      using namespace titan_v3::tools;
      using namespace titan_v3::tools::crtps;

      /* aliasses */
      using tp_type=std::chrono::steady_clock::time_point;
      using ip_addr_type=cidr::raw_ipaddr_t;

      /**
       * @struct ip_state_type : Track if something is active and for how long.
       */
    struct ip_state_type {
        tp_type     time { std::chrono::steady_clock::now() };
        bool        active { true }; /* is active by default */

        ip_state_type(const tp_type & t) noexcept :time{t}{}
        ip_state_type(const tp_type & t, const bool a) noexcept :time{t}, active{a}{}
        ip_state_type(ip_state_type && s) noexcept :time{s.time},active{s.active}{}
        ip_state_type(const ip_state_type& s) noexcept :time{s.time}, active{s.active}{}
        ip_state_type()=default;

        friend std::ostream& operator<<(    std::ostream & out,
                                            const ip_state_type & obj ) noexcept  { 
            using namespace std::chrono;
            out <<"active:"<<std::boolalpha<<obj.active<<"| age:"
                << duration_cast<milliseconds>(steady_clock::now() -obj.time).count()
                << "ms"<<std::endl;
            return out;
        }

    }; /* ip_state_type */

      /**
       * @template uniqip_type<N>
       * @abstract cotainer type for IP addresses which provides:
       *   Container ips map< ip_addr_type, ip_state_type >
       *   Lock mutex, size value 
       */
      template<size_t init_size>
      struct uniqip_type{
         std::unordered_map<ip_addr_type,ip_state_type> ips{init_size};
         std::mutex lock{};
         size_t size{}; /* Needed because items still in map may be inactive */
      }; /* uniqip_type */

      /**
      * @template find_ip_op_type
      * @abstract find ip functor (long ip_addr_type)
      * This template is compatible with the crtp_mixin_type.
      * This functor is Thread-Safe.
      * Returns std::tuple<bool,uniqip_type::ip_state_type> 
      * use e.g. std::tie 
      */
      template<class CRTP>
      struct ip_find_op_type {
         using find_tag=ip_find_op_type;
         using ret_type=std::tuple<bool,ip_state_type>;
         protected:
            template<typename D=CRTP >
            ret_type operator()(ip_addr_type ip) noexcept {
               auto & box{ traits::selfie<D>(this)->box };
               std::lock_guard<std::mutex> lock{box.lock};
               if (box.size){
                  const auto & found{ box.ips.find(ip) }; 
                  if (found != box.ips.end() && found->second.active)
                     return std::make_tuple(true,found->second); /* It's a copy (TS) */
               }
               return {};
            }
      }; /* ip_find_op_type  */

      /**
      * @template ip_find_or_add_op_type
      * @abstract Thread-Safe find-or-add functor 
      */
      template<class CRTP>
      struct ip_find_or_add_op_type{
         using subscript_tag=ip_find_or_add_op_type;
         using s_type=ip_state_type; 

         enum class result_type{
            error=0x00,
            found=0x01,
            added=0x02,
            unlimited=0x04,
         };

         struct input_type{
            const size_t max;
            ip_addr_type ip;    /* ipv6 : cidr::raw_ipaddr_t */
         };

         protected:
            template< typename D=CRTP>
            result_type operator()( const input_type & in ) noexcept {

               if (UNLIMITED_UNIQ_IP==in.max)
                    return result_type::unlimited;

               auto & box = traits::selfie<D>(this)->box;

               std::lock_guard<std::mutex> lock{box.lock};

               // check active entries first
               auto search = box.ips.find(in.ip);
               const bool found{ (search != box.ips.end()) };
               if(found){
                  s_type & ip_state{ search->second };
                  if (ip_state.active)  {
                     //update
                     ip_state.time=std::chrono::steady_clock::now();
                     return result_type::found;
                  }
               }

               // check if we can add/enable more 
               if (UWITHIN_(in.max, 1+box.size)){
                  if (found){
                     //enable back
                     s_type & ip_state{ search->second };
                     ip_state.active=true;
                     ip_state.time=std::chrono::steady_clock::now();
                     ++box.size;
                     return result_type::found;
                  }

                  // add new one and it's ok to move
                  const auto & added = box.ips.insert(std::make_pair(in.ip,s_type{}));
                  if (added.second){
                     ++box.size;
                     return result_type::added;
                  }
                  // it's highly unlikely	to end up here 
                  s_type & ip_state{ added.first->second };
                  ip_state.active=true;
                  ip_state.time=std::chrono::steady_clock::now();
                  return result_type::found;
               }

               return result_type::error;
            }
      }; /* ip_find_or_add_op_type */

      /**
       * @template two_stage_cleanup_op 
       * @abstract Thread-Safe two_stage_cleanup_op functor
       * Two stage sleanup:
       * 1. Soft deletes items that are too old
       * 2. Erases all inactive items
       */
      template<class CRTP>
      struct ip_two_stage_cleanup_op_type{
         using clear_tag=ip_two_stage_cleanup_op_type;
         protected:
            /**
             * @operator() 
             * @param ttl [in] ttl in seconds
             * @return number of actually deleted items (2) 
             */
            template< typename D=CRTP, typename V>
            size_t operator()(const V ttl ) noexcept 
            {
               auto & box = traits::selfie<D>(this)->box;

               const auto ct = ( std::chrono::steady_clock::now() - 
                                 std::chrono::seconds( 1 + ttl ) );
               size_t c{};

               std::lock_guard<std::mutex> lock{box.lock};

               tools::algorithms::erase_if(  box.ips,
                                             [ ct, &c ]( GET_TYPE(box.ips)::value_type & p ) -> bool
                                             {
                                                return ( !p.second.active                    ?: 

                                                         (  p.second.time < ct         &&

                                                            ++c                        && 

                                                            ( p.second.active=false )     )     );
                                             }  );
               box.size -= c;
               return c;
            }
      }; /* ip_two_stage_cleanup_op_type */
        
      /**
       * @template custom_print_op 
       * @abstract Thread-Safe custom_print_op functor
       */
      template<class CRTP>
      struct ip_custom_out_op_type{
         using out_tag=ip_custom_out_op_type;
         protected:
            template<typename D=CRTP>
            std::ostream& operator()(   std::ostream & out,
                                        const D & obj ) const noexcept {

               auto & box{ traits::selfie<D,out_tag>(obj).box };
               std::lock_guard<std::mutex> lock{box.lock};
               out << "Size:["<<box.size<<"]\n";
               for (const auto & e:box.ips){
                  out<<e.first<<"="<<e.second<<"\n";
               }
               return (out);
            }
      }; /* ip_custom_out_op_type */

      /**
       * @name uniqip_box_type
       * @abstract uniqip box specialization
       * Provides thread-safety
       * Supported interface:
       * -> find (ipv4 long) see ip_find_op_type
       * -> operator[] : accepts the input_type  e.g.box[input_type{.ip=<ipv4 long>, .max=<max ip from licence>}]
       * -> clear(ttl) : it is a two stage cleanup see ip_two_stage_cleanup_op_type  
       * -> operator<<
       */
      template<size_t init_size>
      using uniqip_box_type=box_type<   uniqip_type<init_size>,
                                        ip_find_op_type,
                                        ip_custom_out_op_type,
                                        ip_two_stage_cleanup_op_type,
                                        ip_find_or_add_op_type>;


   }; /* uniqip namespace */

}; /* titan_v3  namespace */

#endif /* TTN_UNIQIP_HXX */

