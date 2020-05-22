/*
 * $Id$
 * Titan Tools
 */

#ifndef TTN_TOOLS_HXX
#define TTN_TOOLS_HXX
#include <vector>
#include <map>
#include <string>
#include <assert.h>
#include <type_traits>
#include <iostream>
#include <iomanip> 
#include <sstream> 
#include "global.h"
#include "ttn_global.hxx"
#include "ttn_traits.hxx"
#include "ttn_errors.hxx"
#include "ttn_sbuff.hxx"
#include "ttn_iterators.hxx"
#include "ttn_uuid.hxx"
#include "ttn_functors_templates.hxx"
#include "ttn_eops.hxx"
#include "ttn_pmtx.hxx"
#include "ttn_bswap.hxx"
#include "ttn_status_pair.hxx"
#include "ttn_sql_tools.hxx"
#include "ttn_app_modes.hxx"
#include "ttn_str_tools.hxx"
#include "db.hxx"
#include "db_pg.hxx"
#include "ttn_generator.hxx"
#include "ttn_tools_std.hxx"
#include "ttn_tools_c.h"
#include "ttn_algorithms.hxx"

namespace titan_v3 {

   namespace tools{

      namespace functors{

         /**
          * @functor: stream_size
          */ 

         struct stream_size:public templates::pod_fntor<size_t>{
            explicit stream_size(std::ostream & S):pod_fntor{get_s_(S)}{}
         protected:
            static size_t get_s_(std::ostream & S) noexcept {
               const std::streamoff org=S.tellp();
               S.seekp(0, std::ios::end);
               const std::streamoff r=S.tellp();
               S.seekp(org,std::ios::beg);
               return static_cast<size_t>(r);
            }
         };/* functor */

         /**
          * @functor: addr (address functor) 
          */
         using addr=templates::addr_fn<false>;
         
         /**
          * @functor: tos (to string) PSpecialization
          * @abstract: functor template handling conversions (to string)
          * @example: 
          * std::cout<<tos{true};
          * std::string s=tos{}<<true;
          * 
          */
         using tos=templates::tos;
         
         using templates::citer_cfg;

         
         /**
          * @functor citer\< citer_cfg::cfg_default >{}
          * @abstract concatenated items 
          */
         using citer=templates::citer_fn<>;
         
         /**
          * @functor citer\< citer_cfg::cfg_sep >{}
          * @abstract separated items 
          */
         using citer_sep=templates::citer_fn<citer_cfg::cfg_sep>;

         /**
          * @functor citer\< citer_cfg::cfg_ols >{}
          * @abstract separated items (will omit the last separator symbol)
          */      
         using citer_ols=templates::citer_fn<citer_cfg::cfg_ols>;
         
         enum class hexdump_cfg{
            hdc_print_lines=0x01,
            hdc_print_hex=0x02,
            hdc_print_raw=0x04,
            hdc_default=hdc_print_lines | hdc_print_hex | hdc_print_raw,
            hdc_print_size=0x08,
            hdc_print_base=0x10,
            hdc_use_base=0x20,
            hdc_swipe_bytes=0x40,
            hdc_pad_with_zeros=0x80,
         };

         /**
          * @functor hexdump
          * @abstract   example of usage   
          * e.g. std::cout\<\< hexdump {\< buffer >,\< size >};
          * see constructors
          */         
         struct hexdump:public tos {
            /**
             * @constructor
             * @param sbf        : SBuff
             * @param print_size : to print out the raw data size
             */
            explicit hexdump(const tools::SBuff & sbf,const hexdump_cfg cfg=hexdump_cfg::hdc_default):tos{}{
               dump({sbf.c_str(),sbf.size},cfg);
            }

            /**
             * @constructor
             * @param instr_     : std::string
             * @param print_size : to print out the raw data size
             */
            explicit hexdump(const std::string & instr_,const hexdump_cfg cfg=hexdump_cfg::hdc_default):tos{}{
               dump({instr_.c_str(),instr_.size()},cfg);
            }
            /**
             * @constructor
             * @param instr_     : const char *
             * @param instrsz_   : size 
             * @param print_size : to print out the raw data size
             */
            explicit hexdump(const char * const instr_, const size_t instrsz_,const hexdump_cfg cfg=hexdump_cfg::hdc_default):tos{}{
               dump({instr_,instrsz_},cfg);
            }

            /**
             * @constructor
             * @param instr_     : char *
             * @param instrsz_   : size 
             * @param print_size : to print out the raw data size
             */
            explicit hexdump(char * const instr_, const size_t instrsz_,const hexdump_cfg cfg=hexdump_cfg::hdc_default):tos{}{
               dump({instr_,instrsz_},cfg);
            }

            /**
             * @constructor
             * @param instr_     : void *
             * @param instrsz_   : size 
             * @param print_size : to print out the raw data size
             */
            explicit hexdump(void * const instr_, const size_t instrsz_,const hexdump_cfg cfg=hexdump_cfg::hdc_default):tos{}{
               dump({reinterpret_cast<const char * const>(instr_),instrsz_},cfg);
            }

            template <typename TV, typename std::enable_if<(!std::is_pointer<TV>::value && std::is_arithmetic<TV>::value && sizeof(TV)==8)>::type* = nullptr>
            explicit hexdump(TV inv,const hexdump_cfg cfg=hexdump_cfg::hdc_default):tos{}{
               using namespace tools::eop;
               if ((cfg & hexdump_cfg::hdc_swipe_bytes)==hexdump_cfg::hdc_swipe_bytes) inv=bswap64(inv);
               dump({reinterpret_cast<char*>(&inv),sizeof(TV)},cfg);
            }

            template <typename TV, typename std::enable_if<(!std::is_pointer<TV>::value && std::is_arithmetic<TV>::value && sizeof(TV)==4)>::type* = nullptr>
            explicit hexdump(TV inv,const hexdump_cfg cfg=hexdump_cfg::hdc_default):tos{}{
               using namespace tools::eop;
               if ((cfg & hexdump_cfg::hdc_swipe_bytes)==hexdump_cfg::hdc_swipe_bytes) inv=bswap32(inv);
               dump({reinterpret_cast<char*>(&inv),sizeof(TV)},cfg);
            }

            template <typename TV, typename std::enable_if<(!std::is_pointer<TV>::value && std::is_arithmetic<TV>::value && sizeof(TV)==2)>::type* = nullptr>
            explicit hexdump(TV inv,const hexdump_cfg cfg=hexdump_cfg::hdc_default):tos{}{
               using namespace tools::eop;
               if ((cfg & hexdump_cfg::hdc_swipe_bytes)==hexdump_cfg::hdc_swipe_bytes) inv=bswap16(inv);
               dump({reinterpret_cast<char*>(&inv),sizeof(TV)},cfg);
            }

         protected:
            inline void dump(t_strptr && instr,const hexdump_cfg cfg){
               if (instr.ptr_){
                  const size_t max=instr.sz_;
                  size_t pos=0;
                  using namespace tools::eop;
                  if ((cfg & hexdump_cfg::hdc_print_size)==hexdump_cfg::hdc_print_size) *this << "size:"<<max<<"\n";
                  if ((cfg & hexdump_cfg::hdc_print_base)==hexdump_cfg::hdc_print_base) *this << "base:"<<addr{instr.ptr_}<<"\n";
                  const char * lines=((cfg & hexdump_cfg::hdc_use_base)==hexdump_cfg::hdc_use_base?instr.ptr_:nullptr);
                  const bool plines=((cfg & hexdump_cfg::hdc_print_lines)==hexdump_cfg::hdc_print_lines);
                  const bool phex=((cfg & hexdump_cfg::hdc_print_hex)==hexdump_cfg::hdc_print_hex);
                  const bool praw=((cfg & hexdump_cfg::hdc_print_raw)==hexdump_cfg::hdc_print_raw);
                  const char * const pad_=( !((cfg & hexdump_cfg::hdc_pad_with_zeros)==hexdump_cfg::hdc_pad_with_zeros)?"   ":" 00");
                  while (pos<max){
                     const size_t dchunk=((max-pos)>0x10?0x10:(max-pos));
                     if (plines){
                        *this << addr{lines}; 
                        if (phex || praw) *this << '|';
                     }

                     if (plines && phex){
                        for(size_t i_ = 0; i_ < 0x10; (void)(!(i_ % 8) && (*this <<' ')),(void)(((i_<dchunk) && (*this<< ' ' << tos{std::ostringstream{}<<std::setfill('0')<<std::setw(2)<<std::hex<< +(static_cast<uint8_t>(instr.ptr_[pos+i_]))}))|| (*this<<pad_)),++i_ )
                           ; /* empty body */
                     } else if (phex) for(size_t i_ = 0; i_ < 0x10;(void)(((i_<dchunk) && (*this<< ' ' << tos{std::ostringstream{}<<std::setfill('0')<<std::setw(2)<<std::hex<< +(static_cast<uint8_t>(instr.ptr_[pos+i_]))}))|| (*this<<pad_)),++i_ )
                        ; /* empty body */

                     if (phex && praw) *this << " | ";

                     if (praw) for( size_t i_ = 0; i_ < 0x10;(void)((i_<dchunk) && (*this << (std::isprint(instr.ptr_[pos+i_])?instr.ptr_[pos+i_]:'.'))),++i_ )
                        ; /* empty body */
                     pos+=dchunk;
                     lines+=0x10;
                     if (plines) *this << "\n";
                  }
                  return;
               }
               throw errors::hexdump_error();
            }
         }; /* functor */

         /**
          * @functor free memory deleter
          * usually used as a deleter in std::unique_ptr (e.g. t_cbuffer_uniq)  to deallocate a memory 
          * allocated by using a malloc (and friends)
          */
         struct free_memory_deleter { 
            void operator()(void* const ptr) const{
               ::tx_safe_free(ptr);
            }
         };  

         /**
          * @urldb_rc_map functor;
          */
         using urldb_rc_map=eop::as_string<t_urldb_rc,templates::t_urldb_rc_str_map_functor>;

         /**
          * @raw_out functor
          * @abstract specialized version of the hexdump
          */
         struct raw_out{
            template <typename T, typename std::enable_if<(!std::is_pointer<T>::value)>::type* = nullptr >
            constexpr explicit raw_out(const T & in): r_{&in}, rsz_{sizeof(T)}{}

            friend std::ostream & operator<<(std::ostream & out, const raw_out & ro){
               using namespace tools::eop;
               return ((out<<"size:"<<ro.rsz_<<" |"<<hexdump{const_cast<void*const>(ro.r_),ro.rsz_,(hexdump_cfg::hdc_print_hex | hexdump_cfg::hdc_pad_with_zeros)}));
            }

            protected:
               const void  * const r_{};
               const size_t rsz_{};
         }; /* functor */

      }; /* functors namespace */

      namespace eop{
         /**
          * @template   function template: to_string
          * @abstract   convert enum based value to string 
          * @param v_ : enum based value
          * @return 
          */
         template<typename TBASE,typename std::enable_if<std::is_enum<TBASE>::value>::type* = nullptr>
         TX_CPP_INLINE_LIB std::string to_string(TBASE v_){
            return tools::tos{tools::eop::to_underlying(v_)};
         }
      }; /* eop namespace */

      /**
       * @function   get all sub categories 
       * @param cat_    :  category number
       * @param func_   :  lambda function called when a sub category is found
       */
      TX_CPP_INLINE_LIB
      void getcategories(t_category cat_,std::function<void(const size_t)> func_) noexcept 
      {
         uint_fast64_t i_=0;
         constexpr auto MAX_CATEGORIES_ = static_cast<uint_fast64_t>(MAX_CATEGORIES);
         while(cat_>0){
            if(cat_ & 0x0000000000000001ULL && UWITHIN_(MAX_CATEGORIES_,i_)) func_(i_);
            cat_ >>= 1;
            ++i_;
         }
      };

      /**
       * C compatible unique_ptr
       */
      using t_cbuffer_uniq=std::unique_ptr<char,functors::free_memory_deleter>;

   } /* tools namespace */
   
} /* titan_v3 namespace */


#endif /* TTN_TOOLS_HXX */

