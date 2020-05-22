/*
 * $Id$
 */

#ifndef TTN_FUNCTORS_TEMPLATES_HXX
#define TTN_FUNCTORS_TEMPLATES_HXX



#include <iomanip> 
#include <type_traits>
#include <string>
#include "global.h"
#include "ttn_global.hxx"
#include "ttn_traits.hxx"
#include "ttn_errors.hxx"
#include "ttn_eops.hxx"
#include "ttn_iterators.hxx"

namespace titan_v3 
{
   namespace tools
   {
      namespace functors
      {
         namespace templates
         {
            /**
             * @template: basic_fntor (basic functor) primary template
             * @abstract: template of a functor handling single value (pod/obj/ptr)
             */
            template <
                typename TSV,
                bool UEX=true,
                bool UT=false
            > 
            struct basic_fntor{};

            /**
             * @template: basic_fntor (basic functor) PSpecialization
             * @abstract: template of a functor handling single value (pod/obj/ptr)
             * 
             */
            template <
                typename TSV,
                bool UEX
            > 
            struct basic_fntor<TSV,UEX,false>
            { 
               static_assert(!std::is_array<TSV>::value,"basic_fntor: unable to accept array as an argument");
               typedef  basic_fntor<TSV,UEX,false> self_type;
               typedef  TSV value_type;

               operator TSV() const
               {
                    return value_;
               }

               template<
                    typename TP=TSV,
                    traits::enable_if_true_t<
                        (   !std::is_pointer<TP>::value             &&
                            !(  std::is_standard_layout<TP>::value  &&
                                std::is_trivial<TP>::value          )   )
                    > = false
               >
               operator TSV && () && 
               {
                    return std::move(value_);
               }

               basic_fntor()=default;

               explicit basic_fntor(const TSV * const v):value_{v!=nullptr?*v:TSV{}}
               {
                    if (v==nullptr && UEX) throw errors::nullptr_error();
               }

               template<
                    typename TS=TSV,
                    traits::enable_if_true_t< !std::is_object<TS>::value > = false
               >
               explicit basic_fntor(const typename TS::value_type * const v):value_{v!=nullptr?v:TS{}}
               {
                    if (v==nullptr && UEX) throw errors::nullptr_error();
               }

               template<
                    typename TP=TSV,
                    traits::enable_if_true_t< !std::is_object<TP>::value > = false
               >
               explicit basic_fntor(TSV v):value_{v!=nullptr?v:TSV{}}
               {
                    if (v==nullptr && UEX) throw errors::nullptr_error();
               }

               template<
                    typename TP=TSV,
                    traits::enable_if_true_t< std::is_object<TP>::value > = false
               >
               explicit basic_fntor(const TSV & v):value_{v}{}

               template<
                    typename TP=TSV,
                    traits::enable_if_true_t< std::is_object<TP>::value > = false
               >
               explicit basic_fntor(TSV && v):value_{std::move(v)}{}

               explicit basic_fntor(const self_type & f):value_{f.value_}{}

               explicit basic_fntor(self_type && f):value_{std::move(f.value_)}{}

               template <typename TV=TSV>
               friend  typename std::enable_if<!std::is_object<TV>::value,std::ostream&>::type
               operator<<(std::ostream & out, self_type && obj) noexcept
               {
                  return ( out<<obj.value_ );
               }

               template <typename TV=TSV>
               friend  typename std::enable_if<std::is_object<TV>::value,std::ostream&>::type
               operator<<(std::ostream & out, self_type && obj) noexcept
               {
                     return ( out<<TV{std::move(obj.value_)} );
               }

               friend std::ostream& operator<<(std::ostream & out, const self_type & obj)
               {
                    out<<obj.value_;return (out);
               }

               basic_fntor& operator=(const self_type &)=delete;
            protected:
                #if (__clang_major__ >= 4 || __clang_minor__ > 4)
                    TSV value_{};
                #else 
                    TSV value_;
                #endif
               static constexpr bool uex_=UEX;

            };/* functor template */

            template <
                typename T, 
                bool UT=false, 
                traits::enable_if_true_t< std::is_pointer<T>::value > = false
            >
            struct ptr_fntor:public basic_fntor<T,false,UT>
            {
               using basic_fntor<T,false,UT>::basic_fntor;
            };/* functor template */


            /**
             * @template string functor (primary template)
             */
            template <bool UT> struct string_fntor{};

            /**
             * @enum string_fntor_cfg
             */
            enum class string_fntor_cfg
            {
                sf_cptr_none=0x00,
                sf_cptr_delete=0x01,
                sf_cptr_free=0x02,
             };

            /**
             * @template string functor PSpecialization
             */
            template <> struct string_fntor<false>:public basic_fntor<std::string,true,false>
            {
               using basic_fntor<std::string,true,false>::basic_fntor;

#if !(__clang_major__ >= 4 || __clang_minor__ > 4)
                  /* in the older clang had to manually expose inherited operators  */

                  operator std::string()const
                  {
                     return value_;
                  }

                  operator std::string && () &&
                  {
                     return std::move(value_);
                  }
#endif
               string_fntor()=default;

               /**
                * @constructor      : string_fntor 
                * @abstract         : mov constructor
                * @param v          : movable char ptr
                * @param cfg        : see string_fntor_cfg enum
                * @example
                * string_fntor{std::move(str_dup("abcd")),string_fntor_cfg::sf_cptr_free}
                */
               template<
                    typename TP,
                    traits::enable_if_true_t< 
                        std::is_pointer<TP>::value &&
                        std::is_same<TP,char*>::value
                    > = false
               >
               string_fntor( TP && v,
                             const string_fntor_cfg cfg ) :
                                            basic_fntor{ ( v != nullptr                ? 
                                                           std::string{ v, strlen(v) } : 
                                                           std::string{}                 ) }
               {
                  (void)swap_n_release_(std::move(v),cfg);
               }

               /**
                * @constructor         : string_fntor
                * @abstract            : cpy constructor
                * @param v             : t_strptr
                * @example
                * string_fntor{{"abcd",sizeof("abcd")-1}}
                */
               explicit string_fntor( t_strptr && v ) : 
                                            basic_fntor{ ( ( v.ptr_ && v.sz_ )          ?
                                                           std::string{ v.ptr_, v.sz_ } :
                                                           std::string{}                  ) }
               {
                    if (!(v.ptr_ && v.sz_) && uex_) throw errors::nullptr_error();
               }

            protected:

               template<
                    typename TP,
                    traits::enable_if_true_t< 
                        std::is_pointer<TP>::value &&
                        std::is_same<TP,char*>::value
                    > = false
               >
               static constexpr bool swap_n_release_( TP && v,
                                                      const string_fntor_cfg cfg=templates::string_fntor_cfg::sf_cptr_none)
                {

                  if (v!=nullptr){

                     char * tmp{};
                     std::swap(tmp,v);

                     if (tmp){

                        switch (cfg){
                           case string_fntor_cfg::sf_cptr_delete:{
                              delete[] tmp;
                              return true;
                           }
                           case string_fntor_cfg::sf_cptr_free:{
                              ::tx_safe_free(tmp);
                              return true;
                           }
                           //throw exception we should own this pointer (sf_cptr_none)
                           default:break;
                        }
                     }

                     if (uex_) throw errors::swap_error();
                  }
                  if (uex_) throw errors::nullptr_error();
               }

            };/* functor template */

            template <
                typename T, 
                bool UT=false,
                traits::enable_if_pod_t<T> = false
            >
            struct pod_fntor:public basic_fntor<T,true,UT>
            {
               using basic_fntor<T,true,UT>::basic_fntor;
            };/* functor template */

#if (__clang_major__ >= 4 || __clang_minor__ > 4)
            template <bool UT=false>
            struct cptr_fntor:public ptr_fntor<char*,UT>
            {
               using ptr_fntor<char*,UT>::ptr_fntor;
            };/* functor template */
#else
            template <bool UT=false>
            struct cptr_fntor:public basic_fntor<char*,false,UT>
            {
               using basic_fntor<char*,false,UT>::basic_fntor;
            };/* functor template */
#endif

#if (__clang_major__ >= 4 || __clang_minor__ > 4)
            template <bool UT=false>
            struct ccptr_fntor:public ptr_fntor<const char*,UT>
            {
               using ptr_fntor<const char*,UT>::ptr_fntor;
            };/* functor template */
#else
            template <bool UT=false>
            struct ccptr_fntor:public basic_fntor<const char*,false,UT>
            {
               using basic_fntor<const char*,false,UT>::basic_fntor;
            };/* functor template */
#endif

            /**
             * @template: addr_fn (address functor) primary template
             */
            template <bool UT=false> struct addr_fn;

            /**
             * @template: addr_fn (address functor) secondary template
             */
            template <bool UT> struct addr_fn:public string_fntor<UT>{};

            /**
             * @template: addr_fn (address functor) PSpecialization
             */
            template <> struct addr_fn<false>:public string_fntor<false>
            {
               template<
                    class TV,
                    traits::enable_if_true_t< !std::is_pointer<TV>::value > = false
               >
               explicit addr_fn(const TV& v):string_fntor{dump(&v)}{}

               template<
                    class TV,
                    traits::enable_if_true_t< std::is_pointer<TV>::value > = false
               >
               explicit addr_fn(TV v):string_fntor{dump(v)}{}

               explicit operator uintptr_t() const noexcept
               {
                    return ivalue_;
               }

               explicit operator void * () const noexcept
               {
                    return  reinterpret_cast<void*>(ivalue_);
               }

               protected:
                  uintptr_t ivalue_{};

                  template<
                    class TV,
                    traits::enable_if_true_t< std::is_pointer<TV>::value > = false
                  >
                  std::string dump(TV v)
                  {
                     return std::string{(std::ostringstream{}<<"0x"<<std::setfill('0')<<std::setw(sizeof(uintptr_t)<<1)<<std::hex<<(ivalue_=reinterpret_cast<uintptr_t>(v))).str()};
                  }
            };/* functor template */ 
            
            
            /**
             * @template: tos_fn (to string functor) primary template
             */
            template <bool UT=false> struct tos_fn;

            /**
             * @template: tos_fn (to string functor) secondary template
             */
            template <bool UT> struct tos_fn:public string_fntor<UT>{};

            using  osfunc = std::ostream & (*)(std::ostream&);

            /**
             * @template: tos_fn (to string functor) PSpecialization
             * @abstract: template of a functor handling conversions to string 
             */
            template <> struct tos_fn<false>:public string_fntor<false>
            {
               typedef tos_fn<false> self_type;
               using string_fntor<false>::string_fntor;
               tos_fn()=default;

               template<
                    typename TV, 
                    traits::enable_if_true_t<
                        (   std::is_standard_layout<TV>::value      &&
                            std::is_trivial<TV>::value          )   &&
                        !traits::is_int128<TV>::value               && 
                        !std::is_pointer<TV>::value
                    > = false
               >
               explicit tos_fn(TV v):string_fntor((!std::is_same<TV,char>::value?std::string{std::to_string(v)}: std::string{static_cast<char>(v)})){}

               template<
                    typename TV,
                    traits::enable_if_true_t< traits::is_known_stream<TV>::value > = false
               >
               explicit tos_fn(const TV & o):string_fntor(std::string{o.rdbuf()->str()}){}

               template<
                    typename TV,
                    traits::enable_if_true_t< traits::is_known_stream<TV>::value > = false
               >
               explicit tos_fn(TV && o):string_fntor(TV{std::move(o)}.str()){}

               template<
                    typename TV,
                    traits::enable_if_true_t< traits::is_int128<TV>::value > = false,
                    typename TC = typename std::conditional<
                        std::is_same<TV,__uint128_t>::value,
                        __uint64_t,
                        __int64_t
                    >::type
               >
               explicit tos_fn(const TV & v_,const bool use_prefix=true):string_fntor(
               std::move((std::ostringstream{}<<(use_prefix?"0x":"")<<std::setfill('0')<<std::setw(0x10)<<std::hex<<reinterpret_cast<const TC *>(&v_)[1]<<std::setfill('0')<<std::setw(0x10)<<std::hex<<reinterpret_cast<const TC *>(&v_)[0]).str())){}

               template<
                    typename TV,
                    traits::enable_if_true_t< traits::is_int128<TV>::value > = false,
                    typename TC = typename std::conditional<
                        std::is_same<TV,__uint128_t>::value,
                        __uint64_t,
                        __int64_t
                    >::type
               >
               explicit tos_fn(TV && v_,const bool use_prefix=true):string_fntor(std::move((std::ostringstream{}<<(use_prefix?"0x":"")<<std::setfill('0')<<std::setw(0x10)<<std::hex<<reinterpret_cast<const TC *>(&v_)[1]<<std::setfill('0')<<std::setw(0x10)<<std::hex<<reinterpret_cast<const TC *>(&v_)[0]).str())){}


#if (__clang_major__ >= 4 || __clang_minor__ > 4)
               constexpr const char * c_str() const noexcept  {return value_.c_str();}
#else
               /* in the older clang the support for the constexpr is limited */
               const char * c_str() const noexcept {return value_.c_str();}
#endif

               inline void clear() noexcept { value_=std::string{};}
               inline bool operator!() const noexcept {return (!value_.size());}
               explicit inline operator bool() const noexcept {return !(!value_.size());}
               inline size_t size() const noexcept {return value_.size();}


               template <typename TV> friend constexpr
               tos_fn && operator<<(   tos_fn&& l_,
                                       const TV & r_ ) noexcept 
               {
                     l_.append_(r_);
                     return {std::move(l_)};
               }  

               template <typename TV> friend constexpr
               tos_fn && operator<<(   tos_fn&& l_,
                                       TV && r_ ) noexcept 
               {

                     l_.append_(std::move(r_));
                     return {std::move(l_)};
               }

               template <std::size_t N> friend constexpr
               tos_fn && operator<<(   tos_fn&& l_,
                                       const char(&r_)[N]   ) noexcept 
               {

                     l_.append_(r_);
                     return std::move(l_);
               }

               template <typename TV> friend constexpr
               tos_fn & operator<<( tos_fn& l_,
                                    const TV & r_  )
               {

                     l_.append_(r_);
                     return l_;
               }
                     
               template <typename TV> friend constexpr
               tos_fn & operator<<( tos_fn& l_,
                                    TV && r_ ) noexcept
               {

                     l_.append_(std::move(r_));
                     return l_;
               }

               template <size_t N> friend constexpr
               tos_fn & operator<<( tos_fn& l_,
                                    const char(&r_)[N]   ) noexcept
               {

                     l_.append_(r_);
                     return l_;
               }

               friend tos_fn & operator<<(   tos_fn& l_, 
                                             osfunc r_   ) noexcept
               {

                     l_<<(std::ostringstream{}<<r_);
                     return l_;
               }

               friend  tos_fn && operator<<( tos_fn&& l_, 
                                             osfunc r_   ) noexcept
               {

                     l_<<(std::ostringstream{}<<r_);
                     return std::move(l_);
               } 

            protected:

               template<
                    typename TV, 
                    traits::enable_if_true_t<
                        ((  std::is_standard_layout<TV>::value      &&
                            std::is_trivial<TV>::value          )   &&
                        !traits::is_int128<TV>::value               &&
                        !std::is_pointer<TV>::value                 &&
                        !std::is_array<TV>::value)
                    > = false
               >
               inline void append_(TV v)
               {
                    if ( !std::is_same<TV,char>::value ) {

                        value_+= std::to_string(v);
                    }
                    else {

                        value_+=static_cast<char>(v);
                    }
               }

               template<
                    typename TV,
                    traits::enable_if_true_t<
                        (!traits::is_int128<TV>::value              &&
                        (   std::is_same<TV,char*>::value           ||
                            std::is_same<TV,const char*>::value )   &&
                        !std::is_array<TV>::value)
                    > = false
               >
               inline void append_(TV v)
               {
                  if ( v ) {

                     value_.append(v);
                     return;
                  }

                  if (uex_) throw errors::nullptr_error();  
               }

               template<
                    typename TV,
                    traits::enable_if_true_t< traits::is_int128<TV>::value > = false,
                    typename TC = typename std::conditional<
                        std::is_same<TV,__uint128_t>::value,
                        __uint64_t,
                        __int64_t
                    >::type
               >
               inline void append_(const TV & v_)
               {
                    value_+=std::move((std::ostringstream{}<<"0x"<<std::setfill('0')<<std::setw(0x10)<<std::hex<<reinterpret_cast<const TC *>(&v_)[1]<<std::setfill('0')<<std::setw(0x10)<<std::hex<<reinterpret_cast<const TC *>(&v_)[0]).str());
               }

               template<
                    typename TV,
                    traits::enable_if_true_t< traits::is_int128<TV>::value > = false,
                    typename TC = typename std::conditional<
                        std::is_same<TV,__uint128_t>::value,
                        __uint64_t,
                        __int64_t
                    >::type 
               >
               inline void append_(TV && v_)
               {
                    value_+=std::move((std::ostringstream{}<<"0x"<<std::setfill('0')<<std::setw(0x10)<<std::hex<<reinterpret_cast<const TC *>(&v_)[1]<<std::setfill('0')<<std::setw(0x10)<<std::hex<<reinterpret_cast<const TC *>(&v_)[0]).str());
               }


                template< typename T >
                using enable_if_string_convertable_t = typename std::enable_if<
                        ( !std::is_pointer<T>::value                               &&
                          !std::is_array<T>::value                                 &&
                          std::is_object<T>::value                                 &&
                          ( std::is_same<T,string_fntor::value_type>::value        ||
                            std::is_convertible<T,string_fntor::value_type>::value ||
                            std::is_same<T,tos_fn>::value                               )),
                         bool
                    >::type;
                        

               template<
                    typename TV,
                    enable_if_string_convertable_t<TV> = false
               >
               inline void append_(const TV & v)
               {
                    value_+=v;
               }

               template<
                    typename TV,
                    enable_if_string_convertable_t<TV> = false
               >
               inline void append_(TV && v)
               {

                    value_+=std::forward<TV>(v);
               }

               template <std::size_t N>
               inline void append_(const char(&a)[N])
               {
                    value_.append(a,N-1);
               }

               template <
                    typename TV,
                    traits::enable_if_true_t<
                        !std::is_rvalue_reference<TV&&>::value   &&
                        traits::is_known_stream<TV>::value
                    > = false
               >
               inline void append_(const TV & v)
               {
                    value_.append( v.rdbuf()->str() );
               }

               template <
                    typename TV,
                    traits::enable_if_true_t<
                        std::is_rvalue_reference<TV&&>::value   &&
                        traits::is_known_stream<TV>::value
                    > = false
               >
               inline void append_(TV && v)
               {
                    value_.append(std::forward<TV>(v).str());
               }

            };/* functor template */

            /**
             * @enum citer configuration flags
             * @constant   cfg_default 0x00,
             * @constant   cfg_ols  0x01,
             */
            enum class citer_cfg
            { 
               /**
                * default no separator (aka to_string)
                */
               cfg_default=0x00,

               /**
                * always append the separator symbol
                */
               cfg_sep=0x01,

               /**
                * omit the last separator symbol (at the last item)
                */
               cfg_ols=0x02,
            };

            namespace 
            {
               typedef tos_fn<false>   tos;
            }

            /**
             * @template   citer_fn (citer functor template, primary template)
             * @abstract   this is the container iterator,it iterates the container
             * and output the result as e.g. std::string or print out (all items from
             * the container are separated  by separator symbol e.g. \\n)
             * example: std::cout \<\< citer \< > {\< map/vector/array >,\< sep >};
             * also accepts the citer_cfg flags as a template argument
             * @param vc   :  container \< map/vector/array >
             * @param sep  :  optional separator, default \\n
             * @return     :  t/f
             */
            template <citer_cfg cfg=citer_cfg::cfg_default,bool UT=false> struct citer_fn{};

            /**
             * @template citer_fn Pspecialization
             */
            template <> struct citer_fn<citer_cfg::cfg_default,false>:public tos
            {
               /**
                * @constructor
                * @param vc   :  container \< map/vector/array >
                * @param sep  :  optional separator, default \\n
                */
               template <
                    class VT,
                    traits::enable_if_not_pod_t<VT> = false
               >
               citer_fn(const VT & vc):tos{}
               {
                  using namespace iterators;
                  std::copy (vc.begin(),vc.end(), basic_container_iterator<VT,tos>{*this});
               }
            protected:
               using tos::tos;

            }; /* functor template  */

            /**
             * @template citer_fn Pspecialization
             */
            template <> struct citer_fn<citer_cfg::cfg_sep,false>:public tos
            {
               /**
                * @constructor
                * @param vc   :  container \< map/vector/array >
                * @param sep  :  optional separator, default \\n
                */
               template <
                    class VT,
                    traits::enable_if_not_pod_t<VT> = false
               >
               citer_fn(const VT & vc,std::string sep={'\n'}):tos{}
               {
                  using namespace titan_v3::tools::iterators;

                  std::copy (   vc.begin(),
                                vc.end(),
                                basic_container_iterator<
                                    VT,
                                    tos,
                                    algorithms::basic_seperated_iterator
                                >
                                {*this,std::move(sep)}                      );
               }
            protected:
               using tos::tos;

            }; /* functor template  */

            /**
             * @template citer_fn Pspecialization
             */
            template <> struct citer_fn<citer_cfg::cfg_ols,false>:public tos
            {
               /**
                * @constructor
                * @param vc   :  container \< map/vector/array >
                * @param sep  :  optional separator, default \\n
                */
               template <
                    class VT,
                    traits::enable_if_not_pod_t<VT> = false
               >
               citer_fn(const VT & vc,std::string sep={'\n'}):tos{}
               {
                  using namespace titan_v3::tools::iterators;

                  std::copy (   vc.begin(),
                                vc.end(), 
                                basic_container_iterator<
                                    VT,
                                    tos,
                                    algorithms::basic_seperated_iterator_ols
                                >
                                {*this,sep}                                     );
               }
            protected:
               using tos::tos;

            }; /* functor template */  
            
            /**
             * @Subfunctor Subfunctor for t_urldb_rc
             * @return  std::string;
             */
            struct t_urldb_rc_str_map_functor
            {
               inline std::string operator()(t_urldb_rc v) const noexcept 
               {
                  switch (v){
                     case t_urldb_rc::urldb_rc_er_dec: return std::string{"urldb_rc_er_dec"};
                     case t_urldb_rc::urldb_rc_er_cal: return std::string{"urldb_rc_er_cal"};
                     case t_urldb_rc::urldb_rc_er_unc: return std::string{"urldb_rc_er_unc"};
                     case t_urldb_rc::urldb_rc_er_udb: return std::string{"urldb_rc_er_udb"};
                     case t_urldb_rc::urldb_rc_er_rcv: return std::string{"urldb_rc_er_rcv"};
                     case t_urldb_rc::urldb_rc_er_snd: return std::string{"urldb_rc_er_snd"};
                     case t_urldb_rc::urldb_rc_er_opn: return std::string{"urldb_rc_er_opn"};
                     //t_urldb_rc::urldb_rc_ok
                     default:return std::string{"urldb_rc_ok"};
                  }
               }
            }; /* functor template */  


            /**
             * @template   cutters_fn (cut data buffer by size) Pspecialization
             * @abstract
             */
            template <typename TSV, bool>struct cutters_fn{};

            template <typename TSV>struct cutters_fn<TSV,false>:public basic_fntor<TSV,true,false>
            {
               /**
                * cutters_fn constructor
                * @param str:       data
                * @param str_size:  data size
                * @param cut_size:  cut size (def 1)
                */
               cutters_fn(const char * __restrict str, size_t str_size,const size_t cut_size=1) noexcept
               {
                  size_t s_{};
                  if (str && *str && str_size && cut_size && (((s_=strnlen(str,str_size))==str_size) || (str_size=s_))){
                     if (str_size>cut_size){
                        const size_t odd_{str_size % cut_size};
                        for ( str_size-=odd_,this->value_.reserve(this->value_.size()+static_cast<size_t>(str_size/cut_size));
                              *str && str_size; 
                              this->value_.emplace_back(typename TSV::value_type{str,cut_size}),
                              str+=cut_size,
                              str_size-=cut_size);
                        if (odd_ && *str){
                           this->value_.emplace_back(typename TSV::value_type{str,odd_});
                        }
                        return;
                     }
                     this->value_.emplace_back(typename TSV::value_type{str,str_size});
                  }
               }

               /**
                * cutters_fn constructor
                * @param str:       data (std::string)
                * @param cut_size:  cut size (def 1)
                */
               cutters_fn(const std::string & str,const size_t cut_size=1):
                        cutters_fn(str.c_str(),str.size(),cut_size){}

            }; /* functor template */  

            /**
             * @template lock_and_find_fn
             *
             */
            template <
                typename TMTX, 
                typename TCTR 
            >
            struct lock_and_find_fn
            {
                  using TF = typename std::conditional< 
                                traits::is_pair< typename TCTR::value_type >::value,
                                typename TCTR::key_type , 
                                typename TCTR::value_type 
                             >::type;

                  using TR = typename std::conditional< 
                                traits::is_pair<typename TCTR::value_type>::value,
                                typename TCTR::mapped_type,
                                typename TCTR::value_type
                             >::type;
                  /**
                   * @abstract ctor
                   * @note mtx has to be mutable 
                   */
                  #if (__clang_major__ >= 4 || __clang_minor__ > 4)
                     constexpr lock_and_find_fn(TMTX & mtx, TCTR & ctr) noexcept :   mtx_{mtx}, 
                                                                                    ctr_{ctr}{}
                  #else 
                     lock_and_find_fn(TMTX & mtx, TCTR & ctr) noexcept : mtx_{mtx}, 
                                                                        ctr_{ctr}{}
                  #endif
   
                  /**
                   * @fn call op 
                   * @abstract lock a mutex ( or a mutex like obj) and search the container for the given value 
                   * @param f[in] : TF
                   * @return a index >- 1 or -1 when not found  
                   */
                  inline
                  typename std::enable_if<
                    std::is_convertible<TR,ssize_t>::value,
                    ssize_t
                  >::type
                  operator()( const TF & f ) const noexcept
                  {

                        #ifndef __clang_analyzer__ 
                           std::unique_lock<TMTX> loc_lock( mtx_ );
                        #endif
                        const auto & index=ctr_.find(f);

                        return ( index != ctr_.end() ?
                                 static_cast<ssize_t>(index->second) :
                                 -1 );
                  }

               protected:
                  TMTX & mtx_;
                  TCTR & ctr_;

            }; /* functor template */

         } /* templates namespace */

      } /* functors namespace */

   } /* tools namespace */

} /* titan_v3 namespace */

#endif /* TTN_FUNCTORS_TEMPLATES_HXX */

