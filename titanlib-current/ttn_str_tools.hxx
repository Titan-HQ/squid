/**
 * $Id$
 */

#ifndef TTN_STR_TOOLS_HXX
#define TTN_STR_TOOLS_HXX

#include <string>
#include "global.h"
#include "ttn_status_pair.hxx"
#include "ttn_functors_templates.hxx"

namespace titan_v3{

   namespace tools {

      /**
       * @function  left trim
       * @param str  :  input string
       * @return     :  trimmed string
       */
      std::string & ltrim(std::string & str);

      /**
       * @function   right trim
       * @param str  :  input string
       * @return     :  trimmed string
       */
      std::string & rtrim(std::string & str);

      /**
       * @function is whole stirng numeric
       * @param str  :  input string
       * @return     :  t/f
       */
      bool isnumeric(std::string & str);

      using t_split_lamda=std::function<void(std::string & s_)>;

      /**
       * @function   split
       * @param out     :vector of strings - won't be cleared so the new elements will be appended to it 
       * @param str     :input string
       * @param sep     :separator string (opt) [default:" "]
       * @param lmbd    :lambda function (opt)  [default:noop function] - to do the subprocessing
       * @return        :count of elements 
       */
      size_t split(globals::strings_t & out,const std::string & str, const char * const sep=" ",t_split_lamda lmbd=[](std::string &){});

      constexpr size_t split_not_found=1;

      /**
       * @functor raw_cutter
       * 
       */
      using raw_cutter=titan_v3::tools::functors::templates::cutters_fn<globals::raw_parts_t,false>;

      /**
       * @functor str_cutter
       * 
       */
      using str_cutter=titan_v3::tools::functors::templates::cutters_fn<globals::strings_t,false>;
      

      /**
       * @function trim
       * @param str  :  input string
       * @return     :  trimmed string
       */
      TX_CPP_INLINE_LIB
      std::string trim(std::string str){
         return ltrim(rtrim(str));
      };

      /**
       * @function   trim in place
       * @param str  :  input/output string
       * 
       */
      TX_CPP_INLINE_LIB
      void trim_inplace(std::string & str){
         (void)ltrim(rtrim(str));
      };

      /**
       * is_idna_punycode (not a thread-safe method)
       * @param   :std::string domain name
       * @return  :bool t/f
       */
      bool is_idna_punycode(const std::string&);
      
      enum class case_conv_t{
         to_auto=0x00,
         to_lower=0x01,
         to_upper=0x02,
      };

      /**
       * @fn convert_case_in_place
       * @param str[in] : std::string 
       * @param act[in] : t_case_conv
       * @return bool
       */
      TX_CPP_INLINE_LIB
      bool convert_case_in_place(   std::string & str,
                                    const case_conv_t act=case_conv_t::to_lower) noexcept {
         if ( str.size() ){

            switch (act){
               case case_conv_t::to_lower :{
                  std::transform (  str.begin(), 
                                    str.end(), 
                                    str.begin(), 
                                    [](const uint8_t c){ 
                                       return static_cast<uint8_t>(std::tolower(c));
                                    }
                                 );
               } break;
               case case_conv_t::to_upper :{
                  std::transform (  str.begin(), 
                                    str.end(), 
                                    str.begin(), 
                                    [](const uint8_t c){ 
                                       return static_cast<uint8_t>(std::toupper(c));
                                    }
                                 );
               } break;
               //case_conv_t::to_auto
               default :{
                  std::transform (  str.begin(),
                                    str.end(),
                                    str.begin(),
                                    [](const uint8_t c){
                                       return ( std::islower(c) ?
                                                static_cast<uint8_t>(std::toupper(c)) :
                                                static_cast<uint8_t>(std::tolower(c)) );
                                    }
                                 );
               } break;
            }

            return true;
         }

         return false;
      }
      
      /**
       * @fn convert_to_lower
       * @abstract lower case the string  in place
       * @param str[in] : std::string 
       * @return bool
       */
      TX_CPP_INLINE_LIB
      bool convert_to_lower( std::string & str ){
         return convert_case_in_place(str);
      }

      template <typename T>
      using value_by_key_status = status_pair_t<T>;

      /**
       * @tmplate value_by_key
       * @note locate a sep + key or key in the input str and execute an exec_ with begin, end 
       */
      template < typename R , typename E >
      TX_CPP_INLINE_LIB
      value_by_key_status<R>  value_by_key(  const std::string & str_,
                                             std::string sep_,
                                             std::string key_,
                                             E exec_                    ) noexcept {

         if ( str_.length() ){

            /* could be improved/simplified */

            size_t begin_{  str_.find( sep_ + key_ ) };

            if (  (  begin_ != std::string::npos                                    &&

                     ( begin_ = ( sep_.length() + begin_ + key_.length() ) )    )   ||

                  (  ( begin_ = str_.find( key_ ) ) != std::string::npos            &&  

                     ( begin_ = ( begin_ + key_.length() ) )                    )      ) {


               size_t end_{ str_.find_first_of( sep_, begin_ ) };

               if ( end_  == std::string::npos ){

                  end_= str_.length();

               }

               return value_by_key_status<R>::success(   exec_(   begin_, 
                                                                  ( end_ - begin_ ) )  );

            }

         }

         return value_by_key_status<R>::failure();

      };

      /**
       * @fn get_value
       * @note 
       */

      using get_value_stat=value_by_key_status<std::string>;

      TX_CPP_INLINE_LIB
      get_value_stat get_value( const std::string & str_,
                                std::string sep_,
                                std::string key_          ) noexcept {

            if ( key_.size() ){

                auto exec_fn_ = [ & ](  const size_t b_,
                                                const size_t e_   ){

                    if ( str_[ b_ ] == '=' ){

                        return str_.substr( b_ + 1 , e_ - 1 );

                    } else {

                        return str_.substr( b_ , e_ );

                    }

                };

             return value_by_key< std::string >( str_, sep_, key_, exec_fn_ );

            }

         return get_value_stat::failure();

      };

      /**
       * @fn update_value
       * @note this method only updates an existing key, if key is not present it won't update/append it.
       */
      TX_CPP_INLINE_LIB
      bool update_value(   std::string & str_,
                           const std::string & sep_,
                           const std::string & key_,
                           const std::string & val_ = {}    ) noexcept {


            if ( key_.size() ) {

                auto rep_exec_fn_ = [ & ](  const size_t b_,
                                            const size_t e_     ){

                    str_.replace( b_, e_, ( str_[ b_ - 1 ] == '='         ?

                                            val_                          :

                                            std::string{ "=" + val_ }  )     );
                    return true;

                };

                auto ers_exec_fn_ = [ & ](  const size_t b_,
                                            const size_t e_     ){


                    if ( str_[ b_ - 1 ] == '=' ){

                       str_.erase( b_ -1 , e_ + 1 ) ;

                    } else {

                       str_.erase( b_ , e_ ) ;

                    }

                    return true;

                };

                
                return (    val_.length()                                       ?

                            value_by_key< bool >(   str_,
                                                    sep_,
                                                    key_,
                                                    rep_exec_fn_    ).first     :

                            value_by_key< bool >(   str_,
                                                    sep_,
                                                    key_,
                                                    ers_exec_fn_    ).first         );
            }

            return {};

      };

   } /* tools namespace */

} /* titan_v3 namespace */


#endif /* TTN_STR_TOOLS_HXX */

