/**
 * $Id$
 */

#ifndef TTN_DOMAINS_HT_HXX
#define TTN_DOMAINS_HT_HXX

#include <stdexcept>
#include <exception>
#include <iostream>
#include <sstream>
#include <vector>
#include <unordered_map>
#include <cassert>
#include <iterator>
#include "global.h"
#include "txhash.h"
#include "log.h"
#include "TitaxConf.h"
#include "ttn_tools.hxx"
#include "ttn_eops.hxx"
#include "ttn_domains_ht_tools.hxx"

namespace titan_v3{

#ifdef TTN_ATESTS
    TXATR bool autotest_domains_ht(void);
#endif

    struct domains_ht_t{

#ifdef TTN_ATESTS 

        friend bool autotest_domains_ht(void);

#endif

        const bool & collision_detected{ collision_detected_ };

        domains_ht_t() noexcept {

            table_.reserve(1024<<4);

        }

        explicit domains_ht_t( const bool use_exceptions ) noexcept :   use_exceptions_{use_exceptions}
                                                                        {
                                                                            table_.reserve(1024<<4);
                                                                        }
        ~domains_ht_t() noexcept {
            clear();
        }

        /**
        * count all
        * @return  : count
        */
        inline
        size_t count() const noexcept {

            return table_.size();
        }

        /**
        * add
        * @param str_       :domain (c str)
        * @param ssz_       :domain length
        * @param policy_    :policy id | -1
        * @param act_       :action
        * @param outhash_   :hash (optional)
        * @return           :true|false
        */
        inline
        bool add(   const char * const str_, 
                    const size_t ssz_, 
                    const ssize_t policy_,
                    const t_wbl_actions act_,
                    t_hash * const outhash_ = {}    ) {

            (void)( outhash_ && ( ( *outhash_ ) = {} ) );

            bool error_{};

            if (    last_str_.size()    && 
                    last_hash_              ){

                error_ = !solving_conflicts_(   str_,
                                                ssz_,
                                                policy_,
                                                act_        );
            }

            if ( !error_ ){

                if (    (   !last_hash_                             &&

                            !default_hash_A_(   str_,
                                                ssz_,
                                                &last_hash_ )   )   ||

                        (   !last_str_.size()                       &&

                            !last_str_.assign(  str_,
                                                ssz_    ).size() )      ) {

                    clear_last_();

                    if ( use_exceptions_ ){

                        throw tools::errors::EHTHashingError();
                    }

                    return false;
                }

                if ( last_policy_ != policy_ ){

                    if ( last_hash_ ) { 

                        s_item_ & hitem = table_[ last_hash_ ];
                        clear_flags_(hitem);
                        last_policy_=policy_;
                        hitem.policies_[ last_policy_ ].actions_ =  act_;
                        last_act_=act_;

                    } else {

                        clear_last_();

                        if ( use_exceptions_ ){

                            throw tools::errors::EHTHashingError();
                        }

                        return false;
                    }

                }

                (void)( outhash_ && ( *outhash_ = last_hash_ ) );

                return (true);
            }

            if ( use_exceptions_ ){

                throw tools::errors::EHTCollision();
            }

            return (false);

        }


        /**
        * add
        * @param str_       :domain (std::string)
        * @param policy_    :policy id | -1
        * @param act_       :action
        * @param outhash_   :hash (optional)
        * @return           : true|false
        */
        inline 
        bool add(   const std::string & str_, 
                    const ssize_t policy_,
                    const t_wbl_actions act_,
                    t_hash * const outhash_ = {}    ){

            return add( str_.c_str(),
                        str_.size(),
                        policy_,
                        act_,
                        outhash_        );
        }
        /**
        * clear all
        * @return : always true
        */
        inline
        void clear() noexcept {

            clear_last_();
            table_.clear();

        }

        inline 
        void dump() const noexcept  {

            for ( const auto &h_ : table_ ) {

                std::cout   <<"<"
                            <<h_.first
                            <<">:{collision:"
                            <<h_.second.flags_.htf_collision
                            <<",collision_ctx:"
                            <<h_.second.flags_.htf_collision_ctx
                            <<",policies:";

                for ( const auto &p_ : h_.second.policies_ ) {

                    std::cout   <<"["
                                <<p_.first
                                <<"|"
                                <<p_.second.actions_
                                <<"],";

                }

                std::cout   <<"}\n";

            }

        }

        /**
        * find
        * @param str_    : domain (std::string)
        * @param policy_ : policy id | -1
        * @param hs_     : hashset
        * @param out_    : hash (opt)
        * @return        : action
        */

#ifdef DHT_OLD_FN_MEASUREMENT

        inline
        t_wbl_actions find( const std::string & str_,
                            const ssize_t policy_,
                            t_hashset & hs_,
                            t_hash * const out_ = {}    ) const {

            (void)( out_ && ( *out_ = {} ) );

            if (    !str_.size()                        || 

                    (   !parse_( str_, hs_     )        && 

                        !hs_.size()                 )       ){


#ifndef TTN_ATESTS

                ::titax_log(    LOG_ERROR,
                                "[%s]:%u:domain parser error\n",
                                __func__,
                                __LINE__                            );
#endif
                return {};
            }

            for ( const auto & h_ : hs_ ) {

                if ( h_ ){
                    const auto r_ = find_hash_( h_, policy_ );

                    if ( t_wbl_actions::wba_none != r_ ){

                        (void)( out_ && ( *out_ = h_ ) );

                        return (r_);

                    }

                }

            }

            return {};
        }

#endif /* DHT_OLD_FN_MEASUREMENT */

        inline
        t_wbl_actions find_fqdn(    const std::string & fqdn_,
                                    const ssize_t policy_       ) const noexcept {

            if ( fqdn_.size() && table_.size()){

                t_wbl_actions act{};

                if ( parse_fqdn_( fqdn_, policy_, act ) ) {

                    return act;

                }

            }

            return {};

        }


#ifdef  OFF_BLOCK /* DO NOT REMOVE IT */

         /**
          * find_exact
          * @param str_    : domain (std::string)
          * @param policy_ : policy id | -1
          * @param hs_     : hashset
          * @param 
          * @param out_    : hash (optional)
          * @return        : action
          */


   t_wbl_actions THTDomains::find_exact( const std::string & str_,
                                            const ssize_t policy_,
                                            t_hashset & hs_,
                                            t_wbl_actions action,
                                            t_hash * const out_ ){
        (void)(out_ && (*out_=0));
        size_t inital_size = hs_.size();
        if ((str_.empty()) ||  ( !this->parse_exact(str_,hs_) && !hs_.size()))
        {
            ::titax_log(LOG_ERROR, "[%s]:%u:domain parser error\n",__func__, __LINE__);
            return (t_wbl_actions::wba_none);
        }
       
        if(hs_.size() > inital_size)
        {
            for (auto it = (hs_.begin() + static_cast<long>(inital_size)) ; it != hs_.end(); ++it)
            {
                auto &h_ = it;
                if(t_wbl_actions r_=this->find_hash_(*h_,policy_))
                {
                    (void)(out_ && (*out_ = *h_));
                    return (r_);
                }
            }
        }
       
        return (action);
   }

#endif /* OFF_BLOCK DO NOT REMOVE IT */


      protected:
         std::unordered_map<t_hash,s_item_>     table_{};
         std::string                            last_str_{};
         t_hash                                 last_hash_{};
         ssize_t                                last_policy_{LLONG_MIN};
         t_wbl_actions                          last_act_{};
         bool                                   use_exceptions_{};
         bool                                   collision_detected_{};
        

         static 
         void clear_flags_( s_item_ & hitem_ ) noexcept {
            hitem_.flags_ = {};
         }

         inline 
         void set_collision_( s_item_ * const hitem_ ) noexcept {

            if ( hitem_ ) {
                collision_detected_=true;
                hitem_->flags_.htf_collision=true;
                hitem_->flags_.htf_collision_ctx++;
            }

         }

         inline 
         void clear_last_policy_() noexcept {
            last_policy_=LLONG_MIN;
         }

         inline 
         void clear_last_() noexcept {
            last_str_.clear();
            last_hash_={};
            clear_last_policy_();
            last_act_={};
         }

         static 
         bool default_hash_A_(   const char * const v_,
                                 const size_t len_,
                                 t_hash * const out_     ) noexcept {

            return (    ( *out_ = 0x9e3779b9U ^ len_ )              &&
                        ::str2djb2_ex( v_, len_, out_ )             &&
                        ( *out_ = ( 0x9e3779b97f4a7c13LU ^ *out_ )) &&
                        ::str2Murmur_ex( v_, len_, out_ )               );
         }

         static
         bool default_hash_B_(   const char * const v_,
                                 const size_t len_,
                                 t_hash * const out_     ) noexcept {
            
            return (    ( *out_ = 0x9e3779b97f4a7c13LU ^ len_ ) &&
                        ::str2fnv_ex( v_, len_, out_ )          &&
                        ( *out_ = ( 0x9e3779b9U ^ *out_ ) )     &&
                        ::str2oat_ex( v_, len_, out_ )              );
         }

         static
         bool find_policy_(   const s_item_ * const hitem_,
                              const ssize_t policy_,
                              t_wbl_actions * const out_={}  )  {

               if (  hitem_                  && 

                     hitem_->policies_.size()   ) {


                    auto psearch = hitem_->policies_.find(policy_);

                    if ( hitem_->policies_.end() != psearch ) {

                       if ( out_ )
                          *out_ = psearch->second.actions_;

                       return (true);

                    }

               }

               return (false);
            }

         inline
         bool find_hash_(  const t_hash h_,
                           s_item_ ** const out_   ) const {

            if (  table_.size()  ){

               if( const size_t c_ = table_.count( h_ ) ) {

                  if ( 1 == c_ ){

                     const auto & hsearch = table_.find( h_ );

                     if (  table_.end() != hsearch ){

                        if ( out_ )
                            *out_ = const_cast< s_item_ * >( &hsearch->second );

                        return (true);
                     }

                     if ( use_exceptions_ )
                        throw tools::errors::EHTHashingError();

                     ::titax_log(LOG_ERROR, "[%s]:%u:EHTHashingError %zu\n",__func__, __LINE__,h_);

                  } else {

                     if ( use_exceptions_ )
                        throw tools::errors::EHTDuplicates();

                     ::titax_log(LOG_ERROR, "[%s]:%u:duplicates %zu\n",__func__, __LINE__,h_);

                  }

               }//else zero

            }

            return false;
         }

         inline
         t_wbl_actions find_hash_(  const t_hash curr_hash_,
                                    const ssize_t policy_   ) const {

            t_wbl_actions r_{};

            s_item_ * hitem{};

            if (  find_hash_(   curr_hash_,
                                &hitem      )   && 

                  hitem                         && 

                  find_policy_(  hitem,
                                 policy_,
                                 &r_       ) ) {

                     return (r_);
            }

            if ( use_exceptions_ )
               throw tools::errors::EHTNotFound();

            return (t_wbl_actions::wba_none);
         }

         inline
         bool solving_conflicts_(   const char * const str_,
                                    const size_t ssz_, 
                                    const ssize_t curr_policy_,
                                    const t_wbl_actions  curr_act_        ){

            using namespace titan_v3::tools::eop;

            t_hash curr_hash{};
            s_item_ * hitem{};

            if (  ( last_str_ != str_ )            && 

                  default_hash_A_(  str_,
                                    ssz_,
                                    &curr_hash  )     ) {


                  if ( last_hash_ != curr_hash ){

                     if ( !find_hash_( curr_hash, &hitem ) ){

                        last_hash_ = curr_hash;
                        last_str_.clear();
                        clear_last_policy_();
                        return (true);
                     }

                     if (  hitem && !find_policy_( hitem,
                                          curr_policy_,
                                          nullptr          )  ) {

                           last_hash_ = curr_hash;
                           last_str_.clear();
                           clear_last_policy_();
                           return (true);
                     }

                     return (false);
                  }

                  if ( last_hash_ == curr_hash ){

                     if ( !find_hash_( curr_hash, &hitem ) ) {

                        last_str_.clear();
                        clear_last_policy_();
                        return (true);
                     }
                  
                    if ( !hitem){

                        if ( use_exceptions_ )
                         throw tools::errors::EHTHashingError();

                          return false;
                    }

                  }

                  //collision handling
                  set_collision_(hitem);

                  if (  default_hash_B_(  str_,
                                          ssz_,
                                          &curr_hash  ) ) {
                  hitem = {};

                     if (  find_hash_( curr_hash, &hitem )  ){

                              set_collision_(hitem);

                              t_wbl_actions act_{};

                           if ( !find_policy_(  hitem,
                                                curr_policy_,
                                                &act_          ) ){

                              last_hash_ = curr_hash;
                              last_str_.clear();
                              clear_last_policy_();
                              return (true);
                           }

                           if (  curr_act_ ==  act_ ) {

                              last_policy_ = curr_policy_;
                              last_hash_ = curr_hash;
                              last_str_.clear();
                              return (true);
                           }
                           
                           if ( use_exceptions_ )
                              throw tools::errors::EHTCollision();

                           return (false);
                     }

                     last_str_.clear();
                     clear_last_policy_();
                     last_hash_=curr_hash;
                     return (true);
                  }

                  if ( use_exceptions_ )
                     throw tools::errors::EHTHashingError();

                  return false;
            }

            return ( (!find_hash_( last_hash_, &hitem ) ) ?:
                     ! ( hitem && find_policy_( hitem, curr_policy_ )) );

         }



         inline
         bool parse_fqdn_(  const std::string & fqdn_,
                            const ssize_t policy_,
                            t_wbl_actions & act_        ) const noexcept {

            try{

                auto policy_checker_=[&](   const char * domain, 
                                            const size_t dmsz,
                                            const ssize_t policy    ) -> t_wbl_actions  {

                    t_hash curr_hash{};

                    s_item_ * hitem{};

                    if (    this->default_hash_A_(  domain,
                                                    dmsz, 
                                                    &curr_hash  )     ) {

                            this->find_hash_( curr_hash, &hitem  );
                    }

                    if (    hitem                         && 
                            hitem->flags_.htf_collision        ){

                                default_hash_B_(    domain,
                                                    dmsz, 
                                                    &curr_hash  );
                    }

                    if ( curr_hash ){

                        return  find_hash_( curr_hash, policy );
                    }

                    return {};
                };

                using namespace domains_tools;

                return  parser::fqdn_ending_martcher(   fqdn_,
                                                        policy_,
                                                        act_,
                                                        policy_checker_  );


#ifndef TTN_ATESTS

            } catch ( const std::exception & e ){

                ::titax_log(    LOG_ERROR,
                                "[%s]:%u:%s\n",
                                __func__,
                                __LINE__,
                                e.what()            );
            }

#else

            } catch ( const std::exception & ){

            }

#endif

            return false;

         }


  
#ifdef OFF_BLOCK /* DO NOT REMOVE IT */

   bool THTDomains::parse_exact(const std::string & str_,t_hashset & hs_ )const
   {
      t_hash curr_hash{};
      s_item_ * hitem=nullptr;
      size_t dmsz{str_.size()};
      size_t c_{};
      size_t ctx_{};
      char *domain = new char[str_.length() + 1];
      char * pch = NULL;
     
      if (dmsz>4000)     //Apache standard limit on Urls
      {
        ::titax_log(LOG_ERROR, "[%s]:%u:domain parser error\n",__func__, __LINE__);
        return (false);
      }
     
      try{
            strlcpy(domain, str_.c_str(),dmsz+1);
            while( pch != NULL || ctx_ == 0)
            {
              dmsz = strlen(domain);
              (void)(this->default_hash_A_(domain,dmsz,&curr_hash)
                      && !( hitem = nullptr )
                      && this->find_hash_(curr_hash,&hitem));
              (void)(hitem
                   && hitem->flags_.htf_collision
                      && this->default_hash_B_(domain,dmsz,&curr_hash)
                      && curr_hash && !( hitem = nullptr )
                      && this->find_hash_(curr_hash,&hitem) );
              hs_.push_back(curr_hash);
              ++ctx_;

              pch=strrchr(domain,'&');
             
              if(pch != NULL)
              {
                  *pch = '\0';
              }

              if (pch == NULL)
              {
                  delete[] domain;
                  return (static_cast<bool>(ctx_));
              }

              if ((c_+=2)>4000)     //Apache standard limit on Urls
              {
                 delete[] domain;
                 ::titax_log(LOG_ERROR, "[%s]:%u:domain parser error\n",__func__, __LINE__);
                 return (false);
                }
            }
        } catch (...){}
      delete[] domain;
      return (static_cast<bool>(ctx_));
   }  


#endif /* OFF_BLOCK DO NOT REMOVE IT */


#ifdef DHT_OLD_FN_MEASUREMENT

       bool parse_(const std::string & str_,t_hashset & hs_ ) const 
       {

          t_hash curr_hash{};
          s_item_ * hitem{};
          const char * domain=str_.c_str();
          const char * org=domain;

          size_t ctx_{};
          try{
             size_t dmsz{str_.size()};
             size_t c_{};
             while (domain)
             {
                if ( this->default_hash_A_(domain,dmsz,&curr_hash) )
                {
                    hitem = nullptr;
                    this->find_hash_(curr_hash,&hitem);
                }

                if ( hitem && hitem->flags_.htf_collision && this->default_hash_B_(domain,dmsz,&curr_hash) && curr_hash )
                {
                    hitem = nullptr;
                    this->find_hash_(curr_hash, &hitem);
                }

                hs_.emplace_back(curr_hash);
                ++ctx_;
                ptrdiff_t tmp_{};
                if (    ( domain=::strnstr(domain+1,".",dmsz) ) &&
                        !::ptr_diff(domain,org,&tmp_)               ){

                            tmp_=0;
                }

                if ( domain )
                   org=domain;
                dmsz-=static_cast<size_t>(tmp_);
                if (!domain){
                   return (static_cast<bool>(ctx_));
                }

                /*Q? Why repeat the above code again, rather than simply loop (after  c_ += 1)*/
                if ( this->default_hash_A_(domain,dmsz,&curr_hash) )
                {
                    hitem = nullptr;
                    this->find_hash_(curr_hash,&hitem);
                }

                if ( hitem && hitem->flags_.htf_collision
                     && this->default_hash_B_(domain,dmsz,&curr_hash)
                     && curr_hash )
                {
                    hitem = nullptr;
                    this->find_hash_( curr_hash, &hitem );
                }

                hs_.emplace_back(curr_hash);
                ++ctx_;
                tmp_=0;
                if (    ( domain=::strnstr(domain+1,".",dmsz) ) &&
                        !::ptr_diff(domain,org,&tmp_)               ){

                            tmp_=0;
                }

                if ( domain )
                   org=domain;
                dmsz-=static_cast<size_t>(tmp_);
                if (!domain){
                   return (static_cast<bool>(ctx_));
                }

                if ((c_+=2)>256){
                    #ifndef TTN_ATESTS
                        ::titax_log(LOG_ERROR, "[%s]:%u:domain parserr error\n",__func__, __LINE__);
                    #endif
                    return (false);
                }
             }
          } catch (...){}
          return (static_cast<bool>(ctx_));
       }

#endif /* DHT_OLD_FN_MEASUREMENT */


   }; /* domains_ht_t */

} /* NS */

#endif /* TTN_DOMAINS_HT_HXX */

/* vim: set ts=4 sw=4 et : */

