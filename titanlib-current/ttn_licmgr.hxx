/**
 * $Id$
 */

#ifndef LICMGR_HXX
#define LICMGR_HXX
#include "global.h"

#include <iostream>
#include <fstream>
#include <string>
#include <mutex>
#include <sys/stat.h>

/* private namespace */
namespace{
   /**
    * @struct cache
    * @abstract static type, cache manager
    */
   struct cache_mgr{

      /**
       * @struct line_fmt
       * @abstract inner static type line formater
       * provides two template functions 
       * * function out 
       * - param s [in] out stream, 
       * - param v [variadic|in] list of args
       * * function in
       * - param s [in] in stream
       * - param v [variadic|out] ist of args
       */
      struct line_fmt{

         template <typename V> 
         static constexpr std::ostream& out(std::ostream & s, const V & v) noexcept {
            return ((s<<std::showbase<<std::hex<<v<<' ')); /* col */
         }

         template <typename V, typename... VS> 
         static constexpr std::ostream& out(std::ostream & s,const V & v, VS&&... vs) noexcept {
            return line_fmt::out(line_fmt::out(s,v),vs...);
         }

         template <typename V> 
         static constexpr std::ifstream & in(std::ifstream & s,V & v) noexcept {
            s>>std::hex>>v; /* col */
            return s;
         }

         template <const size_t c,typename V> 
         static constexpr size_t in(std::ifstream & s,V & v) noexcept {
            s>>std::hex>>v; /* col */
            return c+1;
         }

         template <const size_t c,typename V, typename... VS> 
         static constexpr size_t in(std::ifstream & s,V & v, VS&&... vs) noexcept {
            return  line_fmt::in<c+1>(line_fmt::in(s,v),vs...);
         }

      }; /* inner struct line_fmt */

      /**
       * @template save
       * @abstract save given fields/variables into the cache file
       * 
       */
      template <typename FILE,typename... ARGS>
      static bool save_(FILE f,ARGS&&... args) noexcept {
         std::ofstream file(f);
         if (file){
            line_fmt::out(file,args...)<<std::endl;
            if ( file.bad() || file.fail()) return false;
            file.close();
            if ( file.bad() || file.fail()) return false;
            return true;
         }
         return false;
      }

      /**
       * @template load
       * @abstract load the license cache into the list of variables
       */
      template <typename FILE,typename... ARGS>
      static bool load_(FILE f,ARGS&&... args ) noexcept 
      {
         std::ifstream file(f);

         if (   file          &&

                !file.bad()   &&

                !file.fail()  &&

                !file.eof()      ){

            constexpr auto max_ = ( sizeof...(ARGS) );

            const auto proc_ = ( line_fmt::in<0>( file, args... ) + 1 );

            file.close();

            return ( max_ == proc_ );
         }

         return false;
      }

   }; /* cache struct */


   enum class lic_query_type{
      none=0x00,
      runtime=0x01,
      cache=0x02,
   };

   /**
    * @tmeplate query_
    */
   template<lic_query_type>
   inline bool query_(lic_info_t&) noexcept ;

   /**
    * @template query_ the runtime specialization
    *
    */
   template<>
   inline bool query_<lic_query_type::runtime>(lic_info_t & lic) noexcept 
   {
      std::array<char,64> buf{};
      std::array<char,64> trimed{};

      if ( exbin( "/blocker/bin/wt-license.php -t ExpiryDate", buf.max_size(), buf.data() ) ) {
         trim_ex( buf.data(), trimed.data(), trimed.max_size() );
         if ( !tx_safe_atol( trimed.data(), &lic.expiry_date ) )
            lic.expiry_date=EXPIRY_DATE_DEFAULT;
      }

      /*TODO:: retest the /blocker/bin/wt-license.php script itself */
      if ( exbin( "/blocker/bin/wt-license.php -v", buf.max_size(), buf.data() ) ) {
         trim_ex( buf.data(), trimed.data(), trimed.max_size() );
         int val=0;
         lic.is_license_violated=(  tx_safe_atoi( trimed.data(), &val ) ?
                                    static_cast<bool>(val) :
                                    IS_LICENSE_VIOLATED_DEFAULT );
      }

   //use chrono/and timer

      if ( !lic.is_license_violated && lic.expiry_date>time(nullptr) ) {

         if ( exbin( "/blocker/bin/wt-license.php -t MaxUsers", buf.max_size(), buf.data() ) ) {
            trim_ex( buf.data(), trimed.data(), trimed.max_size() );
            if ( !tx_safe_atoul( trimed.data() ,&lic.max_users ) )
               lic.max_users=MAX_USERS_MIN_LIC;
         }

         if ( exbin( "/blocker/bin/wt-license.php -t MaxIPs", buf.max_size(), buf.data() ) ) {
            trim_ex( buf.data(), trimed.data(), trimed.max_size() );
            if ( !tx_safe_atoul( trimed.data(), &lic.max_ips ) )
               lic.max_ips=MAX_UNIQ_IPS_MIN_LIC;
         }

         /* Unlimited uips, it's kinda redundant since (today) the UNLIMITED_UNIQ_IP is defined as zero/0 */
         if (lic.max_ips>0)
            lic.max_ips=UNLIMITED_UNIQ_IP;

         /* Unlimited user, it's kinda redundant since (today) the TITAX_UNLIMITED_USER is eq to UNLIMITED_UNIQ_IP */
         if (lic.max_users>0)
            lic.max_users=TITAX_UNLIMITED_USER;

         return true;
      }
      //log
      //titax_log(LOG_ERROR, "License expired, %lu\n", expiry_date);
      lic.max_ips=MAX_UNIQ_IPS_MIN_LIC;
      lic.max_users=MAX_USERS_MIN_LIC;

      return true;
   }

   /**
    * @template query_ the cache spacialization
    */
   template<>
   inline bool query_<lic_query_type::cache>(lic_info_t & lic) noexcept {
      return cache_mgr::load_(
         lic.cache,
         /* define loading loading order */
         lic.is_license_violated,
         lic.max_users,
         lic.max_ips,
         lic.expiry_date
      );
   }


}; /* private namespace */



/* public namespaces */
namespace titan_v3{
   /**
    * @abstract license manager
    */
   namespace lic_mgr{

      /**
       * @fn save 
       * @abstract save the current license information
       */
      inline bool save() noexcept {
         lic_info_t lic{};

         {  /* 
             * locking scope 
             * read current (defaults) 
             */
            using namespace tools;
            mx_scoped_wrapper_t lock{ g_conf_lock } ;

            if ( const TitaxConf * const conf_ = titax_conf_get_instance() ){

                memcpy( &lic,
                        &conf_->license,
                        sizeof( lic_info_t ) );
            }
         }

         /* we might need to use here std::lock_guard<std::mutex> lock(lock_); */
         return cache_mgr::save_(
            lic.cache,
            /* define the saving order */
            lic.is_license_violated,
            lic.max_users,
            lic.max_ips,
            lic.expiry_date
         );

      }

      /**
       * @fn query
       * @abstract query the current license information 
       */
      inline void query() noexcept {
         lic_info_t lic{};
         using namespace tools;


         { /*
            * locking scope
            * read current (defaults)
            */
            mx_scoped_wrapper_t lock{g_conf_lock};
            if ( const TitaxConf * const conf_ = titax_conf_get_instance() ){

                memcpy( &lic,
                        &conf_->license,
                        sizeof( lic_info_t ) );
            }
         }

         struct stat st;

         if (
                /* 
                 * primitive check to see if current process runs within the jail (chroot) 
                 * since on the freebsd the stat method is a syscall then no extra lock is needed
                 * man STAT(2)
                 */
                ( stat("/blocker/bin/wt-license.php", &st) ) ?
                ( query_<lic_query_type::cache>(lic) ) :
                ( query_<lic_query_type::runtime>(lic) ) ){

                    /*
                     * locking scope
                     * write
                     */
                    mx_scoped_wrapper_t lock{g_conf_lock};

                    if ( TitaxConf * const conf_ = titax_conf_get_instance() ){

                        memcpy( &conf_->license,
                                 &lic,
                                 sizeof( lic_info_t ) );
                    }
         }

      }

   }; /* namespace lic_mgr */

}; /* titan namespace */

#endif /* LICMGR_HXX */

