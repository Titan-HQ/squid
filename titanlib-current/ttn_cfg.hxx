/**
 * $Id$
 */

#ifndef CFG_HXX
#define CFG_HXX


#include <iostream>
#include <string>
#include "TitaxConf.h"
#include "ttn_cidr.hxx"
#include "ttn_global.hxx"
#include "ttn_licmgr.hxx"
#include "ttn_tools.hxx"

namespace titan_v3{

   namespace cfg{

      /**
       * @class TCFGInfo
       */
      class TCFGInfo: protected TitaxConf{
         protected:
            inline bool dump(std::ostream& out) const noexcept {
                using namespace cidr;
               /* todo: restore lic printout */
               out<<"\n>>[TCFGInfo]:\n";
               out<<"\tenable_auth:{"<<enable_auth  <<"}\n";
               out<<"\tallow_ip:{"<<allow_ip<<"}\n";
               out<<"\tallow_ldap:{"<<allow_ldap <<"}\n";
               out<<"\tallow_wada:{"<<allow_wada <<"}\n";
               out<<"\t_bp_backed_http._ip:{"<<bp_backed_http.ip <<"}\n";
               out<<"\t_bp_backed_http._path:{"<<bp_backed_http.path <<"}\n";
               out<<"\t_bp_backed_http._port:{"<<bp_backed_http.port <<"}\n";
               out<<"\tdebug:{"<<debug <<"}\n";
               out<<"\tdisable_filteronreq:{"<<disable_filteronreq <<"}\n";
               out<<"\tdisable_urldb:{"<<disable_urldb  <<"}\n";
               out<<"\tenable_ntlm:{"<<enable_ntlm  <<"}\n";
               out<<"\tint_ip_4:{"<< int_ip_4 <<"}\n";
               out<<"\tint_ip_6:{"<< int_ip_6 <<"}\n";
               out<<"\ttransparentproxy:{"<<transparentproxy  <<"}\n";
               out<<"\tintercept_login:{"<<intercept_login  <<"}\n";
               out<<"\tip_session:{"<<ip_session  <<"}\n";
               out<<"\tleast_restrictive:{"<<least_restrictive  <<"}\n";
               out<<"\tlog_cfg.ip.ipa:{"<<log_cfg.ip<<"}\n";
               out<<"\tlog_cfg.port:{"<<log_cfg.port  <<"}\n";
               out<<"\tlog_cfg.path:{"<<log_cfg.path  <<"}\n";
               out<<"\tlog_cfg.path_sz:{"<<log_cfg.path_sz  <<"}\n";
               out<<"\tlog_cfg.type:{"<<log_cfg.type  <<"}\n";
               out<<"\tproxy_port:{"<<proxy_port <<"}\n";
               out<<"\ttmp_intercept_login_pfm:{"<<tmp_intercept_login_pfm <<"}\n";
               out<<"\tuse_gids:{"<<use_gids <<"}\n";
               out<<"\tuse_kshield:{"<<use_kshield <<"}\n";
               out<<"\twada_cache_file:{"<<wada_cache_file <<"}\n";
               out<<"\twada_ignore_errors:{"<<wada_ignore_errors <<"}\n";
               out<<"\twada_keep_existing_entries:{"<<wada_keep_existing_entries <<"}\n";
               out<<"\tfext_greedy_match:{"<<fext_greedy_match<<"}\n";
               out<<"\tfext_max_match_count:{"<<fext_max_match_count<<"}\n";
               out<<"\twtc_strip_some_headers:{"<<wtc_strip_some_headers<<"}\n";
               out<<"\tverbose:{"<<verbose<<"}\n";
               return true;
            }

            size_t lic_ctx{};
            time_t t_={};


            inline bool reload() noexcept {
               const TitaxConf* const  tcfg_{ titax_conf_get_instance() };
               if (tcfg_ ) {
                  allow_ldap=tcfg_->allow_ldap;
                  enable_auth=tcfg_->enable_auth;
                  transparentproxy=tcfg_->transparentproxy;
                  intercept_login=tcfg_->intercept_login;
                  tmp_intercept_login_pfm=tcfg_->tmp_intercept_login_pfm;
                  memcpy(&license,&tcfg_->license,sizeof(lic_info_t));
                  disable_filteronreq=tcfg_->disable_filteronreq;
                  debug=tcfg_->debug;
                  allow_ip=tcfg_->allow_ip;
                  enable_ntlm=tcfg_->enable_ntlm;
                  use_kshield=tcfg_->use_kshield;
                  ip_session=tcfg_->ip_session;
                  ac_ttl_slide=tcfg_->ac_ttl_slide;
                  ip_session_ttl=tcfg_->ip_session_ttl;
                  allow_wada=tcfg_->allow_wada;
                  proxy_port=tcfg_->proxy_port;
                  wada_keep_existing_entries=tcfg_->wada_keep_existing_entries;
                  wada_ignore_errors =tcfg_->wada_ignore_errors;
                  disable_urldb=tcfg_->disable_urldb;
                  use_gids=tcfg_->use_gids;
                  least_restrictive=tcfg_->least_restrictive;

                  restrict_access_context_str.clear();

                  if ( tcfg_->restrict_access_context && *tcfg_->restrict_access_context ) {

                     restrict_access_context_str.assign(tcfg_->restrict_access_context);
                  }

                  restrict_access_to_tenants_str.clear();

                  if ( tcfg_->restrict_access_to_tenants && *tcfg_->restrict_access_to_tenants ) {

                     restrict_access_to_tenants_str.assign(tcfg_->restrict_access_to_tenants);
                  }

                  restrict_access_domains_str.clear();

                  if ( tcfg_->restrict_access_domains && *tcfg_->restrict_access_domains ) {
                     reload_access_domains = true;
                     restrict_access_domains_str.assign(tcfg_->restrict_access_domains);
                  }

                  return true;
               }
               return false;
            }

         public:
            TCFGInfo() noexcept {
               this->clear();
               t_=time(nullptr);
            }

            inline bool lock_and_init() noexcept {

               if ( const TitaxConf* const  tcfg_=titax_conf_get_instance() ){
                  using namespace tools;

                  mx_scoped_wrapper_t lock{g_conf_lock};

                  (void)::strlcpy(  wada_cache_file,
                                    tcfg_->wada_cache_file,
                                    sizeof(wada_cache_file) );

                  if ( tcfg_->int_ip_4_len ){

                     ip_4_str={  tcfg_->int_ip_4,
                                 tcfg_->int_ip_4_len};

                     const auto & s = cidr::factory::make_ipaddr(   ip_4_str,
                                                                    cidr::raw_ipaddr_hint::ipv4 );
                     if ( s.second )
                        ip_4=std::move(s.first);
                  }

                  if ( tcfg_->int_ip_6_len ){

                     ip_6_str={  tcfg_->int_ip_6,
                                 tcfg_->int_ip_6_len};

                     const auto & s= cidr::factory::make_ipaddr(    ip_6_str,
                                                                    cidr::raw_ipaddr_hint::ipv6 );
                     if ( s.second )
                        ip_6=std::move(s.first);
                  }

                  if (  !cidr::checks::is_nz(ip_4) &&
                        !cidr::checks::is_nz(ip_6)    ){

                           //logging ??
                           return false;
                  }

                  if ( tcfg_->hostname_len ){

                     hostname_str={ tcfg_->hostname,
                                    tcfg_->hostname_len};
                  }

                  if ( tcfg_->fqdn_len ){

                     fqdn_str={  tcfg_->fqdn,
                                 tcfg_->fqdn_len};
                  }

                  if ( tcfg_->cnames_len ){

                     cnames_str={   tcfg_->cnames,
                                    tcfg_->cnames_len};
                  }

                  (void)::tx_safe_memcpy( &bp_backed_http,
                                          &tcfg_->bp_backed_http,
                                          sizeof(bp_backed_http_t) );

                  (void)::tx_safe_memcpy( &log_cfg,
                                          &tcfg_->log_cfg,
                                          sizeof(t_txpe_logging_cfg) );

                  verbose=tcfg_->verbose;
                  fext_greedy_match=tcfg_->fext_greedy_match;

                  if ( (fext_max_match_count=tcfg_->fext_max_match_count) ){

                        //reload the rest
                        return reload();
                  }

                  if ( tcfg_->restrict_access_context && *tcfg_->restrict_access_context) {

                     restrict_access_context_str.assign(tcfg_->restrict_access_context);
                  }

                  if ( tcfg_->restrict_access_to_tenants && *tcfg_->restrict_access_to_tenants ) {

                     restrict_access_context_str.assign(tcfg_->restrict_access_to_tenants);
                  }

                  if ( tcfg_->restrict_access_domains && *tcfg_->restrict_access_domains ) {
                     reload_access_domains = true;
                     restrict_access_domains_str.assign(tcfg_->restrict_access_domains);
                  }

               }

               return false;
            }

            inline bool lock_and_reload() noexcept {
               /* todo: lock and reload only when there is actual need for it or every so often   */
               using namespace tools;

               mx_scoped_wrapper_t lock{g_conf_lock};
               return  reload();
            }

            inline bool clear() noexcept {
               (void)zm(wada_cache_file,sizeof(wada_cache_file));
               (void)zm(int_ip_4,sizeof(int_ip_4));
               (void)zm(int_ip_6,sizeof(int_ip_6));
               (void)zm(&bp_backed_http,sizeof(bp_backed_http_t));
               (void)zm(&log_cfg,sizeof(t_txpe_logging_cfg));

               restrict_access_to_tenants_str.clear();
               restrict_access_context_str.clear();
               restrict_access_domains_str.clear();
               reload_access_domains = false;

               wada_ignore_errors=false;
               wada_keep_existing_entries=false;
               enable_auth=false;
               allow_ldap=false;
               allow_ip=false;
               enable_ntlm=false;
               use_kshield=false;
               ip_session=false;
               ac_ttl_slide=false;
               ip_session_ttl=0;
               allow_wada=false;
               transparentproxy=false;
               intercept_login=false;
               tmp_intercept_login_pfm=false;
               proxy_port=0;
               license={};
               disable_filteronreq=false;
               debug=false;
               disable_urldb=false;
               least_restrictive=true;
               use_gids=false;
               return true;

            }

            /**
             * @fn is_request_local
             * @abstract checks if given request is local:
             * compares given string against:
             * a) hostname
             * b) fqdn
             * c) ipv4
             * d) ipv6
             * e) cnames
             * @param host [in] : std::string (copy)
             * @param cfg [in]  : cfg::TCFGInfo 
             * @return bool
             */
            inline bool is_request_local( std::string host ) noexcept {
               using namespace cidr;


               if ( size_t host_sz=host.size() ){

                  if ( '['==host[0] ){
                     host.erase(0,1);
                     host.erase(----host_sz,1);
                  }

                  const auto & s = factory:: make_cidr(host);
                  bool is_ip{};
                  if ( (is_ip=s.second) ){

                     const raw_ipaddr_t host_ip{ s.first };

                     if (  host_ip==ip_4 ||
                           host_ip==ip_6    ) {

                              return true;
                     }
                  }

                  if (  is_ip || 
                        tools::convert_to_lower(host) ){

                         if ( const size_t cnames_sz=cnames_str.size() ){

                            if (  cnames_sz>=host_sz ){

                                if ( std::string::npos!=cnames_str.find(host) ){

                                    return true;
                                }

                            } else {

                                if ( std::string::npos!=host.find(cnames_str) ){

                                    return true;
                                }

                            }

                         }

                         if (  hostname_str.size() &&
                               hostname_str == host ){

                                  return true;
                         }

                         if (  fqdn_str.size() &&
                               fqdn_str == host ){

                                  return true;
                         }

                  }

               }

               return false;
            }

            /**
             * @fn is_lic_valid
             * @abstract check license state
             */
            inline bool is_lic_valid() noexcept {

               if (1024<=++ lic_ctx){
                  t_=time(nullptr);
                  lic_ctx=0;
               }

               return !(   (t_ > this->license.expiry_date) || 
                           this->license.is_license_violated   );
            }

            /* note : see also the wada_t::configure as it internally stores the raw pointer to this member  */
            using TitaxConf::wada_cache_file;

            std::string          ip_4_str{};
            std::string          ip_6_str{};
            cidr::raw_ipaddr_t   ip_4{};
            cidr::raw_ipaddr_t   ip_6{};

            std::string          fqdn_str{};
            std::string          cnames_str{};
            std::string          hostname_str{};
            std::string          restrict_access_to_tenants_str{};
            std::string          restrict_access_context_str{};
            std::string          restrict_access_domains_str{};
            bool                 reload_access_domains;
            using TitaxConf::bp_backed_http;
            using TitaxConf::log_cfg;
            using TitaxConf::proxy_port;
            using TitaxConf::license;
            using TitaxConf::wada_ignore_errors;
            using TitaxConf::wada_keep_existing_entries;
            using TitaxConf::disable_urldb;
            using TitaxConf::enable_auth;
            using TitaxConf::allow_ldap;
            using TitaxConf::allow_ip;
            using TitaxConf::enable_ntlm;
            using TitaxConf::use_kshield;
            using TitaxConf::ip_session;
            using TitaxConf::ip_session_ttl;
            using TitaxConf::ac_ttl_slide;
            using TitaxConf::allow_wada;
            using TitaxConf::transparentproxy;
            using TitaxConf::intercept_login;
            using TitaxConf::tmp_intercept_login_pfm;
            using TitaxConf::disable_filteronreq;
            using TitaxConf::debug;
            using TitaxConf::least_restrictive;
            using TitaxConf::use_gids;
            using TitaxConf::verbose;
            using TitaxConf::fext_greedy_match;
            using TitaxConf::fext_max_match_count;
            using TitaxConf::wtc_strip_some_headers;

            friend std::ostream& operator<<(std::ostream& out, const TCFGInfo & obj)
            {
                obj.dump(out);
                return (out);
            }

            friend std::ostream& operator<<(std::ostream& out, const TCFGInfo * const obj)
            {
                if ( obj) {
                    obj->dump(out);
                }

                return (out);
            }

      }; /* TCFGInfo */

   }; /*namespace cfg */

}; /* titan namespace */

#endif /* CFG_HXX */

