/* 
 * $Id$
 * 
 */

#ifndef TAPE_HXX
#define	TAPE_HXX

#include <iostream>
#include <exception>
#include <stdexcept>
#include <streambuf>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <assert.h>
#include <chrono>
#include <memory>

#include "ttn_wada.hxx"
#include "global.h"
#include "ttn_global.hxx"
#include "TitaxConf.h"
#include "TitaxUser.h"
#include "Group.h"
#include "txip.h"
#include "DbUserRequestTask.hxx"
#include "tx_log.hxx"
#include "ttn_domains_ht.hxx"
#include "ttn_uniqip.hxx"
#include "ttn_locations.hxx"
#include "ttn_cfg.hxx"


#include "titan_instance_tracker.hxx"

#include "TAPE.h"
#include "TAPE_types.hxx"
#include "TAPE_tools.hxx"

namespace titan_v3 {

    //Titan Policy Engine
    class TaPE{

        protected:
            cfg::TCFGInfo              ttncfg_{};

            char                       blocked_keywords_[1024]{};

            char                       category_str_[2048]{};

            t_strptr *                 ext_map_{};

            using uniqips_type=uniqip::uniqip_box_type<MAX_UNIQ_IP_LIST_LEN>;

            uniqips_type               uniqips{}; 

            app_mode_t                 app_mode_{};

            bool open_logger();

            void combine_policies(  const size_t,
                                    IHRequest &, 
                                    const POLICY * const, 
                                    const bool              ) ;

            static void combine_actions(    t_wbl_actions & l_,
                                            const t_wbl_actions r_,
                                            const bool least_restrictive = false    ) noexcept
            { 

                /*
                * least_restrictive: wba_bypassfilters->(wba_none*)->wba_block
                * most_restrictive: wba_block->(wba_none*)->wba_bypassfilters
                * *(wba_none|wba_log)
                */
                using namespace titan_v3::tools::eop;

                if ( !least_restrictive ){

                    if ( !as_bool( l_ & t_wbl_actions::wba_block ) ){

                        if ( l_ < t_wbl_actions::wba_bypassfilters ){

                            if ( !as_bool( r_ & t_wbl_actions::wba_bypassfilters ) ){

                                l_ |= r_;

                            }

                            return;

                        }

                        l_ |= r_;

                    }

                    return;
                }

                if ( !as_bool( l_ & t_wbl_actions::wba_bypassfilters ) ){

                    if ( ( l_ < t_wbl_actions::wba_bypassfilters ) ){

                        if ( !as_bool( r_ & t_wbl_actions::wba_block ) ){

                            l_ |= r_;

                        }

                        return;
                    }

                    l_ |= r_;
                }

            }

            bool is_file_extension_blocked( const POLICY &, const TaTag & );

            bool is_request_blocked( IHRequest & );


            urldb_simple_stats_t categorize( IHRequest & ) noexcept;

            bool fetch_missing_info( IHRequest & );

            bool is_request_allowed( IHRequest & );

        public:

            locations::locations_box_type   locations{ttncfg_};

            TaPE();

            ~TaPE();

            void log( IHRequest & , ICacheInfo & );

            request_state matchACL( IHRequest &,
                                    IACLChecklist *const,
                                    t_check_authentication_method * const   );

            request_state matchACLCheckAuth(    IHRequest&,
                                                IACLChecklist * const,
                                                t_check_authentication_method * const   );

            request_state matchACLCheckAnswer(  IHRequest &,
                                                IACLChecklist * const,
                                                request_state           );

            bool fetchIdentity( IHRequest &,
                                const search_identity_by,
                                const cidr_t &              );

            inline
            bool check( IHRequest & rq_,
                        const request_state st   ) {

                IHRequestFlags & flags=rq_.get_flags();

                switch (st){
                    case request_state::dunno:{

                        const bool r_ = ( flags.ttn_has_been_processed ?: is_request_allowed( rq_ ) );

                        /*  TODO: review use of the ttag.app_type
                            intentionally treat the titan_app requests as errors */
                        return ( rq_.ttag.app_type == txapp_cmd_none ? r_ : false );

                    }

                    case request_state::allow:{

                        /* if the current request is already allowed lets inform the PE about this too */
                        flags.ttn_explicitly_allowed = true;


                        const bool r_ = ( flags.ttn_has_been_processed ?: fetch_missing_info( rq_ ) );

                        if ( !flags.ttn_do_not_check  && !flags.ttn_log_not_block ){

                            flags.ttn_request_is_blocked = false;
                        }

                        flags.ttn_has_been_processed = r_;

                        /*  TODO: review use of the ttag.app_type
                            intentionally treat the titan_app requests as errors */
                        return ( rq_.ttag.app_type == txapp_cmd_none ? r_ : false );

                    }

                    case request_state::deny:
                    default:{

                        /* if the current request is already blocked lets inform the PE about this too */
                        flags.ttn_request_is_blocked=true;

                        flags.ttn_has_been_processed = ( flags.ttn_has_been_processed ?: fetch_missing_info( rq_ ) );

                        /* load basic info and reply as it was */

                    }

                }

                return false;

           }

            bool init(  const char* const log_name="proxy",
                        const int log_level=LOG_FATAL,
                        const bool verbose=true,
                        vPGconn* const db_=nullptr          );

            inline
            void uniqips_clear_old(){

                this->uniqips.clear(MAX_UNIQ_IP_TTL4LIC);

            }

            cfg::TCFGInfo & ttncfg;

            const app_mode_t &  app_mode{app_mode_};

            titan_v3::wada_t wada{locations};

            class t_wbl{

                friend class TaPE;

                protected:
                    mutable std::mutex lock_{};
                    TaPE & owner_;
                    inline void clear_(){
                        std::lock_guard<std::mutex> wbl_lock{lock_};
                        domains_.clear();
                    }
                public:
                    domains_ht_t domains_{};
                    t_wbl(TaPE & o):owner_(o){}

                    friend std::ostream& operator<<(std::ostream& out, t_wbl &){
                        out<<"t_wbl\n";
                        return (out);
                    }

                    bool reload(vPGconn* const db_=NULL);

                    /**
                     * @name check_all
                     * @abstract check host and path against domain and keyword w/b lists 
                     * ( global policy only )
                     * @param host[in]
                     * @param path[in]
                     * @retunr t_wbl_actions
                     */
                    t_wbl_actions check_all( const std::string &, const std::string & ) const noexcept;


                    /**
                     * @name check_fqdn
                     * @abstract check host and against domain w/b lists 
                     * @param host_[in]
                     * @param policy_[in] ( polic id or -1 for global )
                     * @retunr t_wbl_actions
                     */
                    inline
                    t_wbl_actions check_fqdn(   const std::string & host_,
                                                const ssize_t policy_       ) const noexcept
                    {

                        std::lock_guard<std::mutex> wbl_lock{lock_};

                        return  (   host_.size()                            ?

                                    domains_.find_fqdn( host_, policy_  )   :

                                    t_wbl_actions::wba_none                     );

                    }

            }  wbl;

            class t_ldap{
                friend class TaPE;
                protected:
                    TaPE & owner;
                    globals::strings_t ldap_domains_{};
                public:
                    const globals::strings_t & ldap_domains;
                    t_ldap(TaPE & o):owner(o),ldap_domains{ldap_domains_}{
                        this->ldap_domains_.reserve(10);
                    }
                    bool reload_domains(vPGconn* const db_=NULL);
            }  ldap;

            /**
            * TODO: TRACE THE REDUNDANCY
            */
            class t_tools{
                friend class TaPE;
                protected:
                    TaPE & owner;
                public:
                    t_tools(TaPE & o):owner(o){}
                    std::string conv2pform(std::string);
                    //convert username string to common form (currently it is uname@domain)
                    std::string conv2cform(std::string, const std::string &); //const ref is ok here

                    std::string err2str(const t_err_type)const;
                    void titax_log_msg(const int, const char *const);
            }  tools;

    }; /* TaPE */

    extern TaPE GTAPE;

//------------------------------------------------------------------------------
    /**
     * Diagnostic Instrumentation
     */
    titan_instance_tracker *get_titan_instance_tracker_TaTag();
    void print_tracked_TaTag( void *a_p, std::ostream & a_s);
    void Check_tracker_TaTag( std::ostream & a_os, uint32_t a_older_than_secs);
    void Output_GTAPE_information( std::ostream & a_os);  

}; /* titan_v3 */

#endif /* TAPE_HXX */

/* vim: set ts=4 sw=4 et : */

