/**
 * $Id$
 */

#ifndef TTN_DOMAINS_HT_TOOLS_HXX
#define TTN_DOMAINS_HT_TOOLS_HXX

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


namespace titan_v3{

    /**
    * t_hashset : list of hashes (std::vector)
    */
    using t_hashset = std::vector<t_hash>;

    struct t_ht_flags {
        size_t htf_collision_ctx{};
        bool htf_collision{};
    };

    /**
    * t_wbl_actions : actions
    */
    enum class t_wbl_actions{
        wba_none = 0x00,
        wba_log = 0x01,
        wba_bypassauth = 0x02,
        wba_bypassfilters = 0x04,
        wba_block = 0x08,
        wba_max=(wba_log| wba_bypassauth | wba_bypassfilters |wba_block),
    };

    struct t_wbl_actions_map_fn{

        inline 
        std::string operator()( const t_wbl_actions v ) const noexcept {

            using namespace titan_v3::tools::eop;

            if ( t_wbl_actions::wba_none == v ){
                return "None";
            }

            std::string ret{};

            if ( as_bool( v & t_wbl_actions::wba_log ) ) 
                ret+="Log ";

            if ( as_bool( v & t_wbl_actions::wba_bypassauth ) ) 
                ret+="BypassAuth ";

            if ( as_bool( v & t_wbl_actions::wba_bypassfilters ) ) 
                ret+="BypassFilters ";

            if ( as_bool( v & t_wbl_actions::wba_block ) ) 
                ret+="Blocked ";

            return ret;
        }

    };

    inline
    std::ostream  &operator <<(std::ostream& o_, const t_wbl_actions r_) {

        using namespace titan_v3::tools;
        return o_ << eop::to_string( r_, t_wbl_actions_map_fn{} );

    }

    struct t_htkey{
        t_wbl_actions actions_{};
    };

    struct s_item_{
        t_ht_flags flags_{};
        std::unordered_map<ssize_t,t_htkey> policies_{};
    };

    namespace domains_tools{

        namespace parser{

            template< typename E>
            inline 
            bool fqdn_ending_martcher(  const std::string & fqdn_,
                                        const ssize_t policy_,
                                        t_wbl_actions & act_,
                                        E check_policy_             ) {

                constexpr auto MIN_DNS_DOMAIN_SZ_ = static_cast<std::string::size_type>(MIN_DNS_DOMAIN_SZ);

                constexpr auto RFC1035_MAX_ = static_cast<std::string::size_type>(RFC1035_MAX);

                if (    WITHIN_(    MIN_DNS_DOMAIN_SZ_,
                                    RFC1035_MAX_,
                                    fqdn_.size()         )  &&

                        fqdn_[0]!='.'                           ){ 

                        const char * domain{ fqdn_.c_str() };

                        const char * org{ domain };

                        size_t dmsz{ fqdn_.size() };

                        int  lbl_cnt_{};

                        while ( domain ) {

                            for ( const auto label_no : { 1,1,1,1 } ) {


                                act_ = check_policy_( domain, dmsz, policy_ );

                                if ( t_wbl_actions::wba_none != act_ ){

                                    return true;
                                }

                                lbl_cnt_ += label_no;

                                if ( RFC1035_MAX_LABELS_LIMIT < lbl_cnt_ ){

                                    throw tools::errors::domain_parser_too_many_lbls_error();

                                }

                                ptrdiff_t tmp_{};

                                const bool zero_tmp{    ( domain = ::strnstr(   domain + 1,
                                                                                ".",
                                                                                dmsz        ) ) &&

                                                        !::ptr_diff(    domain,
                                                                        org,
                                                                        &tmp_       )               };

                                if ( zero_tmp ){

                                    tmp_ = {};
                                }

                                constexpr auto LABEL_LIMIT_ = static_cast<decltype(tmp_)>(RFC1035_LABEL_LIMIT);
                                if ( domain &&

                                     ( !tmp_ ||

                                     !UWITHIN_( LABEL_LIMIT_, ( tmp_ - 1 ) ) )  ){

                                    throw tools::errors::domain_parser_invalid_lbl_lenght_error(tmp_,domain);

                                }

                                if ( domain ){

                                    org = domain;

                                    dmsz -= static_cast<size_t>(tmp_);

                                } else break;

                            }

                        }/* loop */

                        return false;

                    }

                    throw tools::errors::domain_parser_invalid_length(fqdn_.size());

            }

         } /* parser ns */
    
    } /* domains_ht */

}

#endif /* TTN_DOMAINS_HT_TOOLS_HXX */

/* vim: set ts=4 sw=4 et : */

