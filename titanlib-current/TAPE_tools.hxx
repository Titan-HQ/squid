/**
 * $Id$
 */

#ifndef TAPE_TOOLS_HXX
#define TAPE_TOOLS_HXX

#include "ttn_tools.hxx"
#include "TAPE.h"
#include "TAPE_types.hxx"

namespace titan_v3
{
    namespace http_tools
    {
        using scan_for_hcookies_ret = std::tuple<bool,std::string, std::string >;

        TX_CPP_INLINE_LIB
        scan_for_hcookies_ret scan_for_hcookies(    IHRequest & rq_, 
                                                    std::string delimiter_ = DEFAULT_COOKIE_DELIM    )
        {
            if ( rq_.headers_has( HDR_COOKIE ) ) {

                /* https://tools.ietf.org/html/rfc6265#section-4.2 */

                std::string hcookies_ = rq_.headers_get( HDR_COOKIE );

                if ( const size_t cstr_sz_ = hcookies_.size() ) {

                    const char * const sc_{ hcookies_.c_str() };

                    //get the existing cookie delimiter (if any)
                    ssize_t c_off_ = ::ttn_strncspn( sc_, cstr_sz_, " ", 1 );

                    if ( c_off_ > 0 ) {

                        switch ( sc_[ --c_off_ ] ) {

                            case '&':
                            case ',':
                            case ':':{

                                delimiter_ = sc_[c_off_];

                                delimiter_ += ' ';
                            } break;

                            default:break;
                        }

                    } //else default;

                    return std::make_tuple( true, hcookies_, delimiter_ );
                }
            }

            return std::make_tuple( false, "", delimiter_ );
        }

        TX_CPP_INLINE_LIB 
        bool header_update( IHRequest & rq_,
                            const t_http_hdr_types hdr_type_,
                            const std::string & str_,
                            const bool allow_empty = false  )
        {
            if ( str_.size() || allow_empty ) {

                if ( !rq_.headers_has( hdr_type_ ) ) {

                    rq_.headers_put( hdr_type_, str_ );

                    return true;
                }

                rq_.headers_del( hdr_type_ );

                rq_.headers_put( hdr_type_, str_ );

                return true;
            }

            return false;
        }

        TX_CPP_INLINE_LIB
        bool update_qstring(    std::string & urlpath_,
                                const std::string & key_,
                                const std::string & val_ = {} ,
                                size_t qpos_ = std::string::npos    )
        {
            const size_t usz_{ urlpath_.length() };

            const size_t vsz_{ val_.size() };

            size_t sz_{ key_.size() };

            if ( sz_ ) {

                sz_ += vsz_ + 2;

                if (    std::string::npos == qpos_                              && 

                        std::string::npos == ( qpos_ = urlpath_.find( "?" ) )       ) {

                    urlpath_.reserve( usz_ + sz_ );

                    urlpath_ += '?';

                    urlpath_ += key_;

                    if ( vsz_ ) {

                        if ( key_[ key_.length() - 1 ] != '=' ) {

                            urlpath_ += '=';
                        }

                        urlpath_ += val_;
                    }

                    return true;
                }

                if ( update_value( urlpath_, "&", key_, val_ ) ) {

                    return true;
                }

                if (  qpos_ <= usz_ -1 ) {

                    urlpath_.reserve( usz_ + sz_ + 1 );

                    if (    qpos_ < usz_ -1                &&

                            urlpath_[ usz_ - 1 ] != '&'         ) {

                        urlpath_ += '&';
                    }

                    urlpath_ += key_;

                    if ( vsz_ ) {

                        if ( key_[ key_.length() - 1 ] != '=' ) {

                            urlpath_ += '=';
                        }

                        urlpath_ += val_;
                    }

                    return true;
                }
            }

            return false;
        }

        TX_CPP_INLINE_LIB
        bool cookie_update( IHRequest & rq_,
                            const std::string & key_,
                            const std::string & val_ = {}    )
        {
            if ( size_t sz_ = key_.size() ) { 

                const size_t vsz_{ val_.size() };

                sz_ += vsz_ + 1;

                std::string cookie_delim_{};

                std::string cstr_{};

                bool state{};

                std::tie( state, cstr_, cookie_delim_ ) = scan_for_hcookies( rq_ );

                if ( state ) {

                    if ( update_value(  cstr_,
                                        cookie_delim_,
                                        key_,
                                        val_            )   ) {

                        return header_update( rq_, HDR_COOKIE,cstr_ );
                    }

                    cstr_.reserve(  sz_                     +

                                    cstr_.size()            + 

                                    cookie_delim_.size()        );

                    cstr_ += cookie_delim_;

                    cstr_ += key_;

                    if ( vsz_ ){

                        if ( key_[ key_.length() - 1 ] != '=' ) {

                            cstr_ += '=';
                        }

                        cstr_ += val_;
                    }

                    return header_update( rq_, HDR_COOKIE,cstr_ );
                }

                cstr_.reserve( sz_ );

                cstr_ = key_ ; //possible move

                if ( vsz_ ){

                    if ( key_[ key_.length() - 1 ] != '=' ) {

                        cstr_ += '=';
                    }

                    cstr_ += val_;
                }

                rq_.headers_put( HDR_COOKIE, cstr_ );

                return true;
            }

            return false;
        }

        TX_CPP_INLINE_LIB
        bool youtube_update_cookie( IHRequest & rq_ )
        {
            using namespace safe_search;

            std::string cookie_delim_{};

            std::string cstr_{};

            bool state{};

            std::tie( state, cstr_, cookie_delim_ ) = scan_for_hcookies( rq_ );

            if (    state                   && 

                    cookie_delim_.size()        ) {

                auto ytPREF_ = get_value(   cstr_,
                                            cookie_delim_,
                                            youtube::key    );

                if ( ytPREF_.second ){

                        if (    ! ytPREF_.first.size()                  ||

                                ! update_value( ytPREF_.first,
                                                "&",
                                                youtube::sub_key,
                                                youtube::sub_val    )       ) {

                            ytPREF_.first = youtube::sub_key_val;
                        }

                        if (    update_value(   cstr_,
                                                cookie_delim_,
                                                youtube::key,
                                                ytPREF_.first      )    ) {

                            return header_update(   rq_,
                                                    HDR_COOKIE, 
                                                    cstr_       );
                        }

                        return false;
                }

                return header_update(   rq_,
                                        HDR_COOKIE,
                                        cstr_ + cookie_delim_ + youtube::key_sub_key_val  );
            }

            rq_.headers_put(    HDR_COOKIE,
                                youtube::key_sub_key_val    );

            return true;
        }

        TX_CPP_INLINE_LIB
        bool bing_update_cookie(    IHRequest & rq_,
                                    std::string val_  )
        {
            if ( !val_.empty() ) {

                using namespace safe_search;

                std::string cookie_delim_{};

                std::string cstr_{};

                bool state{};

                std::tie( state, cstr_, cookie_delim_ ) = scan_for_hcookies( rq_ );

                if ( state && 

                     cookie_delim_.size() ) {

                    auto BingSRCHHPGUSR_ = get_value(   cstr_,
                                                        cookie_delim_,
                                                        bing::key         );

                    if ( BingSRCHHPGUSR_.second ){

                        if (    ! BingSRCHHPGUSR_.first.size()              ||

                                ! update_value( BingSRCHHPGUSR_.first,
                                                "&",
                                                bing::sub_key,
                                                val_                     )      ) {

                                BingSRCHHPGUSR_.first = bing::sub_key;

                                BingSRCHHPGUSR_.first += "=" + val_;
                        }

                        if (    update_value(   cstr_,
                                                cookie_delim_,
                                                bing::key,
                                                BingSRCHHPGUSR_.first    )    ) {

                               return header_update(    rq_,
                                                        HDR_COOKIE,
                                                        cstr_           );
                        }

                        return false;
                    }

                    return header_update(   rq_,

                                            HDR_COOKIE, 

                                            cstr_               +

                                            cookie_delim_       +

                                            bing::key_sub_key   +

                                            val_                    );
                }

                rq_.headers_put(    HDR_COOKIE,
                                    bing::key_sub_key + val_  );
                return true;
            }

            return false;
        }

        TX_CPP_INLINE_LIB
        bool google_enforce_safe_search(    IHRequest & rq_,
                                            const std::string & host,
                                            std::string & path          )
        {
            using namespace safe_search;

            using namespace tools ;

            if (    ( host.size() > ( sizeof( google::signature ) -1 ) )        &&

                    ( host.find( google::signature ) != std::string::npos )     &&

                    ( host.find( google::video ) == std::string::npos )         &&

                    ( host.find( google::trends ) == std::string::npos )            ) {

                    if ( update_qstring( path, google::key, google::val ) ){

                        rq_.set_path( path );

                        return true;
                    }

                    throw errors::safe_search_error("google");
            }

            return false;
        }

        TX_CPP_INLINE_LIB
        bool youtube_enforce_safe_search(   IHRequest & rq_,
                                            const std::string & host,
                                            const uint64_t sse_grp_moderate )
        {
            using namespace safe_search;

            using namespace tools;

            if (    !host.empty()                                                   &&

                    youtube::signatures.find( host ) != youtube::signatures.end()       ) {

                if (    header_update(  rq_,
                                        HDR_YOUTUBE_RESTRICT,
                                        youtube::header_values[ SS_INDEX( SSE_YT ) ] )  &&

                        (   std::string::npos != host.find( youtube::signature )        ||

                            youtube_update_cookie( rq_ )                            )       ) {

                        return true;
                }

                throw errors::safe_search_error("youtube");
            }

            return false;
        }

        TX_CPP_INLINE_LIB
        bool yahoo_enforce_safe_search( IHRequest & rq_,
                                        const std::string & host,
                                        std::string & path,
                                        const uint64_t sse_grp_moderate    )
        {
            using namespace safe_search;

            using namespace tools;

            if (    ( host.length() > ( sizeof( yahoo::signature ) -1 ) )     &&

                    ( host.find( yahoo::signature ) != std::string::npos )        ) {


                if (    cookie_update(  rq_,
                                        yahoo::key,
                                        yahoo::val[ SS_INDEX( SSE_YAHOO ) ] )   &&

                        update_qstring( path,
                                        yahoo::key,
                                        yahoo::val[ SS_INDEX( SSE_YAHOO ) ] )       ) {

                    rq_.set_path( path );

                    return true;
                }

                throw errors::safe_search_error("yahoo");
            }

            return false;
        }

        TX_CPP_INLINE_LIB
        bool bing_enforce_safe_search(  IHRequest & rq_,
                                        const std::string & host,
                                        const uint64_t sse_grp_moderate    )
        {
            using namespace safe_search;

            using namespace tools;

            if (    ( host.length() > ( sizeof( bing::signature ) -1 ) )    &&

                    ( host.find( bing::signature ) != std::string::npos )       ) {

                    if ( bing_update_cookie(    rq_,
                                                bing::sub_val[ SS_INDEX( SSE_BING ) ]    )   ) {
                        return true;
                    }

                    throw errors::safe_search_error("bing");
            }

            return false;
        }


        TX_CPP_INLINE_LIB
        void modify_safe_search_url(    IHRequest & rq_,
                                        const uint64_t sse_grp_onoff,
                                        const uint64_t sse_grp_moderate    )
        {
        //------------------------------------------------------------------------------
            /*****************************************************
            * Function:   modify_safe_search_url
            * Parameters: unsigned long onoff    - onoff setting
            *            unsigned long moderate - moderate setting
            * Modifies: request
            *****************************************************/
            std::string ss_host=rq_.get_host();

            std::string ss_urlpath=rq_.get_path();

            if (    ( sse_grp_onoff & SSE_GOOGLE )                          &&

                    google_enforce_safe_search(    rq_, 
                                                ss_host,
                                                ss_urlpath    )                 ) {
                    return;
            }

            if (    ( sse_grp_onoff & SSE_YT )                              &&

                    youtube_enforce_safe_search(    rq_,
                                                    ss_host,
                                                    sse_grp_moderate    )       ) {
                    return;
            }

            if (    ( sse_grp_onoff & SSE_YAHOO )                           &&

                    yahoo_enforce_safe_search(     rq_,
                                                ss_host,
                                                ss_urlpath,
                                                sse_grp_moderate    )           ) {
                    return;
            }

            if (    ( sse_grp_onoff & SSE_BING )                            &&

                    bing_enforce_safe_search(   rq_,
                                                ss_host,
                                                sse_grp_moderate    )           ) {
                    return;
            }
        }

        TX_CPP_INLINE_LIB
        void add_microsoft_signatures(cfg::TCFGInfo & cfg )
        {
            using namespace restrict_access;
            using namespace tools;

            microsoft::signatures.clear();
            if (!cfg.restrict_access_domains_str.empty()) {
               std::istringstream t(cfg.restrict_access_domains_str);
               std::string s;
               while (std::getline(t, s, ',')) {
                  microsoft::signatures.insert(trim(s));
               }
            }
            cfg.reload_access_domains = false;
        }


        TX_CPP_INLINE_LIB
        bool microsoft_enforce_restrict_access( IHRequest & rq_,
                                                const std::string & host,
                                                cfg::TCFGInfo & cfg )
        {
            using namespace restrict_access;

            using namespace tools;

            if (cfg.reload_access_domains) {
               add_microsoft_signatures(cfg);
            }

            if ( microsoft::signatures.find( host ) != microsoft::signatures.end() ) {

                /* found & add headers */
                if (    header_update(  rq_,
                                        HDR_RESTRICT_ACCESS_CONTEXT,
                                        cfg.restrict_access_context_str )   ) {

                    if (    header_update(  rq_,
                                            HDR_RESTRICT_ACCESS_TO_TENANTS,
                                            /* could be empty ?*/
                                            cfg.restrict_access_to_tenants_str, 
                                            true                                )   ) {
                        /* ok */
                        return true;
                    }

                    rq_.headers_del( HDR_RESTRICT_ACCESS_CONTEXT );
                }

                /* error */
                return false;
            }

            /* not found but ok */
            return true;
        }
    } /* http_tools ns */

} /* titan_v3 ns */

#endif /* TAPE_TOOLS_HXX */

/* vim: set ts=4 sw=4 et : */

