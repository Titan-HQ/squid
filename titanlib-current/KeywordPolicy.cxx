/*
 * $Id: KeywordPolicy.c 13852 2016-10-20 15:09:42Z dawidw $
 *
 * Copyright (c) 2005-2018, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 *
 * The software contained herein is proprietary to and embodies the
 * confidential technology of Copperfasten Technologies, Teoranta.
 * Possession, use, duplication or dissemination of the software and
 * media is authorized only pursuant to a valid written license from
 * Copperfasten Technologies, Teoranta.
 *
 */

#include "KeywordPolicy.hxx"
#include "db_pg.hxx"
#include "TitaxConf.h"
#include "sqls.h"
#include <cstdlib>
#include <cstring>
#include "ttn_eops.hxx"
#include "ttn_iterators.hxx"

namespace titan_v3{

    std::unique_ptr<KeywordPolicies> KeywordPolicies::kp_instance;
    std::once_flag KeywordPolicies::once_flag;

    //---------------------------------------------------------------------
    KeywordPolicyData::KeywordPolicyData(   const bool path_flag,
                                            const bool matchStart,
                                            const char* const __restrict keyword ) 
                                                : urlpath_flag{ path_flag },
                                                  matchUrlStart{ matchStart }
    {

        // Keyword policy supports space separated list of keywords
       std::istringstream t(keyword);
       std::string s;
       while (std::getline(t, s, ' ')) {
           list.push_back(s);
       }
    }

    bool KeywordPolicyData::check_keyword(const char* host, const char* url_path) const
    {
        const auto pathNotEmpty = ( url_path && *url_path );

        size_t match_cnt{};

        for ( const auto& keyword : list ) {

            if ( !matchUrlStart ) {

               if (   (   strcasestr( host, keyword.c_str() )   ||

                          (   pathNotEmpty  &&

                              urlpath_flag  &&

                              strcasestr( url_path, keyword.c_str() ) ) ) ) {

                        ++match_cnt;
                }

                continue;
            }

            const auto keywordLength = keyword.length();
            if ( keywordLength > 0) {

                const auto hostLength = strlen( host );

                if ( keywordLength <= hostLength && !strncasecmp( keyword.c_str(), host, keywordLength ) ) {

                    /* Keyword found in host */
                    ++match_cnt;

                    continue;
                }

                if (    pathNotEmpty                                        &&

                        keywordLength <= hostLength + strlen( url_path )    &&

                        !strncasecmp( keyword.c_str(), host, hostLength )   &&

                        !strncasecmp(   keyword.c_str() + hostLength,
                                        url_path,
                                        keywordLength - hostLength )        ) {

                    /* Keyword found in the full URL (host + path) */
                    ++match_cnt;

                    continue;
                }

            } /* keyword if */

       } /* list loop */

       if ( match_cnt == list.size() ) {

           /* A keyword item can contain multiple keywords.
               When all keywords are found then a match has occurred */
           return true;
       }

       return false;

    } /* top if */



    //---------------------------------------------------------------------
    static bool keyword_policies_is_on_list(    const PolicyList& list,
                                                const char* const __restrict host,
                                                const char* const __restrict url_path   ) noexcept
    {
        if ( host && *host ) {

            for ( const auto & item : list ) {

                if (item.check_keyword(host, url_path)) {
                   return true;
                }
            }
        }

        return false;
    }


    static void load_keywords(  PGresult* const __restrict rset,
                                PolicyList& list                    ) noexcept
    {

        list.clear();

        const auto sz = txpq_row_count( rset );

        for ( size_t i = 0; i < sz; i++ ) {

            const bool flag = txpq_cv_bool( rset, i, 0 );

            const bool matchStart = txpq_cv_bool( rset, i, 1 );

            if ( char * const keyword = txpq_cv_str( rset, i, 2 ) ) {

                // URL decode the keyword
                size_t decoded_size{};

                url_decode_ex( keyword, strlen( keyword ), &decoded_size, false );

                /* size_t is an unsigned int */
                if ( decoded_size ) {

                    list.emplace_back( flag, matchStart, keyword );
                }
            }
        }
    }

    bool KeywordPolicies::load_bypass_auth_keywords( PGconn* const __restrict db ) noexcept
    {

        if ( db ){

            using namespace titan_v3::tools;

            pgresult_uniq_t rset{ pq_get_rset(  db,
                                                TITAXLIB_QS_T_KEYWORD_POLICIES_AUTH ) };

            if ( rset ){

                load_keywords( rset.get(), auth_list );

                return true;
            }
        }

        return false;
    }

    bool KeywordPolicies::load_bypass_filter_keywords( PGconn* const __restrict  db ) noexcept
    {

        if ( db ){

            using namespace titan_v3::tools;

            pgresult_uniq_t rset{ pq_get_rset(  db,
                                                TITAXLIB_QS_T_KEYWORD_POLICIES_FILTER   ) };

            if ( rset ) {

                load_keywords( rset.get(), filter_list );

                return true;
            }
        }

        return false;
     }

    bool KeywordPolicies::load_admin_block_keywords( PGconn* const __restrict db ) noexcept
    {

        if ( db ){

            using namespace titan_v3::tools;

            pgresult_uniq_t rset{ pq_get_rset(  db,
                                                TITAXLIB_QS_T_KEYWORD_POLICIES_BLOCK    ) };

            if (rset) {

                load_keywords( rset.get(), block_list );

                return true;
            }
        }

        return false;
    }

    bool KeywordPolicies::keyword_policies_reload( PGconn* const __restrict db ) noexcept
    {

        std::lock_guard<std::mutex> id_lock{ kp_policies_mtx };

        if (    !load_bypass_auth_keywords(db)      ||

                !load_bypass_filter_keywords(db)    ||

                !load_admin_block_keywords(db)          ) {

            return false;
        }

        return true;
    }


    /**
     *
     * @return true=all kpolicies are empty (or error) | false if at least one is not empty
     */
    static bool keyword_policies_are_empty( PolicyList & auth_list,
                                            PolicyList & filter_list,
                                            PolicyList & block_list     ) noexcept
    {

        return (    !auth_list.size()   &&

                    !filter_list.size() &&

                    !block_list.size()      );
    }


    bool KeywordPolicies::keywords_find( const char* const __restrict host,
                                         const char* const __restrict url_path,
                                            t_wbl_actions& actions                  ) noexcept
    {
        std::lock_guard<std::mutex> id_lock{kp_policies_mtx};

        if ( !keyword_policies_are_empty( auth_list, filter_list, block_list ) ) {

            using namespace titan_v3::tools::eop;

            t_wbl_actions result{t_wbl_actions::wba_none};

            if ( keyword_policies_is_on_list( auth_list, host, url_path ) ) {

                result |= t_wbl_actions::wba_bypassauth;
            } 

            if ( keyword_policies_is_on_list( filter_list, host, url_path ) ) {

                result |= t_wbl_actions::wba_bypassfilters;
            }

            if (  keyword_policies_is_on_list( block_list, host, url_path ) ) {

                result |= t_wbl_actions::wba_block;
            }

            actions = static_cast<t_wbl_actions>(result);
            return true;
        }

        actions = t_wbl_actions::wba_none;
        return false;
    }

} // namespace titan_v3


bool titax_load_keyword_policies_( PGconn* const __restrict db )
{

    return titan_v3::KeywordPolicies::get_instance().keyword_policies_reload( db );
}

/* vim: set ts=4 sw=4 et : */

