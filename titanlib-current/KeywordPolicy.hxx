/*
 * $Id: KeywordPolicy.h 13852 2016-10-20 15:09:42Z dawidw $
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
#pragma once

#include <mutex>
#include <vector>
#include "global.h"
#include "edgelib.h"
#include "edgepq.h"
#include "ttn_domains_ht.hxx"

namespace titan_v3
{
    typedef std::vector<std::string> KeywordList;

    struct KeywordPolicyData
    {
        bool              urlpath_flag{};
        bool              matchUrlStart{};
        KeywordList       list;

        KeywordPolicyData( const bool, const bool, const char* const );

        KeywordPolicyData( const KeywordPolicyData& other )
                                                :   urlpath_flag{ other.urlpath_flag },
                                                    matchUrlStart{ other.matchUrlStart },
                                                    list{ other.list } 
        {

        }

        KeywordPolicyData( KeywordPolicyData&& other ) 
                                                :   urlpath_flag{ std::move( other.urlpath_flag ) },
                                                    matchUrlStart{ std::move( other.matchUrlStart ) },
                                                    list{ std::move( other.list ) } 
        {

        }

        KeywordPolicyData& operator = ( const KeywordPolicyData& ) = delete;

        bool check_keyword(const char* host, const char* url_path) const;

        ~KeywordPolicyData() 
        {
            list.clear();
        }
   };

    typedef std::vector<KeywordPolicyData> PolicyList;

    class KeywordPolicies
    {
        public:
            static KeywordPolicies& get_instance() noexcept 
            {

                std::call_once( KeywordPolicies::once_flag, []{ kp_instance.reset( new KeywordPolicies() ); } );

                return *(kp_instance.get());
            }

            bool keyword_policies_reload( PGconn* const ) noexcept;

            /**
             * @name keywords_find
             * @abstract check if host and path match any known keyword ( global policy )
             * @param host[in]
             * @param path[in]
             * @pram action[out]
             * @retunr true/false
             */
            bool keywords_find( const char* const, const char* const, t_wbl_actions& ) noexcept;

            ~KeywordPolicies()
            {

                auth_list.clear();

                filter_list.clear();

                block_list.clear();

            }

        protected:

            static std::unique_ptr<KeywordPolicies>   kp_instance;
            static std::once_flag                     once_flag;
            std::mutex                                kp_policies_mtx;
            PolicyList                                auth_list;
            PolicyList                                filter_list;
            PolicyList                                block_list;

            KeywordPolicies() = default;

            bool load_bypass_auth_keywords( PGconn* const ) noexcept;
            bool load_bypass_filter_keywords( PGconn* const ) noexcept;
            bool load_admin_block_keywords( PGconn* const ) noexcept;

    };

} /* ns */

extern "C" bool titax_load_keyword_policies_(PGconn* const);

/* vim: set ts=4 sw=4 et : */

