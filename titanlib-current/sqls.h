/*
 * $Id$
 *
 * Copyright (c) 2005-2019, Copperfasten Technologies, Teoranta.  All rights
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
///PLEASE PLACE ALL YOUR SQL HERE

#define  TITAXLIB_QS_T_GROUPS                            "select id, special, disabled, name, policyid from groups where not disabled::bool order by id"

#define  TITAXLIB_QS_T_POLICIES                          "select id, special, name, catssystemwork, catssystemplay, catssystemnotify, catscustomwork"\
                                                         ", catscustomplay, catscustomnotify, notifyemail from policies order by id"

#define  TITAXLIB_QS_T_POLICYNONWORKINGHOURS             "select policyid, daysofweek, stime, etime from policynonworkinghours"

#define TITAXLIB_QS_T_POLICYFLAGS                        "select policyid, filtering, onlyallowspecified, blockall, blockaudio, blockvideo, blockexec"\
                                                         ", blockimage, blockdoc, blockarchive, blockuserdef, logonlygroup, urlfilter, urlthreshold, pagefilter"\
                                                         ", pagethreshold, sizefilter, sizethreshold, blockipaddrurls, dontblockonkeywords, blockotherworkhours"\
                                                         ", blockothernonworkhours, blockotherHTTPSworkhours, blockotherHTTPSnonworkhours"\
                                                         ", blockHTTPSworkhours, blockHTTPSnonworkhours, sinbin, safesearch, mbthreshold"\
                                                         ", show_bypass_tokens_message from policyflags order by policyid"

#define TITAXLIB_QS_T_POLICYNOTIFICATIONS                "select policyid, notificationid from policynotifications order by policyid"

#define TITAXLIB_QS_T_POLICYSAFESEARCH                   "select policyid, searchengine, option from policysafesearch"

#define  TITAXLIB_QS_T_UPDATE_TIMES                      "select lower(tname), mtime from update_times"

#define  TITAXLIB_QS_T_FILTERING                         "select avscan, avengine, avlimit, audioext, videoext, exeext, imgext, docext, archext, udext"\
                                                         ", leastrestrict, disable_filteronreq, disable_filteronresp from filtering"

#define  TITAXLIB_QS_T_AUTHPOLICY                        "select enable_auth, allow_ip, allow_ldap,allow_kshield, enable_ntlm, allow_wada, ip_session, ip_session_ttl, terminal_server_ip"\
                                                         ", intercept_login from authpolicy"

#define  TITAXLIB_QS_T_NETWORKING                        "select smtp_server, smtp_backoff, hostname, domain, int_ip, transparentproxy, cnames, int_ip6 from networking"

#define  TITAXLIB_QS_T_CACHE                             "select httpport from cache"

#define  TITAXLIB_QS_T_URLCATEGORIES_1                   "select categoryid, name from urlcategories order by categoryid"

#define  TITAXLIB_QS_T_URLCATEGORIES_2                   "select categoryid - 100, name from urlcategories where categoryid >= 100 order by categoryid"

#define  TITAXLIB_QS_T_KEYWORDS                          "select keyword, score from keywords"

#define  TITAXLIB_QS_T_REDIRECTIONS                      "select source, destination from redirections"

#define  TITAXLIB_QS_T_KEYWORD_POLICIES_AUTH             "select urlpath_flag, match_start, keyword from keyword_policies where auth_flag = 'TRUE'"

#define  TITAXLIB_QS_T_KEYWORD_POLICIES_FILTER           "select urlpath_flag, match_start, keyword from keyword_policies where filter_flag = 'TRUE'"

#define  TITAXLIB_QS_T_KEYWORD_POLICIES_BLOCK            "select urlpath_flag, match_start, keyword from keyword_policies where block_flag = 'TRUE'"

#define  TITAXLIB_QS_V_USERS                             "select * from v_users order by id asc, parent_id desc"

#define  TITAXLIB_QS_F_USERS_LIST_TYPE                   "select users_list_type()"

#define TITAXLIB_QS_V_DP_FLAGS                           "select * from v_domain_policies_flags;"

#define TITAXLIB_QS_T_USERS_BANDWIDTH                    "select * from usersbandwidth"

#define  TITAXLIB_QS_T_USERGROUPS_DISPLAY                "select usergroups.userid, usergroups.groupid from usergroups join groups on usergroups.groupid=groups.id where not groups.disabled::bool order by userid"

#define  TITAXLIB_QS_T_USERGROUPS_EFFECTIVE              "select distinct on (usergroups.userid, groups.policyid) usergroups.userid,  usergroups.groupid,  groups.policyid from usergroups join groups on usergroups.groupid=groups.id where not groups.disabled::bool order by usergroups.userid,  groups.policyid,  usergroups.groupid"

#define  TITAXLIB_QS_V_LOCATIONS                         "select _usr_id_, loc_iptype, loc_ip, loc_name_st, loc_name, loc_tag, terminal_server, loc_policy_id from v_locations"

#define  TITAXLIB_QT_T_USER_BW                           "delete from usersbandwidth"

#define  TITAXLIB_QI_T_USER_BW                           "select update_users_bw(\'%s\', %s, %s)"

#define  TITAXLIB_QS_V_ACTIVE_USED_BYPASS_TOKENS_SHORT   "select user_id, token, token_md5 from v_active_used_bypass_tokens;"

#define  TITAXLIB_QS_V_USERS_CKEY_COUNTS                 "select id, blockpage_tokens_count from v_users;"

#define  TITAXLIB_QS_PING                                "select 1"

#define  TITAXLIB_QS_T_LDAPSERVERS_DOMAINS               "select domain from ldapservers where enabled='TRUE' and domain is not null;"

#define  TITAXLIB_QS_V_TOP_USERS                         "select id, name, fullname, domain, md5, " \
                                                         "blockpage_tokens_count, parent_id, lic_no, uuid_str, default_flag " \
                                                         "from v_users where parent_id is null order by id asc"

#define  TITAXLIB_QS_T_TOP_POLICIES                      "select user_id, group_id, policy_id, inherited from effective_policies where user_id "


#ifdef TTN_ATESTS
   
   #define TNPQ_TEST_CONSTR         "TNPQ_TESTS"
   // single row one col
   #define TNPQ_TEST_SQL1           "select count(*)"
   // single multi row two cols
   #define TNPQ_TEST_SQL2           "select name, age"
   // single no rows
   #define TNPQ_TEST_SQL3           "select none"
   // select with bind params
   #define TNPQ_TEST_SQL4           "select * from Xtable where arg1=? and arg2=? or arg3=?;"
   #define TNPQ_TEST_SQL4_PARSED    "select * from Xtable where arg1=$1 and arg2=$2 or arg3=$3;"

   #define TNPQ_TEST_SQL5           "select * from Ytable where param1=? and param2=?"
   #define TNPQ_TEST_SQL5_PARSED    "select * from Ytable where param1=$1 and param2=$2"

   #define TITANLIB_TEST_QS_ALL_EFFECTIVE_POLCIES  "select user_id, group_id, policy_id, inherited from effective_policies"

   #define TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID  "select user_id, group_id, policy_id, inherited from effective_policies where user_id = "

   #define TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS "select user_id, group_id, policy_id, inherited from effective_policies where user_id in ("

   #define TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID_2  "2"

   #define TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID_4  "4"

   #define TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_3 "1,3)" 

   #define TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_4 "1,4)"

   #define TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_5 "1,5)"

   #define TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_3_4 "1,3,4)" 

#endif

