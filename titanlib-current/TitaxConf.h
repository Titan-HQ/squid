/*
 * $Id$
 *
 * Copyright (c) 2005-2009, Copperfasten Technologies, Teoranta.  All rights
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
#ifndef TITAN_CONF_H
#define TITAN_CONF_H

#include <pthread.h>
#include "global.h"


#include "edgelib.h"
#include "md5.h"

#ifdef __cplusplus
extern "C" {
#endif
   
   
#ifndef REQUEST_BYPASS_URL_MD5_TOKEN
   #define REQUEST_BYPASS_URL_MD5_TOKEN                        "!TXByPaSsNoWXT!"
#endif
#ifndef REQUEST_BYPASS_URL_MD5_TOKEN_SIZE
   #define REQUEST_BYPASS_URL_MD5_TOKEN_SIZE                   15
#endif
//TODO: randomise it to allow the daisy chaining
#ifndef REQUEST_SESSION_COOKIE
   #define REQUEST_SESSION_COOKIE                              "da1b132741450d54bf7dcc092e06cb70"
#endif

#ifndef REQUEST_SESSION_COOKIE_SZ
   #define REQUEST_SESSION_COOKIE_SZ                           (sizeof(REQUEST_SESSION_COOKIE)-1)
#endif

#ifndef TITAX_UNLIMITED_USER
   #define TITAX_UNLIMITED_USER                                UNLIMITED_UNIQ_IP
   //value 99999999 exceeds the max amount of unique ip
#endif

#ifndef MAX_AVLIMIT
   #define MAX_AVLIMIT                                         10240
#endif
#ifndef DEF_AVLIMIT
   #define DEF_AVLIMIT                                         150
#endif
#ifndef TX_CFG_MAX_KV_STR_SZ
   #define TX_CFG_MAX_KV_STR_SZ                                2047
#endif
#ifndef TX_CFG_MAX_PG_CSTR
   #define TX_CFG_MAX_PG_CSTR                                  (TX_CFG_MAX_KV_STR_SZ >> 1)
#endif
/* backend block page server (usually ipv4) */
#ifndef BP_DEFAULT_PATH
   #define BP_DEFAULT_PATH                                     "/txbp/"
#endif
#ifndef BP_DEFAULT_PATH_SZ
   #define BP_DEFAULT_PATH_SZ                                  (sizeof(BP_DEFAULT_PATH)-1)
#endif
#ifndef BP_DEFAULT_PORT
   #define BP_DEFAULT_PORT                                     80
#endif
#ifndef BP_DEFAULT_IPv4
   #define BP_DEFAULT_IPv4                                      "127.0.0.1"
#endif
#ifndef BP_DEFAULT_IPv6
   #define BP_DEFAULT_IPv6                                      "::1"
#endif
/* backend proxy config (usually ipv4) */
#ifndef PROXY_DEFAULT_IPv4
   #define PROXY_DEFAULT_IPv4                                  "127.0.0.1"
#endif
#ifndef PROXY_DEFAULT_IPv6
   #define PROXY_DEFAULT_IPv6                                  "::1"
#endif
#ifndef PROXY_DEFAULT_PORT
   #define PROXY_DEFAULT_PORT                                  8881
#endif
#ifndef EXPIRY_DATE_DEFAULT
   #define EXPIRY_DATE_DEFAULT                                 0
#endif
#ifndef MAX_USERS_DEFAULT
   #define MAX_USERS_DEFAULT                                   0
#endif
#ifndef MAX_UNIQ_IPS_DEFAULT
   #define MAX_UNIQ_IPS_DEFAULT                                0
#endif
#ifndef IS_LICENSE_VIOLATED_DEFAULT
   #define IS_LICENSE_VIOLATED_DEFAULT                         0
#endif
#ifndef MAX_USERS_MIN_LIC
   #define MAX_USERS_MIN_LIC                                   50
#endif
#ifndef MAX_UNIQ_IPS_MIN_LIC
   #define MAX_UNIQ_IPS_MIN_LIC                                (MAX_USERS_MIN_LIC<<1)
#endif



////////////////////////////////////////////////////////////////////////////////
#ifndef TTN_CF_FILE
   #define TTN_CF_FILE                                         "/blocker/conf/proxy.cfg"
#endif

//LICENCE CACHE
#ifndef TTN_CF_LICENSE_CACHE
   #define TTN_CF_LICENSE_CACHE                                "lcache"
#endif
#ifndef TTN_CF_LICENSE_CACHE_DEFAULT
   #define TTN_CF_LICENSE_CACHE_DEFAULT                        "/lic.cache"
#endif
#ifndef TTN_CF_LICENSE_CACHE_FNAME_MAX_SZ
   #define TTN_CF_LICENSE_CACHE_FNAME_MAX_SZ                   1023
#endif
   
//FROM AUTHPOLICY.
#ifndef TTN_CF_AUTH_ENABLED
   #define TTN_CF_AUTH_ENABLED                                 "auth_on"
#endif
#ifndef TTN_CF_AUTH_ALLOW_IP
   #define TTN_CF_AUTH_ALLOW_IP                                "auth_ip"
#endif
#ifndef TTN_CF_AUTH_ALLOW_LDAP
   #define TTN_CF_AUTH_ALLOW_LDAP                              "auth_ldap"
#endif   
#ifndef TTN_CF_AUTH_ALLOW_KSHIELD
   #define TTN_CF_AUTH_ALLOW_KSHIELD                           "auth_ks"
#endif
#ifndef TTN_CF_AUTH_ALLOW_NTLM
   #define TTN_CF_AUTH_ALLOW_NTLM                              "auth_ntlm"   
#endif   
//AUTH_CACHE_ip_sessions_enabled
#ifndef TTN_CF_AC_IP_SESSION_ENABLED
   #define TTN_CF_AC_IP_SESSION_ENABLED                        "ac_ips_on"
#endif
//AUTH_CACHE_ip_sessions_ttl
#ifndef TTN_CF_AC_IP_SESSION_TTL
   #define TTN_CF_AC_IP_SESSION_TTL                            "ac_ips_ttl"
#endif
//AUTH_CACHE_TIMEOUT_SLIDE
#ifndef TTN_CF_AC_TTL_SLIDE
   #define TTN_CF_AC_TTL_SLIDE                                 "ac_ttl_slide"
#endif
//USE_GROUS_IDS_INTEAD_NAMES
#ifndef TTN_CF_USE_GROUP_IDS
   #define TTN_CF_USE_GROUP_IDS                                "ugrpids"
#endif
//DON't_USE_URLDB
#ifndef TTN_CF_DISABLE_URLDB
   #define TTN_CF_DISABLE_URLDB                                "durldb"
#endif
#ifndef TTN_CF_INTERCEPT_LOGIN
   #define TTN_CF_INTERCEPT_LOGIN                              "intercept_login"
#endif
#ifndef TTN_CF_USE_PORTAL_WITH_PFM
   #define TTN_CF_USE_PORTAL_WITH_PFM                          "use_portal_with_pfm"
#endif
#ifndef TTN_CF_TERMIN_SERVERS_IP_LIST
   #define TTN_CF_TERMIN_SERVERS_IP_LIST                       "ts_ips"
#endif

//FROM NETWORKING.
#ifndef TTN_CF_SMTP_SERVER
   #define TTN_CF_SMTP_SERVER                                  "smtp_server"
#endif
#ifndef TTN_CF_SMTP_BACKOFF
   #define TTN_CF_SMTP_BACKOFF                                 "smtp_backoff"
#endif
#ifndef TTN_CF_TRANSPARENT_PROXY_ENABLED
   #define TTN_CF_TRANSPARENT_PROXY_ENABLED                    "tproxy_on"
#endif
#ifndef TTN_CF_HOSTNAME
   #define TTN_CF_HOSTNAME                                     "hostname"
#endif
#ifndef TTN_CF_DOMAIN
   #define TTN_CF_DOMAIN                                       "domain"
#endif
#ifndef TTN_CF_IP
   /* ipv4 */
   #define TTN_CF_IP                                           "ip"
#endif
#ifndef TTN_CF_IP4
   #define TTN_CF_IP4                                          "ip4"
#endif
#ifndef TTN_CF_IP6
   #define TTN_CF_IP6                                          "ip6"
#endif
#ifndef TTN_CF_CNAME
   #define TTN_CF_CNAME                                        "cname"
#endif
#ifndef TTN_CF_PROXY_PORT
   #define TTN_CF_PROXY_PORT                                   "pport"
#endif

// FROM FILTERING.
#ifndef TTN_CF_AVSCANNER_ENABLED
   #define TTN_CF_AVSCANNER_ENABLED                            "avscan_on"
#endif
#ifndef TTN_CF_AVSCANNER_ENGINE_TYPE
   #define TTN_CF_AVSCANNER_ENGINE_TYPE                        "avs_etype"
#endif
#ifndef TTN_CF_AVSCANNER_MEM_LIMIT
   #define TTN_CF_AVSCANNER_MEM_LIMIT                          "avs_mlimit"
#endif
#ifndef TTN_CF_LEAST_RESTRICTIVE
   #define TTN_CF_LEAST_RESTRICTIVE                            "least_restrictive"
#endif
#ifndef TTN_CF_FILTER_ONREQ_DISABLED
   #define TTN_CF_FILTER_ONREQ_DISABLED                        "frqs_off"
#endif
#ifndef TTN_CF_FILTER_ONRESP_DISABLED
   #define TTN_CF_FILTER_ONRESP_DISABLED                       "frsp_off"
#endif
#ifndef TTN_CF_YSID_MSZ
   #define TTN_CF_YSID_MSZ                                     255   
#endif


//WADA
#ifndef TTN_CF_WCACHE_FILE
   #define TTN_CF_WCACHE_FILE                                  "wcache"
#endif
#ifndef TTN_CF_WCACHE_FILE_MAX_SZ
   #define TTN_CF_WCACHE_FILE_MAX_SZ                           1023
#endif
#ifndef TTN_CF_WCACHE_FILE_DEFAULT
   #define TTN_CF_WCACHE_FILE_DEFAULT                          "/usr/blocker/proxy/var/wada_cache.wad"
#endif
//wada keep keep existing entries
#ifndef TTN_CF_WADA_EXISTING_ENTRIES
   #define TTN_CF_WADA_EXISTING_ENTRIES                        "wkee"
#endif
//wada ignore errors
#ifndef TTN_CF_WADA_IGNORE_ERRORS
   #define TTN_CF_WADA_IGNORE_ERRORS                           "wie"
#endif
//allow WADA | block if not found
#ifndef TTN_CF_WADA_BLOCK_IF_NOT_FOUND
   #define TTN_CF_WADA_BLOCK_IF_NOT_FOUND                      "block_if_not_found"
#endif

//BP
#ifndef TTN_CF_BLOCKPAGE_SERVER_IP
   #define TTN_CF_BLOCKPAGE_SERVER_IP                          "bps_ip"
#endif
#ifndef TTN_CF_BLOCKPAGE_SERVER_PORT
   #define TTN_CF_BLOCKPAGE_SERVER_PORT                        "bps_port"
#endif
#ifndef TTN_CF_BLOCKPAGE_SERVER_QUERY_PATH
   #define TTN_CF_BLOCKPAGE_SERVER_QUERY_PATH                  "bps_qpath"
#endif

//INTERNAL THREADS/SERVICES
#ifndef TTN_CF_USE_INTERNAL_DATA_UPDATER_THREAD    
   #define TTN_CF_USE_INTERNAL_DATA_UPDATER_THREAD             "use_data_upd_th"
#endif
#ifndef TTN_CF_USE_INTERNAL_STAT_UPDATER_THREAD    
   #define TTN_CF_USE_INTERNAL_STAT_UPDATER_THREAD             "use_stat_upd_th"
#endif
#ifndef TTN_CF_USE_INTERNAL_UQIP_REMOVER_THREAD    
   #define TTN_CF_USE_INTERNAL_UQIP_REMOVER_THREAD             "use_uniq_ip_rem_th"
#endif
#ifndef TTN_CF_USE_INTERNAL_LGIN_INTRCPT_THREAD    
   #define TTN_CF_USE_INTERNAL_LGIN_INTRCPT_THREAD             "use_intrcpt_login_th"
#endif

//MISC
#ifndef TTN_CF_LOGGER_LOG_TYPE
   #define TTN_CF_LOGGER_LOG_TYPE                              "log_type"
#endif
#ifndef TTN_CF_LOGGER_LOG_PATH
   #define TTN_CF_LOGGER_LOG_PATH                              "log_path"
#endif
#ifndef TTN_CF_BACKOFF_LIMIT
   #define TTN_CF_BACKOFF_LIMIT                                "tblimit"
#endif
//greedy matching - used comparing file extentions
#ifndef TTN_CF_FILE_EXT_GREEDY_MATCHING
   #define TTN_CF_FILE_EXT_GREEDY_MATCHING                     "fext_gm"
#endif
//max match count - used comparing file extentions
#ifndef TTN_CF_FILE_EXT_MAX_MATCH_COUNT
   #define TTN_CF_FILE_EXT_MAX_MATCH_COUNT                     "fext_mmc"
#endif   
//WTC (ONLY!!) STRIP SOME HEADERS 
#ifndef TTN_CF_WTC_STRIP_SOME_HEADERS
   #define TTN_CF_WTC_STRIP_SOME_HEADERS                       "wtcssh"
#endif
#ifndef TTN_CF_DISABLE_SAFESEARCH
   #define TTN_CF_DISABLE_SAFESEARCH                           "disable_safesearch"
#endif
#ifndef TTN_CF_VERBOSE
   #define TTN_CF_VERBOSE                                      "verbose"
#endif   
//it will turn the verbose flag as well
#ifndef TTN_CF_DEBUG
   #define TTN_CF_DEBUG                                        "debug"
#endif


//DB CON STRINGS
#ifndef TTN_CF_PG_CON_STR_CONFIG_DB
   // If there is an environment variable with this name (case matters), then
   // it's value is used as the config DB connection string.
   #define TTN_CF_PG_CON_STR_CONFIG_DB                         "pgcstr_cdb"
#endif
#ifndef TTN_CF_PG_CON_STR_REPORT_DB
   #define TTN_CF_PG_CON_STR_REPORT_DB                         "pgcstr_rdb"
#endif
////////////////////////////////////////////////////////////////////////////////   

//---------------------------------------------------------------------
#ifndef TX_LOGGER_DAEMON_DEFAULT_CONF_FILE
   #define TX_LOGGER_DAEMON_DEFAULT_CONF_FILE                  "/blocker/conf/logger.cfg"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_BATCH_SIZE_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_BATCH_SIZE_DEF_VAL             1024*2
#endif
#ifndef TX_LOGGER_DAEMON_CFG_BATCH_SIZE
   #define TX_LOGGER_DAEMON_CFG_BATCH_SIZE                     "bsize"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_BATCH_SIZE_SZ
   #define TX_LOGGER_DAEMON_CFG_BATCH_SIZE_SZ                  (sizeof(TX_LOGGER_DAEMON_CFG_BATCH_SIZE)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD_DEF_VAL         8
#endif
#ifndef TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD
   #define TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD                 "btreshold"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD_SZ
   #define TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD_SZ              (sizeof(TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_DELAY_MAX_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_DELAY_MAX_DEF_VAL              64
#endif
#ifndef TX_LOGGER_DAEMON_CFG_DELAY_MAX
   #define TX_LOGGER_DAEMON_CFG_DELAY_MAX                      "delay_max"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_DELAY_MAX_SZ
   #define TX_LOGGER_DAEMON_CFG_DELAY_MAX_SZ                   (sizeof(TX_LOGGER_DAEMON_CFG_DELAY_MAX)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_DELAY_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_DELAY_DEF_VAL                  4
#endif
#ifndef TX_LOGGER_DAEMON_CFG_DELAY
   #define TX_LOGGER_DAEMON_CFG_DELAY                          "delay"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_DELAY_SZ
   #define TX_LOGGER_DAEMON_CFG_DELAY_SZ                       (sizeof(TX_LOGGER_DAEMON_CFG_DELAY)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_PG_CSTR_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_PG_CSTR_DEF_VAL                PQ_CONFDB_CTRAFFIC
#endif   
#ifndef TX_LOGGER_DAEMON_CFG_PG_CSTR
   #define TX_LOGGER_DAEMON_CFG_PG_CSTR                        "pgcstr"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_PG_CSTR_SZ
   #define TX_LOGGER_DAEMON_CFG_PG_CSTR_SZ                     (sizeof(TX_LOGGER_DAEMON_CFG_PG_CSTR)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_DEF_VAL           PQ_CONFDB_CINFO
#endif
#ifndef TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR
   #define TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR                   "info_pgcstr"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_SZ
   #define TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_SZ                (sizeof(TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY_DEF_VAL       0
#endif
#ifndef TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY
   #define TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY               "iflisten_on_any"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY_SZ
   #define TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY_SZ            (sizeof(TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT_DEF_VAL         8884
#endif
#ifndef TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT
   #define TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT                 "iflisten_port"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT_SZ
   #define TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT_SZ              (sizeof(TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_URL_CSZ_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_URL_CSZ_DEF_VAL                100
#endif
#ifndef TX_LOGGER_DAEMON_CFG_URL_CSZ
   #define TX_LOGGER_DAEMON_CFG_URL_CSZ                        "urlcsz"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_URL_CSZ_SZ
   #define TX_LOGGER_DAEMON_CFG_URL_CSZ_SZ                     (sizeof(TX_LOGGER_DAEMON_CFG_URL_CSZ)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_USE_SYSLOG
   #define TX_LOGGER_DAEMON_CFG_USE_SYSLOG                     "use_syslog"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_USE_SYSLOG_SZ
   #define TX_LOGGER_DAEMON_CFG_USE_SYSLOG_SZ                  (sizeof(TX_LOGGER_DAEMON_CFG_USE_SYSLOG)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_USE_SYSLOG_DEV_VAL
   #define TX_LOGGER_DAEMON_CFG_USE_SYSLOG_DEV_VAL             1
#endif
#ifndef TX_LOGGER_DAEMON_CFG_SYSLOG_FACILITY
   #define TX_LOGGER_DAEMON_CFG_SYSLOG_FACILITY                "syslog_facility"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_SYSLOG_FACILITY_SZ
   #define TX_LOGGER_DAEMON_CFG_SYSLOG_FACILITY_SZ             (sizeof(TX_LOGGER_DAEMON_CFG_SYSLOG_FACILITY)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_DEFAULT_SYSLOG_FACILITY
   #define TX_LOGGER_DAEMON_CFG_DEFAULT_SYSLOG_FACILITY        4
#endif
#ifndef TX_LOGGER_DAEMON_CFG_MAX_SYSLOG_FACILITY
   #define TX_LOGGER_DAEMON_CFG_MAX_SYSLOG_FACILITY            7
#endif
#ifndef TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS
#define TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS               "num_batch_per_stats"
#define TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS_SZ            (sizeof(TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS)-1)
#define TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS_DEFAULT       2
#endif
#ifndef TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED
   #define TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED               "log_only_blocked"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED_SZ
   #define TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED_SZ            (sizeof(TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED_DEF_VAL       0
#endif
#ifndef TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS
   #define TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS                  "log_loc_stats"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_LOG_GROUPS
   #define TX_LOGGER_DAEMON_CFG_LOG_GROUPS                     "log_groups"
#endif
#ifndef TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS_SZ
   #define TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS_SZ               (sizeof(TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_LOG_GROUPS_SZ
   #define TX_LOGGER_DAEMON_CFG_LOG_GROUPS_SZ                  (sizeof(TX_LOGGER_DAEMON_CFG_LOG_GROUPS)-1)
#endif
#ifndef TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS_DEF_VAL          0
#endif

#ifndef TX_LOGGER_DAEMON_CFG_LOG_GROUPS_DEF_VAL
   #define TX_LOGGER_DAEMON_CFG_LOG_GROUPS_DEF_VAL             1
#endif

//Microsoft feature
#ifndef TTN_CF_RESTRICT_ACCESS_CONTEXT
   #define TTN_CF_RESTRICT_ACCESS_CONTEXT                      "Restrict-Access-Context"
#endif

#ifndef TTN_CF_RESTRICT_ACCESS_TO_TENANTS
   #define TTN_CF_RESTRICT_ACCESS_TO_TENANTS                   "Restrict-Access-To-Tenants"
#endif

#ifndef TTN_CF_RESTRICT_ACCESS_DOMAINS
   #define TTN_CF_RESTRICT_ACCESS_DOMAINS                   "Restrict-Access-Domains"
#endif

typedef struct
{
   char        cache[TTN_CF_LICENSE_CACHE_FNAME_MAX_SZ+1];
   size_t      max_users;
   size_t      max_ips;
   time_t      expiry_date;
   bool        is_license_violated;
}lic_info_t;


//---------------------------------------------------------------------
// Define and global.
//---------------------------------------------------------------------
typedef struct
{
   lic_info_t           license; 
   char                 wada_cache_file[TTN_CF_WCACHE_FILE_MAX_SZ+1];
   t_txpe_logging_cfg   log_cfg;
   bp_backed_http_t     bp_backed_http;
   ttn_md5              svrmagid;
   
   char                 int_ip_6[INET6_ADDRSTRLEN];
   char                 int_ip_4[INET_ADDRSTRLEN];

   size_t               ip_session_ttl;   
   size_t               smtp_backoff;                   /* networking table */
   size_t               avlimit;                        /* filtering table */
   size_t               wada_cache_file_sz;
   size_t               hostname_len;
   size_t               fqdn_len;
   size_t               int_ip_6_len;
   size_t               int_ip_4_len;
   size_t               cnames_len;
   size_t               proxy_port;
   size_t               titax_backoff_limit;
   size_t               fext_max_match_count;
   char*                smtp_server;                    /* networking table */
   char*                hostname;                       /* networking table */
   char*                fqdn;                           /* networking table */
   char*                cnames;                         /* networking table */
   char*                pgcstr_config;
   char*                pgcstr_reporting;
   char*                restrict_access_to_tenants;
   char*                restrict_access_context;
   char*                restrict_access_domains;

   /* flags */
   bool                 enable_auth:1;                  /* authpolicy table */
   bool                 allow_ip:1;                     /* authpolicy table */
   bool                 allow_ldap:1;                   /* authpolicy table */
   bool                 use_kshield:1;                  /* authpolicy table */
   bool                 enable_ntlm:1;                  /* authpolicy table */
   bool                 ip_session:1;                   /* authpolicy table */
   bool                 intercept_login:1;              /* authpolicy table */
   bool                 allow_wada:1;                   /* authpolicy table */
   bool                 transparentproxy:1;             /* networking table */
   bool                 avscan:1;                       /* filtering table */
   bool                 avengine:1;                     /* filtering table */
   bool                 least_restrictive:1;            /* filtering table */
   bool                 disable_filteronreq:1;          /* filtering table */
   bool                 disable_filteronresp:1;         /* filtering table */
   bool                 ac_ttl_slide:1;
   bool                 use_gids:1;
   bool                 disable_urldb:1;
   bool                 tmp_intercept_login_pfm:1;
   bool                 wada_keep_existing_entries:1;
   bool                 wada_ignore_errors:1;
   bool                 svrmagidset:1;
   bool                 use_stats_update_thread:1;
   bool                 use_data_update_thread:1;
   bool                 use_uniq_ip_remove_thread:1;
   bool                 use_intercept_login_manager:1;
   bool                 fext_greedy_match:1;
   bool                 wtc_strip_some_headers:1;
   bool                 debug:1;
   bool                 verbose:1;
   bool                 safesearch_disabled:1;
   bool                 master:1;

} TitaxConf;

typedef struct
{
   char                 titax_pg_cstr[TX_CFG_MAX_PG_CSTR+1];
   char                 traffic_pg_cstr[TX_CFG_MAX_PG_CSTR+1];
   size_t               batch_size;
   size_t               batch_treshold_div;
   size_t               delay_max;
   size_t               delay;
   size_t               if_listen_port;
   size_t               url_csz;
   uint32_t             syslog_facility;
   uint32_t             n_batches_per_stats_write; /*[1 to 10]*/
   bool                 if_listen_on_any:1;
   bool                 use_syslog:1;
   bool                 log_only_blocked:1;
   bool                 log_loc_stats:1;
   bool                 log_groups:1;

}t_tx_logger_daemon_cfg;

#ifdef __cplusplus
}
#endif

//---------------------------------------------------------------------
// Function.
//---------------------------------------------------------------------
extern pthread_mutex_t  g_conf_lock;

LI_TSA_AQ(g_conf_lock)
void TITAX_CONF_LOCK(void)
{
   tsa_lock(&g_conf_lock);
}

LI_TSA_RE(g_conf_lock)
void TITAX_CONF_UNLOCK(void)
{
   tsa_unlock(&g_conf_lock);
}


TXATR TitaxConf* titax_conf_get_instance(void);

TXATR bool titax_conf_is_enable_auth(const bool);
TXATR bool titax_conf_is_allow_ip(const bool);
TXATR bool titax_conf_is_allow_ldap(const bool);
/* for kshield usage */
TXATR bool titax_conf_use_kshield(const bool);
TXATR bool titax_conf_set_use_kshield(const bool,const bool);


TXATR bool titax_conf_is_enable_ntlm(const bool);

TXATR bool titax_conf_is_ip_session(const bool);
TXATR size_t titax_conf_get_ip_session_ttl(const bool);
TXATR bool titax_conf_get_ac_ttl_slide(const bool);
TXATR bool titax_conf_is_intercept_login(const bool);
TXATR bool titax_conf_get_smtp_server(char * const, const size_t);

TXATR size_t titax_conf_get_smtp_backoff(const bool);
TXATR bool titax_conf_get_transparentproxy(const bool);
TXATR bool titax_conf_get_least_restrictive(const bool);
TXATR bool titax_conf_is_avscan(const bool);

TXATR bool titax_conf_get_avengine(const bool);
TXATR size_t titax_conf_get_avlimit(const bool);
TXATR bool titax_conf_is_debug(const bool);
TXATR bool titax_conf_set_debug(const bool, const bool);
TXATR bool titax_conf_is_master(const bool uselocks);
TXATR bool titax_conf_set_master(const bool val, const bool uselocks);
TXATR bool titax_conf_set_disable_urldb(const bool, const bool);
TXATR bool titax_conf_get_disable_urldb(const bool);


TXATR bool titax_conf_get_verbose(const bool);
TXATR bool titax_conf_set_verbose(const bool, const bool);


TXATR void titax_conf_print_all_NL(void);
TXATR bool titax_conf_read_proxy_conf_file(void);
TXATR bool titax_conf_is_license_violated(const bool);

TXATR bool titax_conf_get_disable_filteronreq(const bool);
TXATR bool titax_conf_get_disable_filteronresp(const bool);

TXATR size_t titax_conf_get_backoff_limit(const bool);

TXATR bool titax_is_local_request(const char * const  pHost);
TXATR bool titax_reload_proxy_config(void);

TXATR bool titax_conf_set_safesearch_disabled(const bool, const bool);
TXATR bool titax_conf_get_safesearch_disabled(const bool);

TXATR bool titax_conf_svr_magid(ttn_md5 * const);

TXATR bool tx_logger_daemon_read_conf_file(t_tx_logger_daemon_cfg * const);


#ifdef TTN_ATESTS
void titax_conf_4tests_reset_a_titan_cfg_init_value(void);
bool titax_conf_4tests_get_a_titan_cfg_init_value(void);
TitaxConf* titax_conf_4tests_get_instance_err1(void);
bool titax_conf_4tests_free_instance(void);
bool titax_conf_4tests_clear_instance(void);
TitaxConf* titax_conf_4tests_get_instance_empty(void);
bool titax_conf_4tests_cfg_parse_license(t_StringList_lookup_call * const,TitaxConf* const);
bool titax_conf_4tests_cfg_parse_authpolicy(t_StringList_lookup_call * const,TitaxConf* const);
bool titax_conf_4tests_cfg_parse_networking(t_StringList_lookup_call * const,TitaxConf* const);
bool titax_conf_4tests_cfg_parse_filtering(t_StringList_lookup_call * const,TitaxConf* const);
bool titax_conf_4tests_cfg_parse_wada(t_StringList_lookup_call * const,TitaxConf* const);
bool titax_conf_4tests_cfg_parse_bp(t_StringList_lookup_call * const,TitaxConf* const);
bool titax_conf_4tests_cfg_parse_services(t_StringList_lookup_call * const,TitaxConf* const);
bool titax_conf_4tests_cfg_parse_misc(t_StringList_lookup_call * const,TitaxConf* const);
bool titax_conf_4tests_cfg_parse_db_cstr(t_StringList_lookup_call * const,TitaxConf* const);
void titax_conf_4tests_print_all_NL(TitaxConf* const);

TXATR bool tx_logger_daemon_parse_config( t_tx_logger_daemon_cfg * const, t_StringList_lookup_call * const );

#endif

/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros
 */
TXATR unsigned int get_TitaxConf_active_instances(void);


#endif /* TITAN_CONF_H */
