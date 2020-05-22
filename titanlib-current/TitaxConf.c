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

#include "TitaxConf.h"
#include "TAPE.h"
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <sys/stat.h>

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros
 */
static unsigned int n_TitaxConf_c = 0;
static unsigned int n_TitaxConf_d = 0;

unsigned int get_TitaxConf_active_instances()
{
    return (n_TitaxConf_c - n_TitaxConf_d);
}
////////////////////////////////////////////////////////////////////////////////




static TitaxConf*          g_titax_conf=NULL;
pthread_mutex_t            g_conf_lock = PTHREAD_MUTEX_INITIALIZER;

static char val_[TX_CFG_MAX_KV_STR_SZ+1];
static const size_t val_s_=sizeof(val_);

//--------------------------------------------------------------------------------
#ifndef DO_SAFE_ACTION_
   #define DO_SAFE_ACTION_(a_exp__) __extension__ ({                             \
      TITAX_CONF_LOCK();                                                         \
      const bool _dsa_v_r__=(bool)((a_exp__));                                   \
      TITAX_CONF_UNLOCK();                                                       \
      _dsa_v_r__;                                                                \
   })
#endif

   
#ifndef SAFE_GET_CONF_VALUE_
   #define SAFE_GET_CONF_VALUE_(a_field__, a_locks__,a_on_error__){              \
      TitaxConf* conf__##a_field__;                                              \
      if ( (a_locks__) ) {                                                       \
         if ((conf__##a_field__=titax_conf_get_instance())){                     \
            TITAX_CONF_LOCK();                                                   \
            const __typeof (conf__##a_field__->a_field__) v_r__##a_field__=      \
            (conf__##a_field__->a_field__);                                      \
            TITAX_CONF_UNLOCK();                                                 \
            return (v_r__##a_field__);                                           \
         }                                                                       \
      }                                                                          \
      else {                                                                     \
         if ((conf__##a_field__=titax_conf_get_instance())){                     \
            const __typeof (conf__##a_field__->a_field__) v_r__##a_field__=      \
            (conf__##a_field__->a_field__);                                      \
            return (v_r__##a_field__);                                           \
         }                                                                       \
      } return ( (a_on_error__) );                                               \
   }
#endif

#ifndef SAFE_GET_CONF_BIT_VALUE_
   #define SAFE_GET_CONF_BIT_VALUE_(a_field__, a_locks__,a_on_error__){          \
      TitaxConf* conf__##a_field__;                                              \
      if ( (a_locks__) ) {                                                       \
         if ((conf__##a_field__=titax_conf_get_instance())){                     \
            TITAX_CONF_LOCK();                                                   \
            const bool v_r__##a_field__ = (conf__##a_field__->a_field__);        \
            TITAX_CONF_UNLOCK();                                                 \
            return (v_r__##a_field__);                                           \
         }                                                                       \
      }                                                                          \
      else {                                                                     \
         if ((conf__##a_field__=titax_conf_get_instance())){                     \
            const bool v_r__##a_field__=(conf__##a_field__->a_field__);          \
            return (v_r__##a_field__);                                           \
         }                                                                       \
      } return ( (a_on_error__) );                                               \
   }
#endif

#ifndef SAFE_SET_CONF_VALUE_
   #define SAFE_SET_CONF_VALUE_(a_field__,a_value__,a_locks__,a_on_error__){     \
      TitaxConf* conf__##a_field__;                                              \
      if ( (a_locks__) ) {                                                       \
         if ((conf__##a_field__=titax_conf_get_instance())){                     \
            TITAX_CONF_LOCK();                                                   \
            conf__##a_field__->a_field__=(a_value__);                            \
            TITAX_CONF_UNLOCK();                                                 \
         }                                                                       \
      }                                                                          \
      else {                                                                     \
         if ((conf__##a_field__=titax_conf_get_instance())){                     \
            conf__##a_field__->a_field__=(a_value__);                            \
         }                                                                       \
         return ( (a_value__) );                                                 \
      } return ( (a_on_error__) );                                               \
   }
#endif

TX_INTERNAL_INLINE
bool parse_bool_( t_StringList_lookup_call * const restrict  call,
                  const char * const restrict  kw,
                  const size_t ksz,
                  const bool def                                  )
{
   size_t l_=0;
   bool r_=def;
   char * val=val_;
   (void)((mk_string_list_lookup_call(call,kw, ksz) && (call->lookup_idx>=0)) && (
         get_cfg_key_value(call->list->arr[call->lookup_idx],val,&l_,val_s_) &&
         ( call->list->arr[call->lookup_idx][0]='#') &&
         ((( tx_safe_atob(val,&r_) || ((r_=def)||true )) && zm(val,l_)) 
           //NE
           || zm(val,l_))
   ));
   
   return (r_);
}

TX_INTERNAL_INLINE
ssize_t parse_numeric_( t_StringList_lookup_call * const restrict call,
                        const char * const restrict kw, 
                        const size_t ksz,
                        const ssize_t def                               )
{
   size_t l=0;
   ssize_t r=def;
   char * val=val_;
   (void)((mk_string_list_lookup_call(call,kw, ksz) && (call->lookup_idx>=0)) && (
         get_cfg_key_value(call->list->arr[call->lookup_idx],val,&l,val_s_) &&
         ( call->list->arr[call->lookup_idx][0]='#') &&
         ((( tx_safe_atol(val,&r) || ((r=def)||1)) && zm(val,l))
           //NE
         || zm(val,l))
   ));
   return (r);
}

TX_INTERNAL_INLINE
size_t parse_uint_(  t_StringList_lookup_call * const restrict  call,
                     const char * const restrict kw, 
                     const size_t ksz,
                     const size_t def                                )
{
   ssize_t r=parse_numeric_(call,kw,ksz,(ssize_t)def);
   return ((size_t)labs(r));
}

TX_INTERNAL_INLINE
bool parse_csa(   t_StringList_lookup_call * const restrict call,
                  const char * const restrict  kw, 
                  const size_t ksz, 
                  const char * const restrict def_val,
                  const  size_t def_val_sz, 
                  size_t * const restrict  outsz                  )
{
   char * val  =  val_;

   const size_t valsz   =  val_s_;

   if (  mk_string_list_lookup_call( call, kw, ksz )                 &&

         call->lookup_idx>=0                                         &&

         get_cfg_key_value(   call->list->arr[call->lookup_idx],
                              val,
                              outsz,
                              valsz                               )  &&

         *outsz                                                         )  {

      call->list->arr[call->lookup_idx][0] = '#';
      
      return true;
   }


   //if (!def_val_sz || tx_safe_memcpy( val, def_val, MIN(valsz,def_val_sz) ) ) {
   if (def_val_sz && tx_safe_memcpy( val, def_val, MIN(valsz,def_val_sz) ) ) {
   
      *outsz = def_val_sz;

      return true;
   }

   return false;
}

//----------------------------------------------------------------------
TX_INTERNAL_INLINE
void CFG_PARSE_LICENSE_(   t_StringList_lookup_call * const restrict a_lcall_,
                           TitaxConf* const restrict a_conf_ ){

   
   a_conf_->license.max_users=MAX_USERS_DEFAULT;
   a_conf_->license.max_ips=MAX_UNIQ_IPS_DEFAULT;
   a_conf_->license.expiry_date=EXPIRY_DATE_DEFAULT;
   a_conf_->license.is_license_violated=IS_LICENSE_VIOLATED_DEFAULT;

   size_t l_=0;
   if (parse_csa(a_lcall_,TTN_CF_LICENSE_CACHE,
      (sizeof(TTN_CF_LICENSE_CACHE)-1),TTN_CF_LICENSE_CACHE_DEFAULT,
      (sizeof(TTN_CF_LICENSE_CACHE_DEFAULT)-1),&l_) && l_){

         tx_safe_memcpy(   a_conf_->license.cache,
                           val_,
                           (TTN_CF_LICENSE_CACHE_FNAME_MAX_SZ>l_ ?
                           l_ :
                           TTN_CF_LICENSE_CACHE_FNAME_MAX_SZ)
                     );
         zm(val_,l_);
   }
}


TX_INTERNAL_INLINE
void  CFG_PARSE_NETWORKING_(  t_StringList_lookup_call * const restrict a_lcall_,
                              TitaxConf* const restrict a_conf_ ){

   size_t l_=0;

   tx_safe_free(a_conf_->smtp_server);
   a_conf_->smtp_server=NULL;
   if (parse_csa(a_lcall_,TTN_CF_SMTP_SERVER, (sizeof(TTN_CF_SMTP_SERVER)-1),0,0,&l_)){
      if (l_ && (a_conf_->smtp_server=str_dup_ex(val_,&l_))){
         zm(val_,l_);
      }
   }

   a_conf_->smtp_backoff=parse_uint_(  a_lcall_,
                                       TTN_CF_SMTP_BACKOFF,
                                       (sizeof(TTN_CF_SMTP_BACKOFF)-1),
                                       DEFAULT_BACKOFF);

   a_conf_->transparentproxy=parse_bool_( a_lcall_,
                                          TTN_CF_TRANSPARENT_PROXY_ENABLED,
                                          (sizeof(TTN_CF_TRANSPARENT_PROXY_ENABLED)-1),
                                          false);

   tx_safe_free(a_conf_->hostname);
   a_conf_->hostname=NULL;
   a_conf_->hostname_len=0;
   if (parse_csa(a_lcall_,TTN_CF_HOSTNAME,(sizeof(TTN_CF_HOSTNAME)-1),0,0,&l_)){
      if (l_ && (a_conf_->hostname=str_dup_ex(val_,&l_))){
         a_conf_->hostname_len=l_;
         zm(val_,l_);
      }
   }

   tx_safe_free(a_conf_->fqdn);
   a_conf_->fqdn=NULL;
   a_conf_->fqdn_len =0;
   if (parse_csa(a_lcall_,TTN_CF_DOMAIN,(sizeof(TTN_CF_DOMAIN)-1),0,0,&l_)){
      if (l_){
          const size_t len_=a_conf_->hostname_len + l_ + 2;
          if ((a_conf_->fqdn=tx_safe_malloc(len_))){
            char f[32]={};
            if (tx_safe_snprintf(f,sizeof(f), "%%%zus.%%%zus",a_conf_->hostname_len,l_)){
               a_conf_->fqdn_len=(size_t)tx_safe_snprintf(a_conf_->fqdn,len_, f, a_conf_->hostname, val_);
            }
         }
      }
      zm(val_,l_);
   }

   strlcpy(a_conf_->int_ip_4,PROXY_DEFAULT_IPv4,sizeof(a_conf_->int_ip_4));
   a_conf_->int_ip_4_len=(sizeof(PROXY_DEFAULT_IPv4)-1);
   strlcpy(a_conf_->int_ip_6,PROXY_DEFAULT_IPv6,sizeof(a_conf_->int_ip_6));
   a_conf_->int_ip_6_len=(sizeof(PROXY_DEFAULT_IPv6)-1);


   /* ipv4 */
   if (  (parse_csa(a_lcall_,TTN_CF_IP,(sizeof(TTN_CF_IP)-1),0,0,&l_) && l_)
         ||
         (parse_csa(a_lcall_,TTN_CF_IP4,(sizeof(TTN_CF_IP4)-1),0,0,&l_) && l_) ){
            
            if ((a_conf_->int_ip_4_len=(l_<INET_ADDRSTRLEN ? l_ : INET_ADDRSTRLEN-1))){
               tx_safe_memcpy(a_conf_->int_ip_4,val_,a_conf_->int_ip_4_len);
               if (!ttn_is_valid_str_ipaddr(a_conf_->int_ip_4)){
                  a_conf_->int_ip_4_len=a_conf_->int_ip_4[0]=0;
               }
            }
            zm(val_,l_);
   }

   /* ipv6 */
   if ( (parse_csa(a_lcall_,TTN_CF_IP6,(sizeof(TTN_CF_IP6)-1),0,0,&l_) && l_)){
            
            if ((a_conf_->int_ip_6_len=(l_<INET6_ADDRSTRLEN ? l_ : INET6_ADDRSTRLEN-1))){
               tx_safe_memcpy(a_conf_->int_ip_6,val_,a_conf_->int_ip_6_len);
               if (!ttn_is_valid_str_ipaddr(a_conf_->int_ip_6)){
                  a_conf_->int_ip_6_len=a_conf_->int_ip_6[0]=0;
               }
            }
            zm(val_,l_);
   }

   tx_safe_free(a_conf_->cnames);
   a_conf_->cnames=NULL;
   a_conf_->cnames_len=0;
   if (parse_csa(a_lcall_,TTN_CF_CNAME,(sizeof(TTN_CF_CNAME)-1),0,0,&l_)){
      if (l_ &&   (a_conf_->cnames=str_dup_ex(val_,&l_)) ){
         a_conf_->cnames_len=l_;
         zm(val_,l_);
      }
   }

   a_conf_->proxy_port=parse_uint_( a_lcall_,
                                    TTN_CF_PROXY_PORT,
                                    (sizeof(TTN_CF_PROXY_PORT)-1),
                                    PROXY_DEFAULT_PORT);

   if (!WITHIN_(1,USHRT_MAX,a_conf_->proxy_port) )
         a_conf_->proxy_port=PROXY_DEFAULT_PORT;

}

#define CFG_PARSE_FILTERING_(a_lcall_,a_conf_,a_val_) {                             \
   (a_conf_)->avscan=parse_bool_((a_lcall_),TTN_CF_AVSCANNER_ENABLED,               \
           (sizeof(TTN_CF_AVSCANNER_ENABLED)-1),false);                             \
   (a_conf_)->avengine=parse_bool_((a_lcall_),TTN_CF_AVSCANNER_ENGINE_TYPE,         \
           (sizeof(TTN_CF_AVSCANNER_ENGINE_TYPE)-1),true);                          \
   (a_conf_)->avlimit=parse_uint_((a_lcall_),TTN_CF_AVSCANNER_MEM_LIMIT,            \
           (sizeof(TTN_CF_AVSCANNER_MEM_LIMIT)-1),DEF_AVLIMIT);                     \
   (void)(!UWITHIN_(MAX_AVLIMIT,(a_conf_)->avlimit)                                 \
            && ((a_conf_)->avlimit=MAX_AVLIMIT));                                   \
   (a_conf_)->least_restrictive=parse_bool_((a_lcall_),TTN_CF_LEAST_RESTRICTIVE,    \
           (sizeof(TTN_CF_LEAST_RESTRICTIVE)-1),true);                              \
   (a_conf_)->disable_filteronreq=parse_bool_((a_lcall_),                           \
           TTN_CF_FILTER_ONREQ_DISABLED,                                            \
           (sizeof(TTN_CF_FILTER_ONREQ_DISABLED)-1),false);                         \
   (a_conf_)->disable_filteronresp=parse_bool_((a_lcall_),                          \
           TTN_CF_FILTER_ONRESP_DISABLED,                                           \
           (sizeof(TTN_CF_FILTER_ONRESP_DISABLED)-1),false);                        \
}

#define CFG_PARSE_WADA_(a_lcall_,a_conf_,a_val_,a_l_){                              \
   (void)zm((a_conf_)->wada_cache_file,sizeof((a_conf_)->wada_cache_file));         \
   (a_conf_)->wada_cache_file_sz=0;                                                 \
   (void)(parse_csa((a_lcall_),TTN_CF_WCACHE_FILE,                                  \
           (sizeof(TTN_CF_WCACHE_FILE)-1),                                          \
           TTN_CF_WCACHE_FILE_DEFAULT,                                              \
           (sizeof(TTN_CF_WCACHE_FILE_DEFAULT)-1),&(a_l_))                          \
   && ((a_conf_)->wada_cache_file_sz=(a_l_))                                        \
   && tx_safe_memcpy((a_conf_)->wada_cache_file,(a_val_),                           \
           (TTN_CF_WCACHE_FILE_MAX_SZ>(a_l_)?(a_l_):                                \
         ((a_conf_)->wada_cache_file_sz=TTN_CF_WCACHE_FILE_MAX_SZ)))                \
   && zm((a_val_),(a_l_)));                                                         \
   (a_conf_)->wada_keep_existing_entries=parse_bool_((a_lcall_),                    \
           TTN_CF_WADA_EXISTING_ENTRIES,                                            \
           (sizeof(TTN_CF_WADA_EXISTING_ENTRIES)-1),false);                         \
   (a_conf_)->wada_ignore_errors=parse_bool_((a_lcall_),                            \
           TTN_CF_WADA_IGNORE_ERRORS,                                               \
           (sizeof(TTN_CF_WADA_IGNORE_ERRORS)-1),false);                            \
   (a_conf_)->allow_wada=parse_bool_((a_lcall_),                                    \
           TTN_CF_WADA_BLOCK_IF_NOT_FOUND,                                          \
           (sizeof(TTN_CF_WADA_BLOCK_IF_NOT_FOUND)-1),false);                       \
}

#define CFG_PARSE_SERVICES_(a_lcall_,a_conf_){                                      \
   (a_conf_)->use_data_update_thread=parse_bool_((a_lcall_),                        \
           TTN_CF_USE_INTERNAL_DATA_UPDATER_THREAD,                                 \
           (sizeof(TTN_CF_USE_INTERNAL_DATA_UPDATER_THREAD)-1),true);               \
   (a_conf_)->use_stats_update_thread=parse_bool_((a_lcall_),                       \
           TTN_CF_USE_INTERNAL_STAT_UPDATER_THREAD,                                 \
           (sizeof(TTN_CF_USE_INTERNAL_STAT_UPDATER_THREAD)-1),true);               \
   (a_conf_)->use_uniq_ip_remove_thread=parse_bool_((a_lcall_),                     \
           TTN_CF_USE_INTERNAL_UQIP_REMOVER_THREAD,                                 \
           (sizeof(TTN_CF_USE_INTERNAL_UQIP_REMOVER_THREAD)-1),true);               \
   (a_conf_)->use_intercept_login_manager=parse_bool_((a_lcall_),                   \
           TTN_CF_USE_INTERNAL_LGIN_INTRCPT_THREAD,                                 \
           (sizeof(TTN_CF_USE_INTERNAL_LGIN_INTRCPT_THREAD)-1),true);               \
}

#define CFG_PARSE_MISC_(a_lcall_,a_conf_,a_val_,a_l_){                                 \
   (void)zm(&(a_conf_)->log_cfg,sizeof(t_txpe_logging_cfg));                           \
   size_t psz=parse_uint_((a_lcall_),TTN_CF_LOGGER_LOG_TYPE,                           \
           (sizeof(TTN_CF_LOGGER_LOG_TYPE)-1),DEF_LOGGER_TYPE);                        \
   (void)(UWITHIN_(ot_max,psz) && ((a_conf_)->log_cfg.type=                            \
           (t_txpe_output_type)psz));                                                  \
   bool e_=true; const char * def_path=DEF_LOGGER_UDS_PATH;                            \
   size_t def_path_sz=(sizeof(DEF_LOGGER_UDS_PATH)-1);                                 \
   switch ((a_conf_)->log_cfg.type){                                                   \
      case ot_file:{def_path=0;def_path_sz=0;}                                         \
      case ot_uds:{                                                                    \
         (void)(parse_csa((a_lcall_),TTN_CF_LOGGER_LOG_PATH,                           \
            (sizeof(TTN_CF_LOGGER_LOG_PATH)-1),def_path,def_path_sz,&(a_l_))           \
         && (a_l_) && ((a_conf_)->log_cfg.path_sz=                                     \
            ((a_l_)<LOGGER_PATH_MAX_SZ?(a_l_):LOGGER_PATH_MAX_SZ)) &&                  \
         tx_safe_memcpy((a_conf_)->log_cfg.path,(a_val_),(a_conf_)->log_cfg.path_sz)   \
         && !(e_=false)                                                                \
         && zm((a_val_),(a_l_)));(void) (e_ && ((a_conf_)->log_cfg.type=ot_none));     \
      }break;                                                                          \
      case ot_tcp:{                                                                    \
         if (parse_csa((a_lcall_),TTN_CF_LOGGER_LOG_PATH,                              \
            (sizeof(TTN_CF_LOGGER_LOG_PATH)-1),0,0,&(a_l_))                            \
            && (a_l_) && ((a_conf_)->log_cfg.path_sz=                                  \
            ((a_l_)<LOGGER_PATH_MAX_SZ?(a_l_):LOGGER_PATH_MAX_SZ))                     \
            && tx_safe_memcpy((a_conf_)->log_cfg.path,(a_val_),                        \
               (a_conf_)->log_cfg.path_sz)){                                           \
            ssize_t v=0;char * p=NULL; c_raw_ipaddr_t ipr={};                          \
            if (WITHIN_(9,LOGGER_PATH_MAX_SZ,(a_l_)) &&                                \
               (p=strnstr((a_val_),":",(a_l_))) && tx_safe_atol(p+1,&v) && !(p=0) &&   \
               WITHIN_(1,USHRT_MAX,v)){                                                \
                    (a_conf_)->log_cfg.port=(uint16_t)v;                               \
                    const size_t ll_=strlen((a_val_));                                 \
                    if (ttn_str_ipaddr2raw_ipaddr_ex((a_val_), ll_ ,&ipr) &&           \
                        !(e_=false)){                                                  \
                            strlcpy((a_conf_)->log_cfg.ip,(a_val_),ll_);               \
                    } else {                                                           \
                        (a_conf_)->log_cfg.port=0;                                     \
                    }                                                                  \
            } (void)zm((a_val_),(a_l_));                                               \
         } (void)(e_ && ((a_conf_)->log_cfg.type=ot_none));                            \
      }break;                                                                          \
      default:break;                                                                   \
   }                                                                                   \
   (a_conf_)->master = 0;                                                              \
   (a_conf_)->titax_backoff_limit=parse_uint_((a_lcall_),                              \
           TTN_CF_BACKOFF_LIMIT,(sizeof(TTN_CF_BACKOFF_LIMIT)-1),0);                   \
   (a_conf_)->fext_greedy_match=parse_bool_((a_lcall_),                                \
           TTN_CF_FILE_EXT_GREEDY_MATCHING,                                            \
           (sizeof(TTN_CF_FILE_EXT_GREEDY_MATCHING)-1),true);                          \
   (a_conf_)->fext_max_match_count=parse_uint_((a_lcall_),                             \
           TTN_CF_FILE_EXT_MAX_MATCH_COUNT,                                            \
           (sizeof(TTN_CF_FILE_EXT_MAX_MATCH_COUNT)-1),1);                             \
   (a_conf_)->wtc_strip_some_headers  =parse_bool_((a_lcall_),                         \
           TTN_CF_WTC_STRIP_SOME_HEADERS,                                              \
           (sizeof(TTN_CF_WTC_STRIP_SOME_HEADERS)-1),false);                           \
   (a_conf_)->safesearch_disabled=parse_bool_((a_lcall_),                              \
           TTN_CF_DISABLE_SAFESEARCH,                                                  \
           (sizeof(TTN_CF_DISABLE_SAFESEARCH)-1),false);                               \
   ttn_set_verbose_state(( (a_conf_)->verbose=parse_bool_((a_lcall_),TTN_CF_VERBOSE,   \
            (sizeof(TTN_CF_VERBOSE)-1),ttn_get_verbose_state()) ));                    \
   ttn_set_txdebug_state( ((a_conf_)->debug=parse_bool_((a_lcall_),                    \
           TTN_CF_DEBUG, (sizeof(TTN_CF_DEBUG)-1),ttn_get_txdebug_state() ))) ;        \
   if ((a_conf_)->debug)                                                               \
       ttn_set_verbose_state(((a_conf_)->verbose=true));                               \
}


TX_INTERNAL_INLINE
void CFG_PARSE_AUTHPOLICY_(   t_StringList_lookup_call * const restrict a_lcall_,
                              TitaxConf* const restrict a_conf_){

   a_conf_->enable_auth=parse_bool_(a_lcall_,TTN_CF_AUTH_ENABLED,(sizeof(TTN_CF_AUTH_ENABLED)-1),false);
   a_conf_->allow_ip=parse_bool_(a_lcall_,TTN_CF_AUTH_ALLOW_IP,(sizeof(TTN_CF_AUTH_ALLOW_IP)-1),false);
   a_conf_->allow_ldap=parse_bool_(a_lcall_,TTN_CF_AUTH_ALLOW_LDAP,(sizeof(TTN_CF_AUTH_ALLOW_LDAP)-1),false);
   a_conf_->use_kshield=parse_bool_(a_lcall_,TTN_CF_AUTH_ALLOW_KSHIELD,(sizeof(TTN_CF_AUTH_ALLOW_KSHIELD)-1),false);
   a_conf_->enable_ntlm=parse_bool_(a_lcall_,TTN_CF_AUTH_ALLOW_NTLM,(sizeof(TTN_CF_AUTH_ALLOW_NTLM)-1),false);
   a_conf_->ip_session=parse_bool_(a_lcall_,TTN_CF_AC_IP_SESSION_ENABLED,(sizeof(TTN_CF_AC_IP_SESSION_ENABLED)-1),false);
   a_conf_->ip_session_ttl=parse_uint_(a_lcall_,TTN_CF_AC_IP_SESSION_TTL,(sizeof(TTN_CF_AC_IP_SESSION_TTL)-1),MIN_IP_SESSION_TTL);
   a_conf_->ac_ttl_slide=parse_bool_(a_lcall_,TTN_CF_AC_TTL_SLIDE,(sizeof(TTN_CF_AC_TTL_SLIDE)-1),false);
   a_conf_->use_gids=parse_bool_(a_lcall_,TTN_CF_USE_GROUP_IDS,(sizeof(TTN_CF_USE_GROUP_IDS)-1),false);
   a_conf_->disable_urldb=parse_bool_(a_lcall_,TTN_CF_DISABLE_URLDB,(sizeof(TTN_CF_DISABLE_URLDB)-1),false);
   a_conf_->intercept_login=parse_bool_(a_lcall_,TTN_CF_INTERCEPT_LOGIN,(sizeof(TTN_CF_INTERCEPT_LOGIN)-1),false);
   a_conf_->tmp_intercept_login_pfm=parse_bool_(a_lcall_,TTN_CF_USE_PORTAL_WITH_PFM,(sizeof(TTN_CF_USE_PORTAL_WITH_PFM)-1),false);
}

TX_INTERNAL_INLINE
void CFG_PARSE_BP_(  t_StringList_lookup_call * const restrict a_lcall_,
                     TitaxConf* const restrict a_conf_){

   size_t l_=0;
   if (  parse_csa(a_lcall_,TTN_CF_BLOCKPAGE_SERVER_IP,(sizeof(TTN_CF_BLOCKPAGE_SERVER_IP)-1), BP_DEFAULT_IPv4,(sizeof(BP_DEFAULT_IPv4)-1),&l_) && l_){
      c_raw_ipaddr_t s_=ttn_str_ipaddr2raw_ipaddr(val_,l_);

      if (!ttn_is_valid_raw_ipaddr( &s_ )){
         s_=ttn_str_ipaddr2raw_ipaddr(BP_DEFAULT_IPv4,(sizeof(BP_DEFAULT_IPv4)-1));
      }

      a_conf_->bp_backed_http.ip=s_;
      zm(val_,l_);
   }

   zm(a_conf_->bp_backed_http.path,sizeof(a_conf_->bp_backed_http.path));
   a_conf_->bp_backed_http.path_sz=0;
   if (  parse_csa(a_lcall_,TTN_CF_BLOCKPAGE_SERVER_QUERY_PATH,(sizeof(TTN_CF_BLOCKPAGE_SERVER_QUERY_PATH)-1), BP_DEFAULT_PATH,(sizeof(BP_DEFAULT_PATH)-1),&l_)
         &&
         (a_conf_->bp_backed_http.path_sz=(l_<BP_PATH_SZ?l_:BP_PATH_SZ)))
   {
      tx_safe_memcpy(a_conf_->bp_backed_http.path,val_,a_conf_->bp_backed_http.path_sz);
      zm(val_,l_);
   }
   a_conf_->bp_backed_http.port=parse_uint_(a_lcall_,TTN_CF_BLOCKPAGE_SERVER_PORT,(sizeof(TTN_CF_BLOCKPAGE_SERVER_PORT)-1),BP_DEFAULT_PORT);
   if (!WITHIN_(1,USHRT_MAX,a_conf_->bp_backed_http.port)){
      a_conf_->bp_backed_http.port=BP_DEFAULT_PORT;
   }
   a_conf_->svrmagidset = false; 
   ttn_md5_clear(&a_conf_->svrmagid);
}

TX_INTERNAL_INLINE
void CFG_PARSE_DB_CSTR_(   t_StringList_lookup_call * const restrict a_lcall_,
                           TitaxConf* const restrict a_conf_){

   size_t l_=0;
   tx_safe_free(a_conf_->pgcstr_config);
   a_conf_->pgcstr_config=NULL;
   if (  !(a_conf_->pgcstr_config=getenv(TTN_CF_PG_CON_STR_CONFIG_DB)) 
         &&
         (parse_csa(a_lcall_,TTN_CF_PG_CON_STR_CONFIG_DB, (sizeof(TTN_CF_PG_CON_STR_CONFIG_DB)-1),PQ_CONFDB_CINFO,  (sizeof(PQ_CONFDB_CINFO)-1),&l_))
         && 
         l_ 
         && 
         (a_conf_->pgcstr_config=str_dup_ex(val_,&l_)))
   {       
         zm(val_,l_);
   } else {
      a_conf_->pgcstr_config = str_dup(a_conf_->pgcstr_config);
   }

   tx_safe_free(a_conf_->pgcstr_reporting);
   a_conf_->pgcstr_reporting=NULL;
   if (  parse_csa(a_lcall_,TTN_CF_PG_CON_STR_REPORT_DB, (sizeof(TTN_CF_PG_CON_STR_REPORT_DB)-1),PQ_CONFDB_CTRAFFIC,(sizeof(PQ_CONFDB_CTRAFFIC)-1),&l_)
         && 
         l_ 
         && 
         (a_conf_->pgcstr_reporting=str_dup_ex(val_,&l_)))
   {
      zm(val_,l_);
   }

}

TX_INTERNAL_INLINE
void CFG_PARSE_MICROSOFT_(   t_StringList_lookup_call * const restrict a_lcall_,
                             TitaxConf* const restrict a_conf_){
   size_t l_=0;
   tx_safe_free(a_conf_->restrict_access_context);
   a_conf_->restrict_access_context = NULL;
   if ((parse_csa(a_lcall_, TTN_CF_RESTRICT_ACCESS_CONTEXT, (sizeof(TTN_CF_RESTRICT_ACCESS_CONTEXT)-1), NULL,  0,&l_))
       &&
       l_
       &&
       (a_conf_->restrict_access_context = str_dup_ex(val_,&l_)))
   {
      zm(val_,l_);
   }

   tx_safe_free(a_conf_->restrict_access_to_tenants);
   a_conf_->restrict_access_to_tenants = NULL;
   if (  parse_csa(a_lcall_, TTN_CF_RESTRICT_ACCESS_TO_TENANTS, (sizeof(TTN_CF_RESTRICT_ACCESS_TO_TENANTS)-1), NULL, 0 ,&l_)
         &&
         l_
         &&
         (a_conf_->restrict_access_to_tenants = str_dup_ex(val_,&l_)))
   {
      zm(val_,l_);
   }

   tx_safe_free(a_conf_->restrict_access_domains);
   a_conf_->restrict_access_domains = NULL;
   if (  parse_csa(a_lcall_, TTN_CF_RESTRICT_ACCESS_DOMAINS, (sizeof(TTN_CF_RESTRICT_ACCESS_DOMAINS)-1), NULL, 0 ,&l_)
         &&
         l_
         &&
         (a_conf_->restrict_access_domains = str_dup_ex(val_,&l_)))
   {
      zm(val_,l_);
   }
}

TX_INTERNAL_INLINE
bool READ_PROXY_CONF_FILE_(   t_StringList_lookup_call * const restrict a_lookup_call_,
                              TitaxConf* const restrict a_conf_){

   if (a_conf_ && a_lookup_call_){
      (void)zm(val_,val_s_);
      size_t v_l_=0;
      CFG_PARSE_LICENSE_      (a_lookup_call_,a_conf_);
      CFG_PARSE_AUTHPOLICY_   (a_lookup_call_,a_conf_);
      CFG_PARSE_NETWORKING_   (a_lookup_call_,a_conf_);
      CFG_PARSE_FILTERING_    (a_lookup_call_,a_conf_,val_)
      CFG_PARSE_WADA_         (a_lookup_call_,a_conf_,val_,v_l_)
      CFG_PARSE_BP_           (a_lookup_call_,a_conf_);
      CFG_PARSE_SERVICES_     (a_lookup_call_,a_conf_)
      CFG_PARSE_MISC_         (a_lookup_call_,a_conf_,val_,v_l_)
      CFG_PARSE_DB_CSTR_      (a_lookup_call_,a_conf_);
      CFG_PARSE_MICROSOFT_    (a_lookup_call_,a_conf_);
      return true;
   }
   return false;
}


TX_INTERNAL_INLINE
void titax_conf_print_all_(TitaxConf* const restrict cfg){

   puts("-------------------------------------------------------");
   puts("");
   printf("enable_auth = %d\n", cfg->enable_auth);
   printf("allow_ip = %d\n", cfg->allow_ip);
   printf("enable_ntlm = %d\n", cfg->enable_ntlm);
   printf("allow_ldap = %d\n", cfg->allow_ldap);
   printf("use_kshield = %d\n", cfg->use_kshield);
   printf("ip_session = %d\n", cfg->ip_session);
   printf("ip_session_ttl = %zu\n", cfg->ip_session_ttl);
   printf("intercept_login = %d\n", cfg->intercept_login);

   printf("smtp_server = %s\n", cfg->smtp_server);
   printf("smtp_backoff = %zu\n", cfg->smtp_backoff);
   printf("avscan = %d\n", cfg->avscan);
   printf("avengine = %d\n", cfg->avengine);

   printf("avlimit = %zu\n", cfg->avlimit);
   printf("hostname = %s\n", cfg->hostname);
   printf("fqdn = %s\n", cfg->fqdn);
   printf("int_ip_4 = %s\n", cfg->int_ip_4);
   printf("int_ip_6 = %s\n", cfg->int_ip_6);
   printf("cnames = %s\n", cfg->cnames_len?cfg->cnames:"<empty>");

   printf("debug = %d\n", cfg->debug);
   printf("_verbose = %d\n", cfg->verbose);
   printf("fext_greedy_match = %d\n", cfg->fext_greedy_match);
   printf("fext_max_match_count = %zu\n", cfg->fext_max_match_count);

   printf("transparentproxy = %d\n", cfg->transparentproxy);
   printf("leastrestrict = %d\n", cfg->least_restrictive);

   printf("disable_filteronreq = %d\n", cfg->disable_filteronreq);
   printf("disable_filteronresp = %d\n", cfg->disable_filteronresp);

   printf("wada_cache_file = %s\n", cfg->wada_cache_file);
   printf("wada_ignore_errors = %d\n", cfg->wada_ignore_errors);
   printf("wada_keep_existing_entries = %d\n", cfg->wada_keep_existing_entries);
   printf("ac_ttl_slide = %d\n", cfg->ac_ttl_slide);
   printf("use_gids = %d\n", cfg->use_gids);
   puts("");
   puts("Logging:\n");
   printf("\t-type:[%d]\n",cfg->log_cfg.type);
   printf("\t-path:[%s]\n",(cfg->log_cfg.path[0]?cfg->log_cfg.path:(cfg->log_cfg.type==ot_uds?DEF_LOGGER_UDS_PATH:"")));
   printf("\t-ip:[%s]\n",cfg->log_cfg.ip);
   printf("\t-port:[%hu]\n",cfg->log_cfg.port);
   puts("");
   puts("Internal Services:\n");
   printf("\t-use_stats_update_thread:[%d]\n",cfg->use_stats_update_thread);
   printf("\t-use_data_update_thread:[%d]\n",cfg->use_data_update_thread);
   printf("\t-use_uniq_ip_remove_thread:[%d]\n",cfg->use_uniq_ip_remove_thread);
   printf("\t-use_intercept_login_manager:[%d]\n",cfg->use_intercept_login_manager);
   puts("");
   puts("Microsoft Tenant Restrictions: \n");
   printf("\t-Restrict-Access-Context:[%s]\n",(cfg->restrict_access_context ? cfg->restrict_access_context : "NULL"));
   printf("\t-Restrict-Access-To-Tenants:[%s]\n",(cfg->restrict_access_to_tenants ? cfg->restrict_access_to_tenants : "NULL"));
   printf("\t-Restrict-Access-Domains:[%s]\n",(cfg->restrict_access_domains ? cfg->restrict_access_domains : "NULL"));
   puts("-------------------------------------------------------");

}

TitaxConf* titax_conf_get_instance(){
   if (g_titax_conf) return (g_titax_conf);   
   TitaxConf* const tmp= (TitaxConf*const )tx_safe_malloc(sizeof(TitaxConf));
   if (tmp){
      t_StringList_lookup_call lookup_call={.list=read_text_file(TTN_CF_FILE, 0)};
      const bool parsing_status=READ_PROXY_CONF_FILE_(&lookup_call,tmp);
      assert(parsing_status && "parsing has failed");
      g_titax_conf=tmp;
      (void)string_list_free(lookup_call.list);
      lookup_call.key=NULL;
      /* DI */
      n_TitaxConf_c++;
      return (g_titax_conf);
   }
   assert(0 && "titax_conf_get_instance->inconclusive state");
}

#ifdef TTN_ATESTS
TitaxConf* titax_conf_4tests_get_instance_err1(){
   return (g_titax_conf?:NULL);
}

bool titax_conf_4tests_free_instance(){
   bool ret=false;
   TITAX_CONF_LOCK();
   TitaxConf* const conf_=g_titax_conf;
   if (conf_){
      g_titax_conf=NULL;
      tx_safe_free (conf_->pgcstr_config);
      tx_safe_free (conf_->pgcstr_reporting);
      tx_safe_free (conf_->smtp_server);
      tx_safe_free (conf_->hostname);
      tx_safe_free (conf_->fqdn);
      tx_safe_free (conf_->cnames);
      (void)zm(conf_,sizeof(TitaxConf));
      tx_safe_free(conf_);
      /* DI */
      n_TitaxConf_d++;
      ret=true;
   }
   TITAX_CONF_UNLOCK();
   return ret;
}

bool titax_conf_4tests_clear_instance(){
   bool ret=false;
   TITAX_CONF_LOCK();
   TitaxConf* const conf_=g_titax_conf; 
   if (conf_){
      tx_safe_free (conf_->pgcstr_config);
      tx_safe_free (conf_->pgcstr_reporting);
      tx_safe_free (conf_->smtp_server);
      tx_safe_free (conf_->hostname);
      tx_safe_free (conf_->fqdn);
      tx_safe_free (conf_->cnames);
      (void)zm(conf_,sizeof(TitaxConf));
      ret=true;
   }
   TITAX_CONF_UNLOCK();
   return ret;
}

TitaxConf* titax_conf_4tests_get_instance_empty(){
   if (g_titax_conf) return (g_titax_conf);
   TitaxConf* const tmp= (TitaxConf*const )tx_safe_malloc(sizeof(TitaxConf));
   if (tmp){
      g_titax_conf=tmp;
      /* DI */
      n_TitaxConf_c++;
      return (tmp);
   }
   assert(0 && "titax_conf_get_instance->inconclusive state");
}

bool titax_conf_4tests_cfg_parse_license(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      (void)zm(val_,val_s_); 
      CFG_PARSE_LICENSE_(lookup_call,conf_);
      return (true);
   }
   return (false);
}

bool titax_conf_4tests_cfg_parse_authpolicy(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      (void)zm(val_,val_s_); 
      CFG_PARSE_AUTHPOLICY_(lookup_call,conf_);
      return (true);
   }
   return (false);
}

bool titax_conf_4tests_cfg_parse_networking(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      (void)zm(val_,val_s_); 
      CFG_PARSE_NETWORKING_(lookup_call,conf_);
      return (true);
   }
   return (false);
}

bool titax_conf_4tests_cfg_parse_filtering(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      char * val=val_;
      (void)zm(val,val_s_);
      CFG_PARSE_FILTERING_(lookup_call,conf_,val)
      return (true);
   }
   return (false);
}

bool titax_conf_4tests_cfg_parse_wada(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      char * val=val_;
      (void)zm(val,val_s_); 
      size_t l_=0;
      CFG_PARSE_WADA_(lookup_call,conf_,val,l_)
      return (true);
   }
   return (false);
}

bool titax_conf_4tests_cfg_parse_bp(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      (void)zm(val_,val_s_); 
      CFG_PARSE_BP_(lookup_call,conf_);
      return (true);
   }
   return (false);
}

bool titax_conf_4tests_cfg_parse_services(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      char * val=val_;
      (void)zm(val,val_s_); 
      CFG_PARSE_SERVICES_(lookup_call,conf_)
      return (true);
   }
   return (false);
}

bool titax_conf_4tests_cfg_parse_misc(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      char * val=val_;
      (void)zm(val_,val_s_); 
      size_t l_=0;
      CFG_PARSE_MISC_(lookup_call,conf_,val,l_)
      return (true);
   }
   return (false);
}

bool titax_conf_4tests_cfg_parse_db_cstr(t_StringList_lookup_call * const restrict lookup_call,TitaxConf* const restrict conf_){
   if (conf_ && lookup_call){
      (void)zm(val_,val_s_); 
      CFG_PARSE_DB_CSTR_(lookup_call,conf_);
      return (true);
   }
   return (false);
}

void titax_conf_4tests_print_all_NL(TitaxConf* const restrict conf_){
   titax_conf_print_all_(conf_);
}

#endif
//---------------------------------------------------------------------

size_t titax_conf_get_backoff_limit(const bool uselocks){
   SAFE_GET_CONF_VALUE_(titax_backoff_limit,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_is_enable_auth(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(enable_auth,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_is_allow_ip(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(allow_ip,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_is_allow_ldap(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(allow_ldap,uselocks,0)
}
//---------------------------------------------------------------------
/* for kshield usage */
bool titax_conf_use_kshield(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(use_kshield,uselocks,0)
}
//---------------------------------------------------------------------
bool titax_conf_set_use_kshield(const bool v,const bool uselocks){
   SAFE_SET_CONF_VALUE_(use_kshield,v,uselocks,0)
}
//---------------------------------------------------------------------
bool titax_conf_is_enable_ntlm(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(enable_ntlm,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_is_ip_session(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(ip_session,uselocks,0)
}

//---------------------------------------------------------------------
size_t titax_conf_get_ip_session_ttl(const bool uselocks){
   SAFE_GET_CONF_VALUE_(ip_session_ttl,uselocks,MIN_IP_SESSION_TTL)
}

//---------------------------------------------------------------------
bool titax_conf_get_ac_ttl_slide(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(ac_ttl_slide,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_is_intercept_login(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(intercept_login,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_get_smtp_server(char * const restrict out, const size_t osz){
   TitaxConf* conf_=NULL;
   if ((conf_=g_titax_conf) || (conf_=titax_conf_get_instance())){ 
      size_t s;
      return DO_SAFE_ACTION_(
           out && osz && conf_->smtp_server &&
           (s=strlen(conf_->smtp_server)) &&  ((s>osz && (s=osz)) || (s)) &&
           tx_safe_memcpy(out,conf_->smtp_server,s) );
   }
   return (false);//on error
}

//---------------------------------------------------------------------
size_t titax_conf_get_smtp_backoff(const bool uselocks){
   SAFE_GET_CONF_VALUE_(smtp_backoff,uselocks,DEFAULT_BACKOFF)
}

//---------------------------------------------------------------------
bool titax_conf_get_transparentproxy(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(transparentproxy,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_get_least_restrictive(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(least_restrictive,uselocks,1)
}

//---------------------------------------------------------------------
bool titax_conf_is_avscan(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(avscan,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_get_avengine(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(avengine,uselocks,1)
}

//---------------------------------------------------------------------
size_t titax_conf_get_avlimit(const bool uselocks){
   SAFE_GET_CONF_VALUE_(avlimit,uselocks,DEF_AVLIMIT)
}

//---------------------------------------------------------------------
bool titax_conf_get_disable_filteronreq(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(disable_filteronreq,uselocks,0)
}

//---------------------------------------------------------------------
bool titax_conf_get_disable_filteronresp(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(disable_filteronresp,uselocks,0)
}
//---------------------------------------------------------------------
bool titax_conf_is_debug(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(debug,uselocks,false)
}
//---------------------------------------------------------------------
bool titax_conf_set_debug(const bool val, const bool uselocks){
   ttn_set_txdebug_state(val);
   SAFE_SET_CONF_VALUE_(debug,ttn_get_txdebug_state(),uselocks,false)
}
//---------------------------------------------------------------------
bool titax_conf_is_master(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(master,uselocks,false)
}
//---------------------------------------------------------------------
bool titax_conf_set_master(const bool val, const bool uselocks){
   SAFE_SET_CONF_VALUE_(master,val,uselocks,false)
}
//---------------------------------------------------------------------
bool titax_conf_get_disable_urldb(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(disable_urldb,uselocks,false)
}

//---------------------------------------------------------------------
bool titax_conf_set_disable_urldb(const bool val, const bool uselocks){
   SAFE_SET_CONF_VALUE_(disable_urldb,val,uselocks,false)
}
//---------------------------------------------------------------------
bool titax_conf_get_verbose(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(verbose,uselocks,false)
}
//---------------------------------------------------------------------
bool titax_conf_set_verbose(const bool val, const bool uselocks){
    ttn_set_verbose_state(val);
    SAFE_SET_CONF_VALUE_(verbose,ttn_get_verbose_state(),uselocks,false)
}
//---------------------------------------------------------------------
bool titax_conf_get_safesearch_disabled(const bool uselocks){
   SAFE_GET_CONF_BIT_VALUE_(safesearch_disabled,uselocks,false)
}
//---------------------------------------------------------------------
bool titax_conf_set_safesearch_disabled(const bool val, const bool uselocks){
   SAFE_SET_CONF_VALUE_(safesearch_disabled,val,uselocks,false)
}
//---------------------------------------------------------------------
void titax_conf_print_all_NL(){
   TitaxConf* conf_=NULL;
   if ((conf_=g_titax_conf) || (conf_=titax_conf_get_instance())){
      if (!titax_conf_get_verbose(true)) return;
      titax_conf_print_all_(conf_);
   }
}

bool titax_conf_svr_magid(ttn_md5 * const restrict md5_) {
   bool ret=false;
   TitaxConf* conf_=NULL;
   TITAX_CONF_LOCK();
   if (md5_ &&  ((conf_=g_titax_conf) || (conf_=titax_conf_get_instance()))){
      ttn_md5_clear(md5_);

      if (!conf_->svrmagidset){
         char tbuf[REQUEST_BYPASS_URL_MD5_TOKEN_SIZE + conf_->int_ip_4_len + 3+1];
         (void)zm(tbuf,sizeof(tbuf));
         tbuf[0]='-';
         (void)tx_safe_memcpy(tbuf+1,conf_->int_ip_4, conf_->int_ip_4_len);
         ttn_md5_clear(&conf_->svrmagid);
         assert(ttn_get_md5raw(tbuf,conf_->int_ip_4_len+1,&conf_->svrmagid));
         (void)ttn_md5_base16_encode(&conf_->svrmagid);
         conf_->svrmagidset = true;
      }
      tx_safe_memcpy(md5_,&conf_->svrmagid,sizeof(ttn_md5));
      ret=true;
   }
   TITAX_CONF_UNLOCK();
   return ret;
}

//---------------------------------------------------------------------
bool titax_reload_proxy_config(){
   return (titax_conf_read_proxy_conf_file());
}

//---------------------------------------------------------------------

bool titax_conf_read_proxy_conf_file(){
   bool ret=false;
   TITAX_CONF_LOCK();
   TitaxConf* const conf_=(g_titax_conf?g_titax_conf:titax_conf_get_instance());
   if (conf_){
      t_StringList_lookup_call lookup_call={.list=read_text_file(TTN_CF_FILE, 0)};
      const bool parsing_status=READ_PROXY_CONF_FILE_(&lookup_call,conf_);
      assert(parsing_status && "parsing has failed");
      (void)string_list_free(lookup_call.list);
      lookup_call.key=NULL;
      ret=true;
   }
   TITAX_CONF_UNLOCK();
   return ret;
}

//---------------------------------------------------------------------

//////////////////////////////////////////////////////////////////////////////////////////

#ifndef TTN_ATESTS
static 
#endif
bool tx_logger_daemon_parse_config( t_tx_logger_daemon_cfg * const restrict cfg,   
                                    t_StringList_lookup_call * const restrict lookup_call )
{
   if ( cfg ) { 

      zm( cfg, sizeof( t_tx_logger_daemon_cfg ) );

      if ( lookup_call && lookup_call->list && lookup_call->list->size ) {
         
         size_t l=0;

         cfg->batch_size = parse_uint_(   lookup_call,
                                          TX_LOGGER_DAEMON_CFG_BATCH_SIZE, 
                                          TX_LOGGER_DAEMON_CFG_BATCH_SIZE_SZ,
                                          TX_LOGGER_DAEMON_CFG_BATCH_SIZE_DEF_VAL   );

         cfg->batch_treshold_div = parse_uint_( lookup_call,
                                                TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD, 
                                                TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD_SZ,
                                                TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD_DEF_VAL  );

         cfg->delay_max = parse_uint_( lookup_call,
                                       TX_LOGGER_DAEMON_CFG_DELAY_MAX,
                                       TX_LOGGER_DAEMON_CFG_DELAY_MAX_SZ,
                                       TX_LOGGER_DAEMON_CFG_DELAY_MAX_DEF_VAL );

         cfg->delay = parse_uint_(  lookup_call,
                                    TX_LOGGER_DAEMON_CFG_DELAY,
                                    TX_LOGGER_DAEMON_CFG_DELAY_SZ,
                                    TX_LOGGER_DAEMON_CFG_DELAY_DEF_VAL);

         cfg->if_listen_on_any = parse_bool_(   lookup_call,
                                                TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY,
                                                TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY_SZ,
                                                TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY_DEF_VAL   );

         cfg->use_syslog = parse_bool_(   lookup_call,
                                          TX_LOGGER_DAEMON_CFG_USE_SYSLOG,
                                          TX_LOGGER_DAEMON_CFG_USE_SYSLOG_SZ,
                                          TX_LOGGER_DAEMON_CFG_USE_SYSLOG_DEV_VAL   );

         cfg->syslog_facility = (uint32_t)parse_uint_(   lookup_call,
                                                         TX_LOGGER_DAEMON_CFG_SYSLOG_FACILITY,
                                                         TX_LOGGER_DAEMON_CFG_SYSLOG_FACILITY_SZ,
                                                         TX_LOGGER_DAEMON_CFG_DEFAULT_SYSLOG_FACILITY );

         if (  cfg->syslog_facility > TX_LOGGER_DAEMON_CFG_MAX_SYSLOG_FACILITY ) { 

            cfg->syslog_facility=TX_LOGGER_DAEMON_CFG_DEFAULT_SYSLOG_FACILITY;
         }

         cfg->if_listen_port = parse_uint_(  lookup_call,
                                             TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT,
                                             TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT_SZ,
                                             TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT_DEF_VAL  );

         cfg->url_csz = parse_uint_(   lookup_call,
                                       TX_LOGGER_DAEMON_CFG_URL_CSZ,
                                       TX_LOGGER_DAEMON_CFG_URL_CSZ_SZ,
                                       TX_LOGGER_DAEMON_CFG_URL_CSZ_DEF_VAL   );

         cfg->n_batches_per_stats_write = (uint32_t ) parse_uint_(   lookup_call,
                                                                     TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS,
                                                                     TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS_SZ,
                                                                     TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS_DEFAULT   );
         
         cfg->log_only_blocked = parse_bool_(   lookup_call,
                                                TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED,
                                                TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED_SZ,
                                                TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED_DEF_VAL   );

         cfg->log_loc_stats = parse_bool_(   lookup_call,
                                             TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS,
                                             TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS_SZ,
                                             TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS_DEF_VAL   );

         cfg->log_groups = parse_bool_(   lookup_call,
                                             TX_LOGGER_DAEMON_CFG_LOG_GROUPS,
                                             TX_LOGGER_DAEMON_CFG_LOG_GROUPS_SZ,
                                             TX_LOGGER_DAEMON_CFG_LOG_GROUPS_DEF_VAL   );

         if ( parse_csa(   lookup_call, 
                           TX_LOGGER_DAEMON_CFG_PG_CSTR,
                           TX_LOGGER_DAEMON_CFG_PG_CSTR_SZ,
                           TX_LOGGER_DAEMON_CFG_PG_CSTR_DEF_VAL,
                           sizeof( TX_LOGGER_DAEMON_CFG_PG_CSTR_DEF_VAL ),
                           &l                                                 )  ) {
         
            strlcpy( cfg->traffic_pg_cstr, val_, MIN( sizeof( cfg->traffic_pg_cstr ), l+1 ) );
         }

         if ( parse_csa(   lookup_call, 
                           TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR, 
                           TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_SZ,
                           TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_DEF_VAL,
                           sizeof( TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_DEF_VAL ),
                           &l                                                 	)  ) {
         
            strlcpy( cfg->titax_pg_cstr, val_, MIN( sizeof( cfg->titax_pg_cstr), l+1 ) );
         }

      }
      else {

         cfg->batch_size =                TX_LOGGER_DAEMON_CFG_BATCH_SIZE_DEF_VAL;

         cfg->batch_treshold_div =        TX_LOGGER_DAEMON_CFG_BATCH_TRESHOLD_DEF_VAL;

         cfg->delay_max =                 TX_LOGGER_DAEMON_CFG_DELAY_MAX_DEF_VAL;

         cfg->delay =                     TX_LOGGER_DAEMON_CFG_DELAY_DEF_VAL;

         cfg->if_listen_on_any =          TX_LOGGER_DAEMON_CFG_IF_LISTEN_ON_ANY_DEF_VAL;

         cfg->if_listen_port =            TX_LOGGER_DAEMON_CFG_IF_LISTEN_PORT_DEF_VAL;

         cfg->use_syslog =                TX_LOGGER_DAEMON_CFG_USE_SYSLOG_DEV_VAL;

         cfg->syslog_facility =           TX_LOGGER_DAEMON_CFG_DEFAULT_SYSLOG_FACILITY;

         cfg->url_csz =                   TX_LOGGER_DAEMON_CFG_URL_CSZ_DEF_VAL;

         cfg->n_batches_per_stats_write = TX_LOGGER_DAEMON_CFG_N_BATCHES_PER_STATS_DEFAULT;

         cfg->log_only_blocked =          TX_LOGGER_DAEMON_CFG_LOG_ONLY_BLOCKED_DEF_VAL;

         cfg->log_loc_stats =             TX_LOGGER_DAEMON_CFG_LOG_LOC_STATS_DEF_VAL;  

         cfg->log_groups =                TX_LOGGER_DAEMON_CFG_LOG_GROUPS_DEF_VAL;

        strlcpy(    cfg->traffic_pg_cstr,
                    TX_LOGGER_DAEMON_CFG_PG_CSTR_DEF_VAL, 
                    MIN( sizeof( cfg->traffic_pg_cstr ), sizeof( TX_LOGGER_DAEMON_CFG_PG_CSTR_DEF_VAL ) )   );

        strlcpy(    cfg->titax_pg_cstr,
                    TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_DEF_VAL,
                    MIN( sizeof( cfg->titax_pg_cstr ), sizeof( TX_LOGGER_DAEMON_CFG_INFO_PG_CSTR_DEF_VAL ) )    );
      }
         
      return true;

   }

   return false;

}


bool tx_logger_daemon_read_conf_file( t_tx_logger_daemon_cfg * const restrict cfg )
{
    if (cfg) {

        t_StringList_lookup_call lookup_call={ .list = read_text_file( TX_LOGGER_DAEMON_DEFAULT_CONF_FILE, 0 ) };

        const bool ret=tx_logger_daemon_parse_config( cfg, &lookup_call );

        string_list_free(lookup_call.list);

        lookup_call.key=NULL;

        return ret;
   }

   return false;

}

