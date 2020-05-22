/*
 * $Id$
 *
 * Copyright (c) 2005-2014, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 *
 * The software contained herein is proprietary to and embodies the
 * confidential technology of Copperfasten Technologies, Teoranta.
 * Possession, use, duplication or dissemination of the software and
 * media is authorized only pursuant to a valid written license from
 * Copperfasten Technologies, Teoranta.
 */


#include "titaxlib.h"
#include "Category.h"
#include "Extension.h"
#include "Group.h"
#include "Keyword.h"
#include "MulKwMap.h"
#include "Redirection.h"
#include "TAPE.h"
#include "TitaxConf.h"
#include "TitaxUser.h"
#include "edgelib.h"
#include "edgepq.h"
#include "log.h"
#include "sock_rw.h"
#include "sqls.h"
#include "titaxtime.h"
#include "ttn_groups.hxx"
#include "wada_api.h"
#include <ctype.h>
#include <iconv.h>
#include <idna.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>
#include "ttn_groups.hxx"

//---------------------------------------------------------------------
static POLICY_FLAGS default_policy_flags = {};



//---------------------------------------------------------------------
// This structure defines the search engine names and associated bits
// it was created to convert the if then else but maybe that used to exist
// to a loop, which should make updates a little easier
struct safeS {
   const char * const   engine;
   const uint32_t       bit;
};

static const struct safeS SSengines[] = {
   {"google",  SSE_GOOGLE},
   {"yahoo",   SSE_YAHOO},
   {"bing",    SSE_BING},
   {"youtube", SSE_YT},
   {"",        0}
};

#define POLICY_TABLES_MAX 6

static const char* const   policy_tables[POLICY_TABLES_MAX] = {
   "policies", 
   "policyflags", 
   "policynonworkinghours", 
   "policynotifications", 
   "policysafesearch",
   "domain_policies"
};

//------------------------------------------------------------------

static size_t g_titax_backoff_limit = 0;
static  int g_logger_sock = INVALID_;


/* if has to be a macro as the method would overshadow the locking and TSA would complain */
#define add_extension_NL_( index_, ext_ ) __extension__ ({  \
         fileExtensionsClear( (index_) );                   \
         fileExtensionsLoad( (index_), (ext_),"\n");        \
})

//static char __urldb_tmp_r_buf[__urldb_tmp_r_buf_max]={0};
/////////////////////////////////////////////////////////////////////////////////////////////////
static bool titax_load_locations_( PGconn* const );
static bool titax_reload_tokens_( PGconn* const );
static bool titax_load_groups_for_user( PGconn* const, user_id_t, TitaxUser* );
static bool titax_load_top_users( PGconn* const );
static bool titax_load_urlcategories_custom_( PGconn * const ); //REDUNDANT!!!!!
static bool titax_load_urlcategories_( PGconn*const );
static bool titax_load_networking_( PGconn*const );
static void titax_load_authpolicy_( PGconn*const );
static int get_svr_sock_( const int, const int, const int );
static void* titax_intercept_login_manager_( void* );
static void titax_intercept_login_manager_serv_( const  int,  const struct sockaddr_in * const );
static void* titax_uniq_ip_remove_thread_( void* );
static void* titax_data_update_thread_( void* );
static void* titax_icap_timer_thread_( void* );
static void* titax_icap_data_update_thread_( void* );
static void init_all_shared_( PGconn* const );
static void init_all_( PGconn* const );
static bool load_policies_( PGconn* const, POLICY** const, size_t * const );

bool titax_load_keyword_policies_( PGconn* const );
extern void add_user_to_cache( TitaxUser* );
extern bool set_list_type( const uint32_t ) ;
void update_tokens_count( size_t, size_t );
void reset_users_bw( void );
extern void clean_users( void );
extern void user_cache_reserve(const size_t);
extern void user_cache_rehash(const size_t);

static int is_icap = 0;

///////////////////////////////////////////////////////////////////////////////
//    HOT
TX_INTERNAL_INLINE
void get_update_times_( PGconn* const restrict db, 
                        StringMap* const restrict map   )
{

   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_UPDATE_TIMES);

   if (rset){

      const uint_fast64_t max_=txpq_row_count(rset);

      for (uint_fast64_t i_=0; i_<max_; i_++){

         char* tname_ = txpq_cv_str(rset, i_, 0);
         char* mtime_ = txpq_cv_str(rset, i_, 1);

         if ( tname_ && mtime_ ){

            string_map_add(map, tname_, mtime_);
         }

      }

      txpq_reset(rset);
   }

}

TX_INTERNAL_INLINE
bool is_updated_table_( StringMap* const restrict old_map,
                        StringMap* const restrict new_map,
                        const char* const restrict kw       )
{
   char old_time[24]={};
   char new_time[24]={};

   (void)string_map_val(old_map, kw, old_time,sizeof(old_time));

   (void)string_map_val(new_map, kw, new_time,sizeof(new_time));

   if(strcmp(new_time, old_time) != 0) {

      (void)string_map_add(old_map, kw, new_time);

      return true;
   }

   return false;
}

struct is_policy_updated_elems_{uint_fast64_t i_; size_t policy_tables_len_; bool res_; const char *const* pt_;};
TX_INTERNAL_INLINE
bool is_policy_updated_(StringMap* const restrict old_map, StringMap* const restrict  new_map) {
   struct is_policy_updated_elems_ e={
      .policy_tables_len_=POLICY_TABLES_MAX,
      .pt_=policy_tables
   };
   for (;e.i_<e.policy_tables_len_;(UWITHIN_(POLICY_TABLES_MAX,e.i_) && is_updated_table_(old_map, new_map, e.pt_[e.i_]) && (e.res_ = true)),++e.i_);
   return (e.res_);
}

TX_INTERNAL_INLINE
int titax_load_filtering_(PGconn* const restrict db) 
{

   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_FILTERING);

   int success = 0;

   if ( rset ) {

      if ( txpq_row_count(rset) ) {

         bool avscan = txpq_cv_bool(rset, 0, 0);
         //avengine = txpq_cv_str(rset, 0, 1);
         size_t avlimit = txpq_cv_uint(rset, 0, 2);
         char * audioext = txpq_cv_str(rset, 0, 3);

         char * videoext = txpq_cv_str(rset, 0, 4);
         char * exeext = txpq_cv_str(rset, 0, 5);
         char * imgext = txpq_cv_str(rset, 0, 6);
         char * docext = txpq_cv_str(rset, 0, 7);

         char * archext = txpq_cv_str(rset, 0, 8);
         char * udext = txpq_cv_str(rset, 0, 9);
         bool leastrestrict = txpq_cv_bool(rset, 0, 10);
         bool disable_filteronreq = txpq_cv_bool(rset, 0, 11);

         bool disable_filteronresp = txpq_cv_bool(rset, 0, 12);

         // File extensions.

         file_ext_wr_lock();
         add_extension_NL_(ttn_ext_aud, audioext);
         add_extension_NL_(ttn_ext_vid, videoext);
         add_extension_NL_(ttn_ext_exe, exeext);
         add_extension_NL_(ttn_ext_img, imgext);
         add_extension_NL_(ttn_ext_txt, docext);
         add_extension_NL_(ttn_ext_arc, archext);
         add_extension_NL_(ttn_ext_usr, udext);
         file_ext_wr_unlock();

         TitaxConf* const titax_conf = titax_conf_get_instance();

         if ( titax_conf ) {

            TITAX_CONF_LOCK();
            titax_conf->avscan = avscan;
            titax_conf->avengine = 1;  // Always CLAM.
            titax_conf->avlimit = avlimit;
            titax_conf->least_restrictive  = leastrestrict;
            titax_conf->disable_filteronreq = disable_filteronreq; //??
            titax_conf->disable_filteronresp = disable_filteronresp; //??
            (void)((titax_conf->avlimit >= MAX_AVLIMIT) && (titax_conf->avlimit = MAX_AVLIMIT));
            TITAX_CONF_UNLOCK();

            success = 1;

         } else {

            titax_log(LOG_ERROR, "%s :: %d failed!\n",__func__, __LINE__);
            exit(INVALID_);
         }
      }
      txpq_reset(rset);
   }

   return success;

}

struct load_groups_elems_{uint_fast64_t i_; const uint_fast64_t max_; GROUP *const group_list;};
TX_INTERNAL_INLINE
int load_groups_( PGconn* const restrict db,
                  GROUP** const restrict p_group_list, 
                  size_t * const restrict p_group_count  )
{
   /* Count groups &  Allocate memory */

   if ( db && p_group_list && p_group_count ) {

      PGresult * const rset = pq_get_rset( db, TITAXLIB_QS_T_GROUPS );

      if (  rset &&
            ( ( *p_group_count ) = txpq_row_count( rset ) ) && 
            ( ( *p_group_list ) = ( GROUP* )tx_safe_calloc( ( *p_group_count ), sizeof( GROUP ) ) )      ) {

         struct load_groups_elems_ e = {  .max_ = ( *p_group_count ),
                                          .group_list = ( *p_group_list )  };

         //load & some defaults (everything else is already zeroed)
         for ( e.i_=0; e.i_<e.max_; ++e.i_ ) {

            e.group_list[ e.i_ ].groupNumber = txpq_cv_int( rset, e.i_, 0 );
            e.group_list[ e.i_ ].permanent = txpq_cv_int( rset, e.i_, 1 );
            e.group_list[ e.i_ ].hide = txpq_cv_int( rset, e.i_, 2 );
            strlcpy( e.group_list[ e.i_ ].name, 
                     txpq_cv_str( rset, e.i_, 3 ),
                     sizeof( e.group_list[ e.i_ ].name ) );

         }

         txpq_reset( rset );
         return 1;
      }

      if ( rset )
         txpq_reset( rset );
   }

   return 0;
}

TX_INTERNAL_INLINE
bool titax_load_groups_(PGconn* const restrict  db) TSA_CAP_TR_RQ(sGroupMutex)
{
   if (db){
      /* Load groups */
      size_t group_count = 0;
      GROUP* group_list = NULL;

      size_t policy_count = 0;
      POLICY* policy_list = NULL;

      int debug_mode=titax_conf_is_debug(true);
      if(debug_mode) {
         (void)puts("Trying to load groups.");
      }

      if(!load_groups_(db, &group_list, &group_count)) {
         if(debug_mode) {
            (void)puts("load_groups_ failed!");
         }
         return false;
      }

      /* Load policies */
      if(!load_policies_(db, &policy_list, &policy_count)) {
         tx_safe_free(group_list);
         group_list = NULL;
         group_count = 0;

         tx_safe_free(policy_list);
         policy_list = NULL;
         policy_count = 0;

         if(debug_mode) {
            (void)puts("load_policies_ failed!");
         }

         return false;
      }
      /* Replace group table with the new one */
      replaceGroupPolicyTables(group_list, group_count, policy_list, policy_count);
      checkAccessTimes();

      return true;
   }
   return false;
}

static 
bool TS_TITAX_LOAD_GROUPS_( PGconn* const restrict  db )
{
   bool r = false;
   {
      LOCKGROUPTABLE();

      r = titax_load_groups_(db);

      UNLOCKGROUPTABLE();
   }
   return r;
}

struct titax_load_keywords_elems_ {size_t i_; const size_t max_;char * kw_;}; 
TX_INTERNAL_INLINE
int titax_load_keywords_(PGconn* const restrict  db) 
{
   
   if (db){
      PGresult* const rset=pq_get_rset(db, TITAXLIB_QS_T_KEYWORDS);
      if (rset){
         // LOCK keywords table to prevent any reads while we're
         // building it
         KEYWORDSLOCK();

         /* Destroy existing data */
         keywordsDestroy();

         //CHANGE: removed/disabled mul_kw_map    
         // Get keyword - score map for multi-bytes words.
         (void)mul_kw_map_get_instance();

         mul_kw_map_lock();

         mul_kw_map_clear();

         size_t current_len = 100;
         char* kw_ = NULL;
         if (!is_icap) {
             kw_ = malloc(current_len);
         }

         for(struct titax_load_keywords_elems_ e={
            .max_=(size_t)txpq_row_count(rset)
         }; e.i_<e.max_; ++e.i_) {
            /* 
             * Handling of MB Keywords:
             * see WT-127, for now we will filter out any MBK
             * It was 127 but I changed it to be 126 to avoid of warning message.
             */
            //if(e.kw_ && e.kw_[0] && (e.kw_[0] < 0 || e.kw_[0] > 126)) {
            char* rw_ = txpq_cv_str(rset, e.i_, 0);
            if (rw_ && rw_[0]) {
               if (kw_ != NULL) {
                  size_t kw_len = strlen(rw_) + 1;
                  if (kw_len > current_len) {
                     free(kw_);
                     current_len = kw_len;
                     kw_ = malloc(current_len);
                  }

                  strncpy(kw_, rw_, current_len);
                  e.kw_ = kw_ + kw_len - 2;
                  while (e.kw_ >= kw_ && *e.kw_ == ' ') {
                      *e.kw_ = 0;
                      --e.kw_;
                  }
                  e.kw_ = kw_;
                  while (*e.kw_ == ' ') ++e.kw_;
               }
               else {
                  e.kw_ = rw_;
               }

               if (isascii(e.kw_[0])) {
                   keywordAdd(e.kw_, (uint32_t)txpq_cv_uint(rset, e.i_, 1));
               }
               else {
                   mul_kw_map_add(e.kw_,txpq_cv_int(rset, e.i_, 1));
               }
            }
         }

         if (kw_ != NULL) {
            free(kw_);
         }

         mul_kw_map_unlock();

         KEYWORDSUNLOCK();

         txpq_reset(rset);

         return 1;
      }
   }
   return 0;
}


TX_INTERNAL_INLINE
bool titax_load_user_dic_(PGconn* const restrict  db)
{

   if ( db ) {
      // Init g_titax_user_dic.
      // Don't need to init here.
      if(!titax_load_top_users(db)) {
         (void)puts("titax_load_users failed!");
         return false;
      }

      if(!titax_load_locations_(db)) {
         (void)puts("titax_load_userlogins failed!");
         return false;
      }

      if(!titax_reload_tokens_(db)) {
         (void)puts("titax_reload_tokens_ failed!");
         return false;
      }

      wada_api_t * const wapi = gtape_wada_api();

      if ( wapi ) {

         wapi->reload_from_files();

      }

      return true;

   }
   return false;
}

TX_INTERNAL_INLINE
void set_system_categories_(POLICY* const restrict policy, const char* const  restrict catwork, const char* const restrict  catnonwork, const char* const restrict catnotify) {
   if(catwork != NULL) {
      const size_t len =strlen(catwork);
      for(uint_fast64_t i = 0; i < DEFINED_TITAX_CATEGORIES; ++i) {
         if ((policy->categoryTable[i].allowWorking=!((i >= len) || (catwork[i] == 'N') || (catwork[i] == 'n')))){
            policy->workingHoursMask=(i?(policy->workingHoursMask | (t_mask)(1ULL<<i)):1);
         }
      }
   }

   if(catnonwork != NULL) {
      const size_t len = strlen(catnonwork);
      for(uint_fast64_t i = 0; i < DEFINED_TITAX_CATEGORIES; ++i) {
         if ((policy->categoryTable[i].allowNonWorking=!((i >= len) || (catnonwork[i] == 'N') || (catnonwork[i] == 'n')))){
            policy->nonWorkingHoursMask=(i?( policy->nonWorkingHoursMask | (t_mask)(1ULL<<i)):1);
            }
      }
   }

   if(catnotify != NULL) {
      const size_t len = strlen(catnotify);
      for(uint_fast64_t i = 0; i < DEFINED_TITAX_CATEGORIES; ++i) {
         if ((policy->categoryTable[i].notify=!((i >= len) || (catnotify[i] == 'N') || (catnotify[i] == 'n')))){
            policy->notifyCategoryMask |=  (t_mask)(1ULL<<i);
         }
      }
   }
}

TX_INTERNAL_INLINE
void set_custom_categories_(POLICY* const restrict policy, const char* const restrict  catwork, const char* const restrict catnonwork, const char* const restrict  catnotify) {
   if(catwork != NULL) {
      const size_t len = strlen(catwork);
      for(uint_fast64_t i = 0; i < DEFINED_TITAX_CATEGORIES; ++i) {
         if ((policy->custom_categoryTable[i].allowWorking=!((i >= len) || (catwork[i] == 'N') || (catwork[i] == 'n')))){
            policy->custom_workingHoursMask=(i?(policy->custom_workingHoursMask|(t_mask)(1ULL<<i)):1);
            }
      }
   }

   if(catnonwork != NULL) {
      const size_t len = strlen(catnonwork);
      for(uint_fast64_t i = 0; i < DEFINED_TITAX_CATEGORIES; ++i) {
         if ((policy->custom_categoryTable[i].allowNonWorking=!((i >= len) || (catnonwork[i] == 'N') || (catnonwork[i] == 'n')))){
            policy->custom_nonWorkingHoursMask=(i?(policy->custom_nonWorkingHoursMask |(t_mask)(1ULL<<i)):1);
            }
      }
   }

   if(catnotify != NULL) {
      const size_t len = strlen(catnotify);
      for(uint_fast64_t i = 0; i < DEFINED_TITAX_CATEGORIES; ++i) {
         if ((policy->custom_categoryTable[i].notify=!((i >= len) || (catnotify[i] == 'N') || (catnotify[i] == 'n')))){
            policy->custom_notifyCategoryMask |=  (t_mask)(1ULL<<i);
         }
      }
   }
}

TX_INTERNAL_INLINE
int add_nonworking_time_(POLICY* const restrict  policy, const size_t daysofweek,const  size_t start, const size_t end) {
   if (policy){
      policy->nonWorkingHours.periods = (policy->nonWorkingHours.periodCount
      ?
         tx_safe_realloc_ex(policy->nonWorkingHours.periods,(policy->nonWorkingHours.periodCount * sizeof(NONWORKING_PERIOD)),((1+policy->nonWorkingHours.periodCount) * sizeof(NONWORKING_PERIOD)))
      :
         tx_safe_realloc_ex(policy->nonWorkingHours.periods,0,((1+policy->nonWorkingHours.periodCount) * sizeof(NONWORKING_PERIOD)))
      );      
      ++policy->nonWorkingHours.periodCount;
      if(NULL == policy->nonWorkingHours.periods) return 0;

      policy->nonWorkingHours.periods[policy->nonWorkingHours.periodCount-1].daysOfWeek = daysofweek;
      policy->nonWorkingHours.periods[policy->nonWorkingHours.periodCount-1].start = start;
      policy->nonWorkingHours.periods[policy->nonWorkingHours.periodCount-1].end = end;
      return 1;
   }
   return 0;
}

#ifndef load_required_field
#define load_required_field( FIELD, RSET, RN, ID ) __extension__ ({        \
   char * const _value_##ID = txpq_cv_str( (RSET), (RN), (ID) );           \
   bool _success_##ID = false;                                             \
   if ( _value_##ID && *_value_##ID ) {                                    \
                                                                           \
      strlcpy( (FIELD), _value_##ID, sizeof( (FIELD) ) );                  \
      _success_##ID = true;                                                \
   }                                                                       \
   else {                                                                  \
                                                                           \
      titax_log(  LOG_ERROR,                                               \
                  "%s:%d :: unable to load data for the required field "   \
                  "[%s] from recno %zu requested by tid %d \n",            \
                  __func__,                                                \
                  __LINE__,                                                \
                  STR(FIELD),                                              \
                  (RN),                                                    \
                  tx_gettid()                                           ); \
                                                                           \
   }                                                                       \
   (_success_##ID);                                                        \
})
#endif /* load_required_field */

#ifndef load_opt_field
#define load_opt_field( FIELD, RSET, RN, ID ) {                            \
   char * const _value_##ID = txpq_cv_str( (RSET), (RN), (ID) );           \
   if ( _value_##ID && *_value_##ID ) {                                    \
                                                                           \
      strlcpy( (FIELD), _value_##ID, sizeof( (FIELD) ) );                  \
   }                                                                       \
}
#endif /* load_opt_field */

TX_INTERNAL_INLINE
bool load_user_(  PGresult * const restrict rset, 
                  const uint_fast64_t recno,
                  TitaxUser * const restrict out_user   )
{

   if (  rset                                &&

         out_user                            &&

         txpq_is_row_in_rset( rset, recno )     ) {

      /* req */
      if ( txpq_is_null( rset, recno,  0 ) ) {

         titax_log(  LOG_WARNING,
                     "%s:%d :: unable to successfully load user's id from recno %zu"\
                     " requested by tid %d - so this record is ommited\n",
                     __func__,
                     __LINE__,
                     recno,
                     tx_gettid()                                                       );

         return false;
      }

      TitaxUser user = {   .id =  txpq_cv_ulong( rset, recno, 0 ),

                           .TXTokens_Count = txpq_cv_ulong( rset, recno, 5 )  };

      if (  ! load_required_field( user.name, rset, recno, 1 )    ||

            ! load_required_field( user.md5val, rset, recno, 4 )     ) {

         return false;
      }

      load_opt_field( user.fullname, rset, recno, 2 )

      /* opt - domain */
      char * value = txpq_cv_str( rset, recno, 3 );

      if ( value && *value ) {

         const uint_fast64_t len_used = strlen( user.name );

         if ( len_used + strlen(value) + 2 < sizeof( user.name ) ) {

            strlcat( user.name, "@" ,sizeof( user.name ) );

            strlcat( user.name, value ,sizeof( user.name ) );

         } 
         else {

            titax_log(  LOG_WARNING,
                        "%s:%d :: unable to successfully convert the user name into"\
                        " the UPN format [ %s :: %s ] from recno %zu"\
                        " requested by tid %d\n",
                        __func__,
                        __LINE__,
                        user.name,
                        (value ?: "<NULL>"),
                        recno,
                        tx_gettid()                                                       );
         }

      }

      /* parent / child */
      if ( !txpq_is_null( rset, recno,  6 ) ) {

         user.parent_id = txpq_cv_ulong( rset, recno, 6 ); 

         user.parent_valid = true;
      }
      else {

         load_opt_field( user.lic_no, rset, recno, 7 )

         user.default_user = txpq_cv_bool( rset, recno, 9 );
      }

      char uuid_str[GUID_STR_SZ+1] = {};

      load_opt_field( uuid_str, rset, recno, 8 )

      /* opt - uuid */
      if (  uuid_str[0]                                     &&

            ! ttn_uuid_str2uuid_int( &user.uuid, uuid_str )    ) {

            titax_log(  LOG_WARNING,
                        "%s:%d :: unable to successfully convert the uuid_str into"\
                        " the uuid [ %s :: %s ] from recno %zu"\
                        " requested by tid %d\n",
                        __func__,
                        __LINE__,
                        user.name,
                        uuid_str,
                        recno,
                        tx_gettid()                                                    );
      }

      tx_safe_memcpy( out_user, &user, sizeof(TitaxUser) );

      return ( out_user->id == user.id ) ;
   }

   return false;
}

////////////////////////////////////////////////////////////////////////////////

void init_all_shared_(PGconn* const restrict db){
   
   // filtering.
   if(!titax_load_filtering_(db)) {
      titax_log(LOG_ERROR, "titax_load_filtering_ failed.\n");
      exit(INVALID_);
   }

   // group.
   if(!TS_TITAX_LOAD_GROUPS_(db)) {
      titax_log(LOG_ERROR, "titax_load_groups_ failed.\n");
      exit(INVALID_);
   }

   // keyword.
   if(!titax_load_keywords_(db)) {
      titax_log(LOG_ERROR, "titax_load_keywords_ failed.\n");
      exit(INVALID_);
   }
}

void init_all_(PGconn* const restrict db){
   
   // Init bandwidth usage info map.
   init_all_shared_(db); 
   
   // authpolicy.
   titax_load_authpolicy_(db);
   
   // networking.
   if(!titax_load_networking_(db)) {
      titax_log(LOG_ERROR, "titax_load_networking_ failed.\n");
      exit(INVALID_);
   }

   // category.
   if(!titax_load_urlcategories_(db)) {
      titax_log(LOG_ERROR, "titax_load_urlcategories_ failed.\n");
      exit(INVALID_);
   }

   //REDUNDANT
   if(!titax_load_urlcategories_custom_(db)) {
      titax_log(LOG_ERROR, "titax_load_urlcategories_custom_ failed.\n");
      exit(INVALID_);
   }

   // redirections.
   if(!redirections_reload(db)) {
      titax_log(LOG_ERROR, "redirections_reload failed.\n");
      exit(INVALID_);
   } 

   // keyword policies.
   if(!titax_load_keyword_policies_(db)) {
      titax_log(LOG_ERROR, "titax_load_keyword_policies_ failed.\n");
      exit(INVALID_);
   }

   // user.
   if(!titax_load_user_dic_(db)) {
      titax_log(LOG_ERROR, "titax_load_user_dic_ failed.\n");
      exit(INVALID_);
   }
}

//---------------------------------------------------------------------
struct load_policies_categories_elems_{uint_fast64_t k_; const uint_fast64_t max_;  PGresult* const rset_; POLICY *const policy_list;};
TX_INTERNAL_INLINE
int load_policies_categories_(PGconn* const restrict db, POLICY** const restrict p_policy_list, size_t * const restrict  p_policy_count){

   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_POLICIES);
   if (rset && ((*p_policy_count) = txpq_row_count(rset)) > 0){

      *p_policy_list = (POLICY*)tx_safe_calloc( (*p_policy_count), sizeof(POLICY) );

      for (struct load_policies_categories_elems_ e={
         .max_=(*p_policy_count),
         .rset_=rset,
         .policy_list=(*p_policy_list)
      };e.k_<e.max_;++e.k_){
         e.policy_list[e.k_].policyId = txpq_cv_int(e.rset_, e.k_, 0);
         const char * const name=txpq_cv_str(e.rset_, e.k_,2 );
         if (!name){
            txpq_reset(rset);
            titax_log(LOG_ERROR, "[load_policies_categories_]:required field name is null");
            return 0;
         }
         strlcpy(e.policy_list[e.k_].name,name,MAX_POLICY_NAME);

         (void)tx_safe_memcpy(&(e.policy_list[e.k_].flags),&default_policy_flags,sizeof(POLICY_FLAGS));

         set_system_categories_(&e.policy_list[e.k_], txpq_cv_str(e.rset_, e.k_, 3), txpq_cv_str(e.rset_, e.k_, 4), txpq_cv_str(e.rset_, e.k_, 5));
         set_custom_categories_(&e.policy_list[e.k_], txpq_cv_str(e.rset_, e.k_, 6), txpq_cv_str(e.rset_, e.k_, 7), txpq_cv_str(e.rset_, e.k_, 8));

         tx_safe_free(e.policy_list[e.k_].emailNotify);
         e.policy_list[e.k_].emailNotify = str_dup(txpq_cv_str(e.rset_, e.k_, 9));

         e.policy_list[e.k_].flags.inWorkingDay = true;
         e.policy_list[e.k_].nonWorkingHours.periods = 0;
      }
      txpq_reset(rset);
      return 1; 
   }
   if (rset)
       txpq_reset(rset);
   return 0;
}


struct load_policies_working_hours_elems_{uint_fast64_t k_; const uint_fast64_t max_;  PGresult* const rset_; 
      struct {
         int            policyId;
         char*          temp;
         size_t         daysofweek;
         size_t         start;
         size_t         end;
         size_t         hour;
         size_t         minute;
   } fields_;POLICY* in_policies;POLICY * policy;};

TX_INTERNAL_INLINE
int load_policies_working_hours_(PGconn* const restrict  db, POLICY* const restrict   policy_list, const size_t policy_count){
   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_POLICYNONWORKINGHOURS);
   if (rset){
      for (struct load_policies_working_hours_elems_ e={
         .max_=txpq_row_count(rset),
         .rset_=rset
      };e.k_<e.max_;++e.k_){
         //XXX:FIXED:reuse old values or null
         //variables like the "daysofweek", "start" and  "end"  were never set to zero (reset) so values from previous iteration were used
         //tmp variable could be null
         struct load_policies_working_hours_elems_ se={
            .max_=policy_count,
            .fields_={
            .policyId = txpq_cv_int(e.rset_, e.k_, 0),
            .daysofweek=(((e.fields_.temp = txpq_cv_str(e.rset_, e.k_, 1)) && strlen(e.fields_.temp) == 7)?
               ((e.fields_.temp[0] != '0' ? 1U << 0 : 0)
               | (e.fields_.temp[1] != '0' ? 1U << 1 : 0)
               | (e.fields_.temp[2] != '0' ? 1U << 2 : 0)
               | (e.fields_.temp[3] != '0' ? 1U << 3 : 0)
               | (e.fields_.temp[4] != '0' ? 1U << 4 : 0)
               | (e.fields_.temp[5] != '0' ? 1U << 5 : 0)
               | (e.fields_.temp[6] != '0' ? 1U << 6 : 0))
               : 0),
            .hour=0,
            .minute=0,
            .start=0,
            .end=0
         },.in_policies=policy_list};
         //confirm with older version 

         /* 
          * We could use the sscanf_s (or equivalent) here if and when the FreeBSD adds support for it.
          * But in this case, it is not as beneficial as advertised as there is no string handling here.
          */

         if((se.fields_.temp = txpq_cv_str(e.rset_, e.k_, 2)) && 2 == sscanf(se.fields_.temp, "%zu:%zu", &se.fields_.hour, &se.fields_.minute)) {
            se.fields_.start = (se.fields_.hour * 60) + se.fields_.minute;
         }

         if((se.fields_.temp = txpq_cv_str(e.rset_, e.k_, 3)) && 2 == sscanf(se.fields_.temp, "%zu:%zu", &se.fields_.hour, &se.fields_.minute)) {
            se.fields_.end = (se.fields_.hour * 60) + se.fields_.minute;
         }

         for (; se.k_<se.max_;++se.k_){
            if ((se.policy=&se.in_policies[se.k_])->policyId==se.fields_.policyId){
               if (se.fields_.start == se.fields_.end){
                  /* All day is playtime */
                  (void)add_nonworking_time_(se.policy, se.fields_.daysofweek, 0, 24 * 60);
               }else if (se.fields_.start < se.fields_.end) {
                  /* Add nonworking period(s) to group */
                  (void)add_nonworking_time_(se.policy, se.fields_.daysofweek, se.fields_.start, se.fields_.end);
               } else {
                  /* something like Non-working time is 1700-0900
                   * for simpler check later, add two records:
                   * 0000-end and start-2400, so above would be
                   * 0000-0900 and 1700-2400
                   */
                  (void)add_nonworking_time_(se.policy, se.fields_.daysofweek, 0, se.fields_.end);
                  (void)add_nonworking_time_(se.policy, se.fields_.daysofweek, se.fields_.start, 24*60);
               }
            }
         }
      }
      txpq_reset(rset);
      return 1;
   }
   return 0;
}


struct load_policies_flags_elems_{uint_fast64_t k_; const uint_fast64_t max_;  PGresult* const rset_; 
      struct {
      int policyId;
      char* temp;
} fields_;POLICY* in_policies;POLICY * policy;};

TX_INTERNAL_INLINE
int load_policies_flags_(PGconn* const restrict db, POLICY* const restrict policy_list, const size_t policy_count){
 
   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_POLICYFLAGS);
   if (rset){
      for (struct load_policies_flags_elems_ e={
         .max_=txpq_row_count(rset),
         .rset_=rset
      };e.k_<e.max_;++e.k_){
         for (struct load_policies_flags_elems_ se={
            .max_=policy_count,
            .fields_.policyId=txpq_cv_int(e.rset_, e.k_, 0),
            .in_policies=policy_list
         };se.k_<se.max_;++se.k_){
            if ((se.policy=&se.in_policies[se.k_])->policyId==se.fields_.policyId){
               se.policy->flags.filterEnabled = txpq_cv_bool(e.rset_, e.k_, 1);
               se.policy->flags.onlyAllowSpecified = txpq_cv_bool(e.rset_, e.k_, 2);
               se.policy->flags.blockAll = txpq_cv_bool(e.rset_, e.k_, 3);
               se.policy->flags.blockAudioFiles = txpq_cv_bool(e.rset_, e.k_, 4);
               se.policy->flags.blockVideoFiles = txpq_cv_bool(e.rset_, e.k_, 5);
               se.policy->flags.blockExeFiles = txpq_cv_bool(e.rset_, e.k_, 6);
               se.policy->flags.blockImageFiles = txpq_cv_bool(e.rset_, e.k_, 7);
               se.policy->flags.blockTextFiles = txpq_cv_bool(e.rset_, e.k_, 8);
               se.policy->flags.blockArchiveFiles = txpq_cv_bool(e.rset_, e.k_, 9);
               se.policy->flags.blockUserDefinedFiles = txpq_cv_bool(e.rset_, e.k_, 10);
               se.policy->flags.logOnlyGroupName = txpq_cv_bool(e.rset_, e.k_, 11);
               se.policy->flags.urlKeywordEnabled = txpq_cv_bool(e.rset_, e.k_, 12);
               se.policy->flags.urlThreshold = (uint32_t)txpq_cv_int(e.rset_, e.k_, 13);
               se.policy->flags.textKeywordEnabled = txpq_cv_bool(e.rset_, e.k_, 14);
               se.policy->flags.pageThreshold = (uint32_t)txpq_cv_int(e.rset_, e.k_, 15);
               se.policy->flags.sizeKeywordEnabled = txpq_cv_bool(e.rset_, e.k_, 16);
               se.policy->flags.pagesizeThreshold = (uint64_t)txpq_cv_long(e.rset_, e.k_, 17);
               se.policy->flags.blockIPAddressURLs = txpq_cv_bool(e.rset_, e.k_, 18);
               se.policy->flags.dontBlockOnKeywords =txpq_cv_bool(e.rset_, e.k_, 19);
               se.policy->flags.blockOtherWorkingHours = txpq_cv_bool(e.rset_, e.k_, 20);
               se.policy->flags.blockOtherNonWorkingHours = txpq_cv_bool(e.rset_, e.k_, 21);
               se.policy->flags.blockOtherHTTPSWorkingHours = txpq_cv_bool(e.rset_, e.k_, 22);
               se.policy->flags.blockOtherHTTPSNonWorkingHours = txpq_cv_bool(e.rset_, e.k_, 23);
               se.policy->flags.blockHTTPSWorkingHours = txpq_cv_bool(e.rset_, e.k_, 24);
               se.policy->flags.blockHTTPSNonWorkingHours = txpq_cv_bool(e.rset_, e.k_, 25);
               se.policy->flags.sinBin = txpq_cv_bool(e.rset_, e.k_, 26);
               // We don't have httpsBlocked column in the table.
               se.policy->flags.httpsBlocked = 0;
               se.policy->flags.safeSearch=SAFESEARCH_OFF;
               if ((se.fields_.temp=txpq_cv_str(e.rset_, e.k_, 27))){
                  if(strcmp(se.fields_.temp,"SAFESEARCH_OFF") == 0) {
                     se.policy->flags.safeSearch = SAFESEARCH_OFF;
                  } else if(strcmp(se.fields_.temp,"SAFESEARCH_ON") == 0) {
                     se.policy->flags.safeSearch = SAFESEARCH_ON;
                  } else if(strcmp(se.fields_.temp,"SAFESEARCH_CUSTOM") == 0) {
                     se.policy->flags.safeSearch = SAFESEARCH_CUSTOM;
                  }
               }
               se.policy->flags.mbThreshold =txpq_cv_ulong(e.rset_, e.k_, 28);
               se.policy->flags.TXTokens_Show_Message=(txpq_cv_int(e.rset_, e.k_,29)>0?1:0);
            }
         }
      }
      txpq_reset(rset);
      return 1;
   }
   return 0;
}

struct load_policies_notifications_elems_{uint_fast64_t k_; const uint_fast64_t max_;  PGresult* const rset_; 
      struct {
      uint32 flag; // the bitmap version of the flags
      int policyId;
      int notificationId;
   } fields_;POLICY* in_policies;POLICY * policy;};

TX_INTERNAL_INLINE
bool load_policies_notifications_(PGconn* const restrict db, POLICY* const restrict policy_list, const size_t policy_count){
   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_POLICYNOTIFICATIONS);
   if (rset){
      for (struct load_policies_notifications_elems_ e={
         .max_=txpq_row_count(rset),
         .rset_=rset
      };e.k_<e.max_;++e.k_){
         e.fields_.policyId = txpq_cv_int(e.rset_, e.k_, 0);
         e.fields_.notificationId = txpq_cv_int(e.rset_, e.k_, 1);
         e.fields_.flag |= 1<< e.fields_.notificationId;
         if(e.k_ == e.max_-1 || e.fields_.policyId != txpq_cv_int(e.rset_, e.k_+ 1, 0)) {
            for (struct load_policies_notifications_elems_ se={
               .max_=policy_count,
               .fields_.policyId=e.fields_.policyId,
               .fields_.flag=e.fields_.flag,
               .in_policies=policy_list
            };se.k_<se.max_;++se.k_)(void)((se.policy=&se.in_policies[se.k_])->policyId==se.fields_.policyId &&
            (se.policy->notifyFlags=se.fields_.flag));
            e.fields_.flag=0;
         }
      }
      txpq_reset(rset);
      return true;
   }
   return false;
}

struct load_policies_safesearch_elems_{
   uint_fast64_t k_; 
   const uint_fast64_t max_; 
   PGresult* const rset_; 

   struct {
      int     policyId;
      char*   option;
   } fields_;

   POLICY* in_policies;
   POLICY* policy;
   const struct safeS * engines_;
};

TX_INTERNAL_INLINE
bool load_policies_safesearch_(  PGconn* const restrict db,
                                 POLICY* const restrict policy_list, 
                                 const size_t policy_count              ){

   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_POLICYSAFESEARCH);
   if (rset){

      // Default set to off 
      for ( struct load_policies_safesearch_elems_ e={   .max_ = policy_count,
                                                         .in_policies = policy_list }; 
            e.k_ < e.max_;
            ++e.k_            ){

               (void)zm(&e.in_policies[e.k_].safeSearchFlags,sizeof(SAFESEARCH_FLAGS));
      }

      //load
      for ( struct load_policies_safesearch_elems_ e={   .max_ = txpq_row_count(rset),
                                                         .rset_ = rset,
                                                         .engines_ = SSengines };
            e.k_ < e.max_ ;
            ++e.k_            ){

               for ( struct load_policies_safesearch_elems_ se={  .max_ = policy_count,
                                                                  .fields_.policyId = txpq_cv_int(e.rset_, e.k_, 0),
                                                                  .in_policies = policy_list };
                     se.k_ < se.max_;
                     ++se.k_              ){

                        se.policy=&se.in_policies[se.k_];

                        if (  se.policy->policyId==se.fields_.policyId ){

                           for( uint_fast64_t m = 0; e.engines_[m].bit; ++m ){
                              //TODO::IMPROVE ME!!!
                              if( !strcmp(txpq_cv_str(e.rset_, e.k_, 1),e.engines_[m].engine) ){

                                 if( !strcmp((se.fields_.option=txpq_cv_str(e.rset_, e.k_, 2)),"ON") ){

                                    se.policy->safeSearchFlags.SSE_OnOff |= e.engines_[m].bit;

                                 } else if( !strcmp(se.fields_.option,"MODERATE") ){

                                    se.policy->safeSearchFlags.SSE_OnOff |= e.engines_[m].bit;
                                    se.policy->safeSearchFlags.SSE_Moderate |= e.engines_[m].bit;
                                 }
                                 break;

                              }/* if */

                           } /* for */

                        } /* if */

               }/* for */

      }/* for */

      txpq_reset(rset);
      return true;
   }
   return false;
}

//---------------------------------------------------------------------
bool load_policies_(PGconn* const restrict db, POLICY** const restrict p_policy_list, size_t * const restrict  p_policy_count) {
   //INLINED 
   return (
            load_policies_categories_(db,p_policy_list,p_policy_count) &&
            load_policies_working_hours_(db,*p_policy_list,*p_policy_count) &&
            load_policies_flags_(db,*p_policy_list,*p_policy_count) &&
            load_policies_notifications_(db,*p_policy_list,*p_policy_count) &&
            load_policies_safesearch_(db,*p_policy_list,*p_policy_count)
           );
}
//---------------------------------------------------------------------
void titax_load_authpolicy_( PGconn* const restrict db ) 
{

   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_AUTHPOLICY);

   TitaxConf* const titax_conf=titax_conf_get_instance();

   if ( rset && txpq_row_count(rset) > 0 && titax_conf ) {

      TITAX_CONF_LOCK();
      titax_conf->enable_auth =     txpq_cv_bool(rset, 0, 0);
      titax_conf->allow_ip =        txpq_cv_bool(rset, 0, 1);
      titax_conf->allow_ldap =      txpq_cv_bool(rset, 0, 2);
      titax_conf->use_kshield =     txpq_cv_bool(rset, 0, 3);
      titax_conf->enable_ntlm =     txpq_cv_bool(rset, 0, 4);

      titax_conf->allow_wada =      txpq_cv_bool(rset, 0, 5); //block if not found

      titax_conf->ip_session =      txpq_cv_bool(rset, 0, 6);
      titax_conf->ip_session_ttl =  txpq_cv_ulong(rset, 0, 7);

      //TODO: add handling of the fext_greedy_match field when UI/DB will be ready
      //titax_conf->fext_greedy_match = txpq_cv_int(rset, 0, X);

      titax_conf->intercept_login =txpq_cv_bool(rset, 0, 9);

      if(titax_conf->ip_session_ttl < MIN_IP_SESSION_TTL) {

         titax_conf->ip_session_ttl = MIN_IP_SESSION_TTL;
      }

      // Set all download limit to 0.
      if (!titax_conf->enable_auth){
         //bw_reset
         reset_users_bw();
      }

      TITAX_CONF_UNLOCK();
   }
   else {

      // Set all download limit to 0.
      if(!titax_conf_is_enable_auth(true)) {

         reset_users_bw();
      }
   }

   if ( rset ) {

      txpq_reset(rset);
   }

}

//---------------------------------------------------------------------
#define TITAX_LOAD_NETWORKING_ERROR_RETURN(TRACK) __extension__ ({   \
   if (rset) txpq_reset(rset);                                       \
   TITAX_CONF_UNLOCK();                                              \
   titax_log(   LOG_ERROR,                                           \
               "%s:%d :: required field %s is empty\n",              \
               __func__,                                             \
               __LINE__,                                             \
               TRACK                                       );        \
   return false;                                                     \
})

TX_INTERNAL_INLINE
bool set_ip_addr( TitaxConf* const restrict titax_conf, 
                  const char * const restrict ip_str,
                  const size_t ip_str_sz,
                  const bool ipv6                        ){

   c_raw_ipaddr_t ip_addr={};

   if (  ttn_str_ipaddr2raw_ipaddr_ex( ip_str, ip_str_sz, &ip_addr ) ){

         char * const ptr = (   !ipv6                ?
                                titax_conf->int_ip_4 :
                                titax_conf->int_ip_6    );
         
         const size_t ptr_sz = (    !ipv6                         ?
                                    sizeof(titax_conf->int_ip_4)  :
                                    sizeof(titax_conf->int_ip_6)     );

         size_t * const ptr_str_sz = (  !ipv6                      ?
                                        &titax_conf->int_ip_4_len  :
                                        &titax_conf->int_ip_6_len     );

         if ( ttn_raw_ipaddr2str_ipaddr_ex( &ip_addr, ptr, ptr_sz ) ){

            *ptr_str_sz=strlen(ptr);
            return true;
         }

   }
   return false;
}

bool titax_load_networking_( PGconn* const restrict db ) 
{

    bool ret = false;

    TITAX_CONF_LOCK();

    TitaxConf* const titax_conf = titax_conf_get_instance();

    PGresult* rset  = pq_get_rset(db, TITAXLIB_QS_T_NETWORKING);

   if ( titax_conf && rset ) {

      if ( txpq_row_count(rset) ) {

        // Get new data.
        char* const    smtp_server =        txpq_cv_str(rset, 0, 0);
        char* const    hostname =           txpq_cv_str(rset, 0, 2);
        char* const    domain =             txpq_cv_str(rset, 0, 3);
        char* const    cnames =             txpq_cv_str(rset, 0, 6);

         //check requred fields
         if (  smtp_server    &&

               hostname       &&

               *hostname      &&

               domain         &&

               *domain        &&

               cnames            ) {

            // Free old data.
            tx_safe_free( titax_conf->smtp_server );
            titax_conf->smtp_server = NULL;

            tx_safe_free( titax_conf->hostname );
            titax_conf->hostname = NULL;

            tx_safe_free( titax_conf->fqdn );
            titax_conf->fqdn = NULL;

            tx_safe_free( titax_conf->cnames );
            titax_conf->cnames = NULL;

         //assign and validate

            if (    !( titax_conf->smtp_server = str_dup( smtp_server ) )   ||

                    *smtp_server != *titax_conf->smtp_server                    ){

                TITAX_LOAD_NETWORKING_ERROR_RETURN("smtp_server");
            }

            titax_conf->smtp_backoff = txpq_cv_ulong(rset, 0, 1);

            titax_conf->transparentproxy = txpq_cv_bool(rset, 0, 5);

            titax_conf->hostname = str_dup_ex( hostname, &titax_conf->hostname_len );

            if (    ! titax_conf->hostname_len          ||

                    ! titax_conf->hostname              ||

                    *hostname != *titax_conf->hostname      ) {

                TITAX_LOAD_NETWORKING_ERROR_RETURN("hostname");
            }

             char* const int_ip_4 = txpq_cv_str(rset, 0, 4);

            if (    ! int_ip_4                           ||

                    ! *int_ip_4                          ||

                    ! set_ip_addr(  titax_conf,
                                    int_ip_4,
                                    strlen(int_ip_4),
                                    false               )   ) {

                set_ip_addr(    titax_conf,
                                PROXY_DEFAULT_IPv4,
                                (sizeof(PROXY_DEFAULT_IPv4)-1),
                                false                           );
            }

            char* const int_ip_6 = txpq_cv_str(rset, 0, 7);

            if (    ! int_ip_6                           ||

                    ! *int_ip_6                          ||

                    ! set_ip_addr(  titax_conf,
                                    int_ip_6,
                                    strlen( int_ip_6 ),
                                    true                )   ) {

                set_ip_addr(    titax_conf,
                                PROXY_DEFAULT_IPv6,
                                (sizeof(PROXY_DEFAULT_IPv6)-1),
                                true                            );
            }

            if ( !( titax_conf->cnames = str_dup_ex ( cnames, &titax_conf->cnames_len ) ) ) {

                TITAX_LOAD_NETWORKING_ERROR_RETURN("cnames");
            }

            // Get fqdn.
            const size_t dsz=(  ( domain && domain[0] ) ?
                                strlen(domain)+1        :
                                0                           );

            const size_t len_ = titax_conf->hostname_len + dsz+1;

            char* const fqdn = (char*const)tx_safe_malloc( len_ );

            if ( ! fqdn ) {

               TITAX_LOAD_NETWORKING_ERROR_RETURN("FQDN");
            }

            if ( dsz ) {

                titax_conf->fqdn_len = tx_safe_snprintf( fqdn, len_, "%s.%s", hostname, domain );
            }
            else {

                if ( ( strlcpy( fqdn, titax_conf->hostname,len_ ) < len_ ) ) {

                    titax_conf->fqdn_len = titax_conf->hostname_len;
                }
                else {

                    TITAX_LOAD_NETWORKING_ERROR_RETURN( "FQDN" );
                }
            }

            titax_conf->fqdn = fqdn;

            txpq_reset( rset );

            if ( ( rset = pq_get_rset( db, TITAXLIB_QS_T_CACHE ) ) ) {

               if ( txpq_row_count( rset ) ) {

                titax_conf->proxy_port = txpq_cv_ulong( rset, 0, 0 );
               }

               txpq_reset( rset );
               rset = NULL;
               ret = true;
            }
         }
      }

      txpq_reset(rset);
    }

    TITAX_CONF_UNLOCK();

    if ( !ret ) {

      titax_log(LOG_ERROR, "[titax_load_networking_]:networking table is empty\n");
    }

    return ret;
}

//---------------------------------------------------------------------
struct titax_load_urlcategories_elems_
{
   uint_fast64_t i_; 
   const uint_fast64_t max_ ; 
   t_category id_; 
   char * catname_;
};

bool titax_load_urlcategories_( PGconn* const restrict  db ) 
{

   PGresult* const rset = pq_get_rset( db, TITAXLIB_QS_T_URLCATEGORIES_1 );

   if ( rset ){

      categoryLockWrite();

      /* Destroy existing data */
      for ( uint_fast64_t i = 0; i < MAX_CATEGORIES; categoryClear( i++ ) )
         ;/* empty body */

      struct titax_load_urlcategories_elems_ e={ .max_ = txpq_row_count( rset ) };

      for ( ; e.i_<e.max_; ++e.i_ ) {

         if (  UWITHIN_( MAX_CATEGORIES, ( e.id_ = txpq_cv_ulong( rset, e.i_, 0 ) ) ) &&

               ( e.catname_ = txpq_cv_str( rset, e.i_, 1 ) )                             ) {

            categorySetName( e.id_, e.catname_ );
         }
      }

      categoryUnlock();
      txpq_reset(rset);
      return true;
   }

   return false;
}

//---------------------------------------------------------------------
//REDUNDANT!!!!!
struct titax_load_urlcategories_custom_elems_{uint_fast64_t i_; const uint_fast64_t max_; t_category id_; char * catname_; PGresult* const rset_;};
bool titax_load_urlcategories_custom_(PGconn* const restrict db) {
   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_URLCATEGORIES_2);
   if (rset){
      custom_categoryLockWrite();
         for (uint_fast64_t i=0;i<MAX_CATEGORIES;custom_categoryClear(i++))
            ;/* empty body */
         for (struct titax_load_urlcategories_custom_elems_ e={
            .max_=txpq_row_count(rset),
            .rset_=rset
         };e.i_<e.max_; ++e.i_){
            (void)(UWITHIN_(MAX_CATEGORIES,(e.id_ = txpq_cv_ulong(e.rset_, e.i_, 0))) && (e.catname_ = txpq_cv_str(e.rset_, e.i_, 1)) && custom_categorySetName(e.id_, e.catname_));
         }
      custom_categoryUnlock();
      txpq_reset(rset);
      return true;
   }
   return false;
}

bool titax_load_groups_for_user( PGconn* const restrict db, 
                                 user_id_t id, 
                                 TitaxUser* restrict user   ) 
{

   if ( db && user ) {

      zm( &user->policy_info , sizeof( user->policy_info ) );

      char buffer[ sizeof( TITAXLIB_QS_T_TOP_POLICIES ) + 30 ] = {};

      tx_safe_snprintf( buffer,
                        sizeof( buffer ),
                        "%s = %zu",
                        TITAXLIB_QS_T_TOP_POLICIES,
                        id                            );

      PGresult * const rset = pq_get_rset( db, buffer );

      const bool ret = load_ids_for_policies_and_groups_for_user( rset, id, user );

      txpq_reset(rset);

      return ret;

   }

   return false;
}


bool ttn_load_user(  PGresult* const restrict rset,
                     const uint_fast64_t rec_no,
                     TitaxUser * const restrict  user )
{
   return load_user_(   rset,
                        rec_no,
                        user     );
}

//---------------------------------------------------------------------
bool titax_load_top_users( PGconn* const restrict db ) 
{

   PGresult * rset = pq_get_rset( db, TITAXLIB_QS_F_USERS_LIST_TYPE );
   if ( rset ) {

      if ( txpq_row_count( rset ) ) {

         if ( ! set_list_type( txpq_cv_uint( rset, 0 , 0 ) ) ) {

              /* on errors */

               set_list_type( ult_plain );
               /* it's not strictly necessary as the default constructor
                * for the UsersListType class will set it as well
                */
         }
      }

      txpq_reset( rset );
   }

   rset = pq_get_rset( db, TITAXLIB_QS_V_TOP_USERS );

   if ( rset ) {

      const uint_fast64_t max = txpq_row_count( rset )  ;

      for ( uint_fast64_t recno = 0 ; recno < max ; ++recno ) {

         TitaxUser user={};

         if (  load_user_( rset, recno, &user ) ) {

            if ( titax_load_groups_for_user( db, user.id, &user ) )  {

               add_user_to_cache( &user );

               continue;
            }

            titax_log(  LOG_ERROR,
                        "%s:%d :: unable to run titax_load_groups_for_user [ %s :: %zu ]"\
                        " from recno %zu requested by tid %d\n",
                        __func__,
                        __LINE__,
                        user.name,
                        user.id,
                        recno,
                        tx_gettid()                                                             );
         }

      } /* loop */

      txpq_reset(rset);

      return true;
   }

   return false;

}
//---------------------------------------------------------------------
bool titax_load_locations_(PGconn* const restrict db)
{
   return gtape_location_reload( db );
}

//---------------------------------------------------------------------

struct tok_load_e{uint_fast64_t i_; const uint_fast64_t max_; size_t user_id; PGresult* const rset_; char* token_md5_; };
bool titax_reload_tokens_(PGconn* const restrict db) {
   PGresult* rset=NULL;
   //split this function int two prarts
   if ((rset = pq_get_rset(db, TITAXLIB_QS_V_USERS_CKEY_COUNTS))){
      for (size_t i = 0; i < txpq_row_count(rset); ++i) {
         size_t user_id = txpq_cv_ulong(rset, i, 0);
         update_tokens_count(user_id, txpq_cv_ulong(rset, i, 1));
      }
      txpq_reset(rset);
   }
   else {
      return false;
   }

   if ((rset = pq_get_rset(db, TITAXLIB_QS_V_ACTIVE_USED_BYPASS_TOKENS_SHORT))){
      token_map_clear();
      for (struct tok_load_e e={
         .max_=txpq_row_count(rset),
         .rset_=rset
      };e.i_<e.max_;++e.i_){
         e.user_id = txpq_cv_ulong(e.rset_, e.i_, 0);
         if ((e.token_md5_ = txpq_cv_str(e.rset_, e.i_, 2))) {
            token_map_add_elem(e.token_md5_, TitaxCKey_new(e.token_md5_,txpq_cv_str(e.rset_, e.i_, 1), e.user_id));
         }
      }
      txpq_reset(rset);
      return true;
   }
   return false;
}

//---------------------------------------------------------------------
int get_svr_sock_( const int port, const int backlog, const  int local_only ) {

    int svr_sock=INVALID_;

    struct sockaddr_in server_addr={
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = (    local_only              ?

                                inet_addr("127.0.0.1")  :

                                INADDR_ANY                  )
    };

    int on = 1;

    errno = 0;

    if( INVALID_ == ( svr_sock = socket( AF_INET, SOCK_STREAM, 0 ) ) ) {
        titax_log( LOG_ERROR, "%s:%s\n", __func__, strerror(errno) );
        return -1;
    }

    if( INVALID_ == setsockopt( svr_sock, SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on) ) ) {

        titax_log( LOG_ERROR, "%s:%s\n", __func__, strerror( errno ) ) ;
        close( svr_sock );
        return -2;
    }

    if( INVALID_ == bind( svr_sock, (struct sockaddr *)&server_addr, sizeof(server_addr) ) ) {

        titax_log( LOG_ERROR, "%s:%s\n", __func__, strerror( errno ) ) ;
        close( svr_sock );
        return -3;
    }

    if( INVALID_ == listen( svr_sock, backlog ) ) {

        titax_log( LOG_ERROR, "%s:%s\n", __func__, strerror( errno ) ) ;
        close( svr_sock );
        return -4;
    }

    return svr_sock;
}


void titax_intercept_login_manager_serv_( const  int clt_sock, const struct sockaddr_in * const restrict clt_ip ) {

    static char rbuf[1024];
    zm( rbuf, sizeof(rbuf) );

    if( read( clt_sock, rbuf, sizeof(rbuf) - 1 ) >= 0 ) {

        size_t osz=0;
        char* const line = trim_ptr( rbuf, sizeof(rbuf), &osz );

        if ( line && osz ) {

            line[osz]=0;

            c_raw_ipaddr_t cip={};

            size_t user_id;

            StringList* const list = split_by_space(line,osz);

            /* format should be [<IPV4> <NUMBER>\n] */
            /* fix me - to accept ipv 4/6 */
            if ( list->size == 2 ) {

                if (    ttn_str_ipaddr2raw_ipaddr_ex( list->arr[0], strlen( list->arr[0] ), &cip )  &&

                        tx_safe_atoul( list->arr[1], &user_id )                                         ) {

                        if ( gtape_location_add_session( &cip, user_id ) ) {

                            TXDEBUG("Added, ip = %s\n",inet_ntoa(clt_ip->sin_addr) );
                        }

                } 
                else {

                    titax_log(LOG_ERROR, "%s:%d:parsing error [%s]\n",__func__,__LINE__,rbuf);
                }

            }
            else {

                titax_log(LOG_ERROR, "%s:%d:format error [%s]\n",__func__,__LINE__,rbuf);
            }

            string_list_free(list);

        } /* if line && osz */

   }/* if read */
}

//---------------------------------------------------------------------
#define INTERCEPT_PORT_NO 18881

void* titax_intercept_login_manager_( void* arg ) {

   (void)arg;

   if (ttn_get_shutdown_now()){

        titax_log(LOG_WARNING, "%s:%d:shutdown detected, exiting\n",__func__,__LINE__);
        return NULL;
    }

    const int svr_sock = get_svr_sock_( INTERCEPT_PORT_NO, 10, 1 );
    if ( svr_sock < 0 ){

        titax_log(LOG_WARNING, "%s:%d:error detected, exiting\n",__func__,__LINE__);
        return NULL;
    }

    TXDEBLOG((void)printf("Intercept login manager is waiting (%d)...\n",INTERCEPT_PORT_NO));

    int clt_sock=INVALID_;

    int max=0;

    struct sockaddr_in clt_addr = {};

    socklen_t clt_addr_size = sizeof(clt_addr);

    fd_set read_fds;

    while( !ttn_get_shutdown_now() ) {

        int ierror=0;

        FD_ZERO(&read_fds);

        if ( !tx_get_sock_error( svr_sock, &ierror ) ||  tx_s_qs( ierror ) == tq_fal ){

            titax_log(LOG_ERROR, "%s: svr error %d , exiting \n",__func__,ierror);

            if ( INVALID_<svr_sock ) {

                close(svr_sock);
            }

            if( INVALID_<clt_sock ) {

                close(clt_sock);
            }

            return NULL;
        }

        FD_SET( svr_sock, &read_fds );

        if ( svr_sock >= max ) {

            max = svr_sock + 1;
        }

        if ( INVALID_<clt_sock ) {

            ierror=0;

            if ( tx_get_sock_error( clt_sock, &ierror ) && tx_s_qs( ierror ) != tq_fal ) {

                FD_SET(clt_sock, &read_fds);

                if ( clt_sock >= max ) {

                    max = clt_sock + 1;

                }

            }
            else {

                if ( INVALID_ < clt_sock ) {

                    titax_log(LOG_ERROR, "%s: clt error %d \n",__func__,ierror);

                    close(  clt_sock );

                    clt_sock = INVALID_;
                }
            }
        }

        struct timeval tv = { .tv_sec = 4 };

        const int sf = select(max, &read_fds, (fd_set *)NULL, (fd_set *)NULL, &tv);

        switch (sf) {

            case INVALID_:
            case 0: continue;

            default:{

                if ( INVALID_ < clt_sock && FD_ISSET( clt_sock, &read_fds ) ){

                    titax_intercept_login_manager_serv_( clt_sock, &clt_addr );

                    close(clt_sock);

                    clt_sock=INVALID_;
                }

                if ( ttn_get_shutdown_now() ) {

                    titax_log(LOG_WARNING, "%s:%d:shutdown detected, exiting\n",__func__,__LINE__);

                    if ( INVALID_ < clt_sock) {

                      close(clt_sock);
                    }

                    if ( INVALID_<svr_sock ) {

                        close(svr_sock);
                    }

                    return NULL;
                }

                if (    FD_ISSET( svr_sock, &read_fds ) && 

                        ( INVALID_ < ( clt_sock = accept(   svr_sock,
                                                            (struct sockaddr*)&clt_addr,
                                                            &clt_addr_size)                 ) ) ) {

                    TXDEBLOG((void)printf("Intercept login manager - got client socket (%d)\n",clt_sock));
                }

            }break;

        } /* switch */

    } /* while */

    TXDEBLOG((void)puts("Intercept login manager - shutdown detected\n"));

    close(svr_sock);

    return NULL;
}

//---------------------------------------------------------------------
void* titax_uniq_ip_remove_thread_(void* arg) {
   (void)arg;

   if (ttn_get_shutdown_now()) {

      return NULL;
   }

   char prev_date[80]={};
   get_curdate_safe(prev_date, sizeof(prev_date));

   TXDEBLOG((void)puts("uniq_ip_remove_thread running ...\n"));
   PGconn* db = NULL;

   app_t app=gtape_app_mode();

   while( !ttn_get_shutdown_now() ) {

      const TitaxConf* const txcnf=titax_conf_get_instance();
      if (txcnf) {

         TITAX_CONF_LOCK();
         const size_t max_ips=txcnf->license.max_ips;
         TITAX_CONF_UNLOCK();
         
         if (TITAX_UNLIMITED_USER!=max_ips) {

            gtape_uniqips_clear_old();
            //add print 
         }
      }

      if ( gateway == app.mode ) {

         char new_date[80]={};

         get_curdate_safe(new_date, sizeof new_date);

         if ( 0 != strcmp( prev_date, new_date ) ) {

            /* clear user bw */
            reset_users_bw();
            if ( check_raw_dbconn(&db,16,&db_config_connect)) {

               pq_do(db, TITAXLIB_QT_T_USER_BW);
            }

            strlcpy(prev_date, new_date,sizeof(prev_date));
         }
      }

      sleep(5);
   }
   pq_conn_close(db);
   TXDEBLOG((void)puts("uniq_ip_remove_thread shutdown\n"));
   return NULL;
}

//---------------------------------------------------------------------
void* titax_data_update_thread_(void* arg) {
   (void)arg;
   if (ttn_get_shutdown_now()) 
        return NULL;
   PGconn* db=NULL;
   if (!check_raw_dbconn(&db,16,&db_config_connect)){
      titax_log(LOG_ERROR, "[titax_data_update_thread_]:Can't connect db\n");
      exit(INVALID_);
   }

   StringMap* const old_map = string_map_new();
   StringMap* const new_map = string_map_new();

   get_update_times_(db, old_map);

   TXDEBLOG((void)puts("data_update_thread running\n"));
   static uint_fast64_t lic_ctx=0;
   static uint_fast64_t at_ctx=0;

   while(!ttn_get_shutdown_now()) {
      bool users_updated = false;

      // Check and re-conn to db.
      if (!check_raw_dbconn(&db,16,&db_config_connect)){
         continue;
      }

      (void)get_update_times_(db, new_map);

      if(is_policy_updated_(old_map, new_map)) {
         
         // Make it stop loading twice.
         (void)is_updated_table_(old_map, new_map, "groups");

         //from now on domain_policies are directly connected to the policies
         //so whenever policies or domain_policies change then whole list must be reloaded too
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload domain_policies\n"));
         (void)gtape_reload_wbl_domains(db);
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload groups\n"));
         if (!titax_conf_is_master(true)) {
            users_updated = true;
            clean_users();
            (void)titax_load_user_dic(db);
         }
         TS_TITAX_LOAD_GROUPS_(db);
      }

      if(is_updated_table_(old_map, new_map, "filtering")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload filtering\n"));
         (void)titax_load_filtering_(db);
         TS_TITAX_LOAD_GROUPS_(db);
      }

      if(is_updated_table_(old_map, new_map, "keywords")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload keywords\n"));
         (void)titax_load_keywords_(db);
      }

      if(is_updated_table_(old_map, new_map, "networking")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload networking\n"));
         (void)titax_load_networking_(db);
      }
      
      if(is_updated_table_(old_map, new_map, "redirections")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload redirections\n"));
         (void)redirections_reload(db);
      }

      if(is_updated_table_(old_map, new_map, "urlcategories")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload urlcategories\n"));
         (void)titax_load_urlcategories_(db);
         (void)titax_load_urlcategories_custom_(db);
      }

      if(is_updated_table_(old_map, new_map, "authpolicy")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload authpolicy\n"));
         titax_load_authpolicy_(db);
      }

      if(is_updated_table_(old_map, new_map, "keyword_policies")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload keyword_policies\n"));
         (void)titax_load_keyword_policies_(db);
      }

      if(is_updated_table_(old_map, new_map, "users") || is_updated_table_(old_map, new_map, "ldapservers")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload users\n"));

         if (titax_conf_is_master(true)) {
            (void)titax_load_locations_(db);
         }
         else if (!users_updated) {
             clean_users();
            (void)titax_load_user_dic(db);
         }

         (void)gtape_reload_ldap_domains(db);
         (void)gtape_reload_wbl_domains(db);
         // Flush the map.
         (void)is_updated_table_(old_map, new_map, "usergroups");
         (void)is_updated_table_(old_map, new_map, "userlogins");
         (void)is_updated_table_(old_map, new_map, "usersbandwidth");

      }

      if(   is_updated_table_(old_map, new_map, "locations")            ||

            is_updated_table_(old_map, new_map, "virtual_locations")        ) {

         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload locations\n"));
         (void)titax_load_locations_(db);

      }

      if(is_updated_table_(old_map, new_map, "bypass_tokens")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload bypass_tokens\n"));
         (void)titax_reload_tokens_(db);
      }
      // Read license values.
      if(++lic_ctx >= 360){
         //wait for an hour
         (void)puts("Reading license values.");
         /* individual locks */
         gtape_lic_mgr_query();
         lic_ctx = 0;
      }

      (void)sleep(2);
      if(++at_ctx >= 45){
         TS_CHECKACCESSTIMES();
         at_ctx=0;
      }
   }
   (void)string_map_free(old_map);
   (void)string_map_free(new_map);
   (void)pq_conn_close(db);
   TXDEBLOG((void)puts("data_update_thread shutdown\n"));   
   return NULL;
}
//---------------------------------------------------------------------
struct titax_init_all_items_{bool use_data_update_thread; bool use_uniq_ip_remove_thread;bool use_intercept_login_manager;};
void titax_init_all(const bool verb) {
   pthread_t update_thread;
   pthread_t remove_thread;
   pthread_t intercept_thread;
   // Init titax_conf.
   //create new instance and read conf file or assign defaults
   assert(titax_conf_get_instance());
   (void)titax_conf_set_verbose(verb,true);
  
   gtape_lic_mgr_query();

   PGconn* db=NULL;
   if (!check_raw_dbconn(&db,16,&db_config_connect)){
      titax_log(LOG_ERROR, "[titax_init_all]: Can't connect db\n");
      exit(INVALID_);
   }
   

   init_all_(db);

   // Close connection to DB.
   (void)pq_conn_close(db);

   //internal services
   struct titax_init_all_items_ items={};
   TITAX_CONF_LOCK();
   const TitaxConf* const conf_=titax_conf_get_instance();
   items.use_data_update_thread=conf_->use_data_update_thread;
   items.use_uniq_ip_remove_thread=conf_->use_uniq_ip_remove_thread;
   items.use_intercept_login_manager=conf_->use_intercept_login_manager;
   TITAX_CONF_UNLOCK();

   if(   items.use_data_update_thread                                                  && 

         pthread_create(&update_thread, NULL, &titax_data_update_thread_, NULL) != 0      ) {

      titax_log(LOG_ERROR, "Creation of the update_thread failed\n");
      exit(INVALID_);
   }

   if(   items.use_uniq_ip_remove_thread                                                  &&  

         pthread_create(&remove_thread, NULL, &titax_uniq_ip_remove_thread_, NULL) != 0      ) {

      titax_log(LOG_ERROR, "Creation of the remove_thread failed\n");
      exit(INVALID_);
   }

   if(   items.use_intercept_login_manager                                                   &&

         pthread_create(&intercept_thread, NULL, &titax_intercept_login_manager_, NULL) != 0    ) {

     titax_log(LOG_ERROR, "Creation of the intercept_thread failed\n");
     exit(INVALID_);
   }

   TITAX_CONF_LOCK();
   (void)titax_conf_print_all_NL();
   TITAX_CONF_UNLOCK();
   
}

//---------------------------------------------------------------------
#ifdef TTN_ATESTS
bool titax_init_all_4tests(PGconn* const restrict db){
   (void)titax_conf_get_instance();
   init_all_(db);
   return (true);
}

void titax_cleanup_all_4test(){
   titax_conf_4tests_free_instance();
}

bool get_update_times_4tests(PGconn* const restrict db, StringMap* const restrict map){
   get_update_times_(db, map);
   return true;
}


bool is_updated_table_4tests(StringMap* const restrict  old_map, StringMap* const restrict  new_map,const char* const restrict  kw){
   return is_updated_table_(old_map,new_map,kw);
}


bool is_policy_updated_4tests(StringMap* const restrict old_map, StringMap* const restrict  new_map){
   return is_policy_updated_(old_map,new_map);
}


bool titax_data_update_4tests(PGconn* const restrict db,StringMap* const restrict new_map,const bool verb) {

   StringMap* const old_map = string_map_new();
   (void)(verb && puts("data_update_thread running\n"));

   if(!ttn_get_shutdown_now()){
      if(is_policy_updated_(old_map, new_map)) {
         
         // Make it stop loading twice.
         (void)is_updated_table_(old_map, new_map, "groups");

         //from now on domain_policies are directly connected to the policies
         //so whenever policies or domain_policies change then whole list must be reloaded too
         (void)(verb && puts("Try to reload domain_policies\n"));
         (void)gtape_reload_wbl_domains(db);
         (void)(verb && puts("Try to reload groups\n"));
         (void)TS_TITAX_LOAD_GROUPS_(db);
      }

      if(is_updated_table_(old_map, new_map, "filtering")) {
         (void)(verb && puts("Try to reload filtering\n"));
         (void)titax_load_filtering_(db);
         (void)TS_TITAX_LOAD_GROUPS_(db);
      }
      

      if(is_updated_table_(old_map, new_map, "keywords")) {
         (void)(verb && puts("Try to reload keywords\n"));
         (void)titax_load_keywords_(db);
      }

      if(is_updated_table_(old_map, new_map, "networking")) {
         (void)(verb && puts("Try to reload networking\n"));
         (void)titax_load_networking_(db);
      }
      
      if(is_updated_table_(old_map, new_map, "redirections")) {
         (void)(verb && puts("Try to reload redirections\n"));
         (void)redirections_reload(db);
      }

      if(is_updated_table_(old_map, new_map, "urlcategories")) {
         (void)(verb && puts("Try to reload urlcategories\n"));
         (void)titax_load_urlcategories_(db);
         (void)titax_load_urlcategories_custom_(db);
      }

      if(is_updated_table_(old_map, new_map, "authpolicy")) {
         (void)(verb && puts("Try to reload authpolic\n"));
         titax_load_authpolicy_(db);
      }

      if(is_updated_table_(old_map, new_map, "keyword_policies")) {
         (void)(verb && puts("Try to reload keyword_policies\n"));
         (void)titax_load_keyword_policies_(db);
      }

      if(is_updated_table_(old_map, new_map, "users") || is_updated_table_(old_map, new_map, "ldapservers")) {
         TXDEBLOG(titax_log(LOG_DEBUG, "Try to reload users\n"));

         (void)titax_load_locations_(db);
         (void)titax_reload_tokens_(db);
         (void)gtape_reload_ldap_domains(db);
         (void)gtape_reload_wbl_domains(db);
         // Flush the map.
         (void)is_updated_table_(old_map, new_map, "usergroups");
         (void)is_updated_table_(old_map, new_map, "userlogins");
         (void)is_updated_table_(old_map, new_map, "usersbandwidth");

      }

      if(is_updated_table_(old_map, new_map, "userlogins")) {
         (void)(verb && puts("Try to reload reloaduserlogins\n"));
         (void)titax_load_locations_(db);
      }
      
      if(is_updated_table_(old_map, new_map, "bypass_tokens")) {
         (void)(verb && puts("Try to reload bypass_tokens\n"));
         (void)titax_reload_tokens_(db);
      }
   }
   (void)string_map_free(old_map);
   (void)(verb && puts("data_update_thread shutdown\n"));
   return true;
}


#endif
//---------------------------------------------------------------------
void* titax_icap_timer_thread_(void*arg) {
   (void)arg;
   int oldState=0;

   (void)pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &oldState);

   while(1) {
      pthread_testcancel();
      TS_CHECKACCESSTIMES();
      sleep(120);
   }
   return NULL;
}

//---------------------------------------------------------------------
void* titax_icap_data_update_thread_(void*arg) {
   (void)arg;
   PGconn* db=NULL;
   if (!check_raw_dbconn(&db,16,&db_config_connect)){
      titax_log(LOG_ERROR, "[titax_icap_data_update_thread_]: Can't connect db\n");
      exit(INVALID_);
   }

   StringMap* const old_map = string_map_new();
   StringMap* const new_map = string_map_new();
   get_update_times_(db, old_map);

   while(1) {
      // Check and re-conn to db.
      if (!check_raw_dbconn(&db,16,&db_config_connect))
         continue;

      get_update_times_(db, new_map);

      if(is_policy_updated_(old_map, new_map)) {

         // Make it stop loading twice.
         (void)is_updated_table_(old_map, new_map, "groups");

         titax_log(LOG_DEBUG, "Try to reload groups\n");
         (void)TS_TITAX_LOAD_GROUPS_(db);
      }

      if(is_updated_table_(old_map, new_map, "filtering")) {
         titax_log(LOG_DEBUG, "Try to reload filtering\n");
         (void)titax_load_filtering_(db);
         (void)TS_TITAX_LOAD_GROUPS_(db);
      }

      if(is_updated_table_(old_map, new_map, "keywords")) {
         titax_log(LOG_DEBUG, "Try to reload keywords\n");
         (void)titax_load_keywords_(db);
      }
      (void)sleep(2);
   }

   return NULL;
}

//---------------------------------------------------------------------
void titax_init_all_icap() {
   pthread_t timer_thread;
   pthread_t update_thread;

   // Init titax_conf.
   (void)titax_conf_get_instance();

   is_icap = 1;

   // Connect to Config DB.
   PGconn*  db=NULL;
   if (!check_raw_dbconn(&db,16,&db_config_connect)){
      titax_log(LOG_ERROR, "[titax_icap_data_update_thread_]: Can't connect db\n");
      exit(INVALID_);
   }
   
   init_all_shared_(db);
   
   // Close connection to DB.
   (void)pq_conn_close(db);

   if(pthread_create(&timer_thread, NULL, &titax_icap_timer_thread_, NULL) != 0) {
      titax_log(LOG_ERROR, "timer_thread creation failed.\n");
      exit(INVALID_);
   }

   if(pthread_create(&update_thread, NULL, &titax_icap_data_update_thread_, NULL) != 0) {
      titax_log(LOG_ERROR, "update_thread creation failed\n");
      exit(INVALID_);
   }
}

//---------------------------------------------------------------------
#define URLDB_SCAN_DATA_ULL_STR_MAX_   20

/**
 * @name urldb_scan_data_
 * @abstract atomic parser
 * @warning parser will change the input data, 
 * so if successful one CANNOT use this data anymore
 * @note thread-safe
 * @param data_[in] input data 
 * @param dsz_[in] input data sz
 * @param lout_[out] output number
 * @param rout_[out] output number
 * @return t/f
 */
TX_INTERNAL_INLINE
bool urldb_scan_data_(  char * const data_,
                        const size_t dsz_, 
                        unsigned long long * const restrict lout_, 
                        unsigned long long * const restrict rout_   )
{
    if ( data_ && 
         dsz_ >= 3 && 
         dsz_ <= ( URLDB_SCAN_DATA_ULL_STR_MAX_ * 2 + 1 ) && lout_ && rout_ ) {

        const ssize_t lp_ = ttn_strncspn( data_, dsz_, " ", 1 );
        if ( lp_ > 0 && ( lp_ <= URLDB_SCAN_DATA_ULL_STR_MAX_ ) ) {

            const size_t rp_ = dsz_ - (size_t)( lp_ + 1 );
            data_[ lp_ ] = 0;
            if ( ( rp_ <= URLDB_SCAN_DATA_ULL_STR_MAX_ ) && tx_safe_atoull( data_, lout_ ) ) {

                char d2[ 32 ];
                memcpy( d2, data_ + (size_t)( lp_ + 1 ), rp_ );
                d2[rp_] = 0;
                return tx_safe_atoull( d2, rout_ );
            }
        }
    }
    return false;
}

#ifdef TTN_ATESTS 
bool urldb_scan_data_4tests( char * const data_,
                             const size_t dsz_, 
                             unsigned long long * const lout_, 
                             unsigned long long * const rout_   )
{
    return ( urldb_scan_data_( data_, dsz_, lout_, rout_ ) );
}
#endif

#ifdef TTN_ATESTS 
   t_udb_test_call urldb_test_={};
#endif

typedef struct iovec iovec_t;

typedef struct { 
   const size_t max; 
   size_t try;
   ssize_t ctx;
   bool receiving;
} urldb_try_t;


t_urldb_rc urldb_send_request(urldb_call_t * const restrict call) 
{
    t_urldb_rc res = urldb_rc_er_cal;

    if (    call && call->out.ac                                &&
#ifndef TTN_ATESTS
            call->urlsvr.conn                                   &&
#endif
            ( call->out.buf && call->out.bsz )                  &&

            ( call->in.bsz && call->in.buf && call->in.buf[0] ) &&

            call->out.buf != call->in.buf                       &&

            CLEAN_URI_SZ >= call->in.bsz                        &&

            call->max_try                                           ) {


        for ( urldb_try_t e = { .max = call->max_try, .try = 0 }; e.max > e.try++; /*empty*/ ) {

            errno = 0;

            if ( INVALID_ < ( *call->urlsvr.fd ) ) {

                /* send */
                if ( !e.receiving ) {
#ifndef TTN_ATESTS

                    const iovec_t mvec[2]={
                        { .iov_base = (void*)call->in.buf, .iov_len = call->in.bsz },
                        { .iov_base = (void*)"\n", .iov_len =1 }
                    };

                    if ( ! ( e.receiving = ( 0 < ( e.ctx = writev( (*call->urlsvr.fd), mvec, 2 ) ) ) ) ) {

                        /* error or disconnect */
                        res = urldb_rc_er_snd;
                        close_fd((*call->urlsvr.fd), true);
                        titax_log(  LOG_ERROR,
                                    "%s : send %d fail err [ %d | %s ]:{%s}\n",
                                    __func__,
                                    (*call->urlsvr.fd),
                                    errno,
                                    strerror(errno),
                                    call->in.buf                                 );

                        *call->urlsvr.fd = INVALID_;

                        break;
                    }
#else
                    if ( urldb_test_.type == udbtt_error_send ) {
                        //mock tx_ip_try_send error
                        res = urldb_rc_er_snd;
                        break;
                    }
                    else {

                        e.receiving=true;
                    }
#endif

                } /* if !e.receiving */

                /* recv */
#ifndef TTN_ATESTS
                struct timeval timeout={.tv_sec=2};
                fd_set input_mask;
                FD_ZERO(&input_mask);
                FD_SET(*call->urlsvr.fd, &input_mask);
                if (e.receiving
                    && (e.ctx = select(*call->urlsvr.fd + 1, &input_mask, NULL, NULL, &timeout)) > 0
                    && (e.ctx = recv( (*call->urlsvr.fd), call->out.buf, call->out.bsz, 0 )) > 0) {

                    call->out.buf[ e.ctx ] = 0;

#else

                if (    e.receiving && urldb_test_.type != udbtt_error_recv ) {
#endif

                    char * const rbuf = call->out.buf;

#ifdef  TTN_ATESTS
                    if ( !urldb_test_.buffer_with_reply ) {

                        strlcpy( rbuf, URL_MSG_DBERR, call->out.bsz );

                        e.ctx = URL_MSG_DBERR_SZ;
                    }
                    else if ( !urldb_test_.buffer_with_reply[0] ) {

                        strlcpy( rbuf, URL_MSG_NOTFOUND, call->out.bsz );

                        e.ctx = URL_MSG_NOTFOUND_SZ;
                    }
                    else {

                        strlcpy( rbuf, urldb_test_.buffer_with_reply, call->out.bsz );

                        e.ctx = (ssize_t)strlen( urldb_test_.buffer_with_reply );
                    }
#endif

                    switch ( e.ctx ) {

                        case URL_MSG_DBERR_SZ:

                            if ( !strncmp( URL_MSG_DBERR, rbuf, (size_t)e.ctx ) ) {

                                return urldb_rc_er_udb;
                            }

                        /* fall through */
                        case URL_MSG_NOTFOUND_SZ:

                            if ( !strncmp( URL_MSG_NOTFOUND, rbuf, (size_t)e.ctx ) ) {

                                return urldb_rc_er_unc;
                            }

                        /* fall through */
                        default: {

                             AccessControl * const  ac_ = call->out.ac;

                             ac_->flagsD = ac_->categoryD = ac_->categoryE = 0;

                             if ( urldb_scan_data_(  rbuf,
                                                     (size_t)e.ctx,
                                                     &( ac_->categoryD ),
                                                     &( ac_->categoryE )  )  ) {

                                return urldb_rc_ok; 
                            }

                        } break;

                    } /* switch */

                    /* parsing error */
                    titax_log(  LOG_ERROR,
                                "%s : parse fail err [ %zd | %s | %zu | %s ]\n",
                                __func__,
                                e.ctx,
                                call->out.buf,
                                call->in.bsz,
                                call->in.buf                                            );

                    res=urldb_rc_er_dec;

                }
                else{

                    /* error or disconnect */
                    res=urldb_rc_er_rcv;
                    #ifndef TTN_ATESTS
                        titax_log(  LOG_ERROR,
                                    "%s : recv %d fail err [ %d | %s ]:{%s}\n",
                                    __func__,
                                    (*call->urlsvr.fd),
                                    errno,
                                    strerror( errno ),
                                    call->in.buf                              );
                    #endif
                }

#ifndef TTN_ATESTS
                if ( errno==EAGAIN ) continue;

                /* close */
                close_fd( (*call->urlsvr.fd), true );
#endif

                (*call->urlsvr.fd) = INVALID_;
                e.receiving = false;

            } /* INVALID_ < ( *call->urlsvr.fd ) */

            /* open */
#ifndef TTN_ATESTS

            (*call->urlsvr.fd) = tx_ip_socket_ex( call->urlsvr.conn );

            if ( INVALID_ >= (*call->urlsvr.fd) ) {

                titax_log( LOG_ERROR,
                           "%s : open fail err [ %d | %s ]\n",
                            __func__,
                           errno,
                           strerror(errno)                        );

                res = urldb_rc_er_opn;
            }
#else
            if ( urldb_test_.type == udbtt_error_connect ) {

                res=urldb_rc_er_opn;
            }
            else {

                (*call->urlsvr.fd) = 1;
            }
#endif

        } /* loop */

    } /* main if */

   return res;
}

//---------------------------------------------------------------------

// Misc.

//------------------------------------------------------------------
size_t get_titax_backoff_limit() {
   return g_titax_backoff_limit;
}

//------------------------------------------------------------------
void set_titax_backoff_limit(const size_t l) {
   g_titax_backoff_limit = l;
}

//------------------------------------------------------------------
int logger_open() {
   /*
   if(g_logger_sock != -1){
   return 1;
   }
   */

   if(!open_unix_connection_noblock(&g_logger_sock, "/var/run/logger/logger.sock")) {
      return 0;
   }
   return 1;
}

//------------------------------------------------------------------
int logger_writen(const void* vptr,const  size_t n) {
   if(writen(g_logger_sock, vptr, n) <= 0) {
      return 0;
   }
   return 1;
}

//------------------------------------------------------------------
void logger_close() {
   close(g_logger_sock);
   // g_logger_sock = -1;
}

//---------------------------------------------------------------------

PGconn* db_config_connect(){

   PGconn* db=NULL;

   TITAX_CONF_LOCK();

   const TitaxConf* const conf_ = titax_conf_get_instance();

   if ( conf_ ) {

      // Connect to Config DB.

#ifndef TTN_ATESTS

      if ( conf_->pgcstr_config ) {

         titax_log(  LOG_DEBUG,
                     "%s:%s:%d ::DB:: attempt to connect to db [%s]\n",
                     __FILE__,
                     __func__,
                     __LINE__,
                     conf_->pgcstr_config );

         db = pq_conn( conf_->pgcstr_config );

      }

#else 

         db = pq_conn(TNPQ_TEST_CONSTR );
#endif

   }

   TITAX_CONF_UNLOCK();

   return db;
}

PGconn* db_reporting_connect(){

   PGconn* db=NULL;

   TITAX_CONF_LOCK();
   const TitaxConf* const conf_=titax_conf_get_instance();
   
   if ( conf_ ) {
      
      // Connect to Report DB.
      
      if ( conf_->pgcstr_reporting ) {

         titax_log(  LOG_DEBUG,
                     "%s:%s:%d ::DB:: attempt to connect to db [%s]\n",
                     __FILE__,
                     __func__,
                     __LINE__,
                     conf_->pgcstr_reporting );

         db = pq_conn( conf_->pgcstr_reporting );

      }

   }

   TITAX_CONF_UNLOCK();
   return db;
}

//---------------------------------------------------------------------
void titax_load_groups(PGconn* const restrict db){
   if (db) (void)titax_load_groups_(db);   
}

void titax_load_user_dic(PGconn* const restrict db){
   if (db) (void)titax_load_user_dic_(db);   
}
/////////////////////////////////////////////////////////////////////////////////

/*
char * get_sld(const char * pHostName) {
   char * lHost=cut_protocol_from_uri(pHostName);
   size_t ffslash_off=strcspn(lHost,"/");
   if (ffslash_off) {
      char * p=(char *)malloc(ffslash_off);
      memmove(p,lHost,ffslash_off);
      p[ffslash_off]=0;
      free(lHost);
      lHost=p;
   } else {
      if (lHost){
          free(lHost);
      }
      lHost=strdup(pHostName);
   }

   char * sld = NULL;
   strrev_in_place(lHost);
   size_t off_tld=strcspn(lHost,  ".");
   if (off_tld>=2) {
      size_t off_sld=strcspn(lHost+off_tld+1,  ".");
      if (off_sld>=1) {
         sld=(char *)malloc(off_sld+off_tld+1);
         strncpy(sld,lHost,off_tld);
         strncpy(sld+off_tld,lHost+off_tld,off_sld+1);
         sld[off_sld+off_tld+1]=0;
         strrev_in_place(sld);
      }
   }
   free(lHost);
   return sld;
}
*/
