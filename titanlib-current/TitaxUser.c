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
 *
 */


#include "TitaxUser.h"
#include "Group.h"
#include "edgelib.h"
#include <limits.h>

static TitaxUserDic* g_titax_user_dic=NULL;
static pthread_mutex_t g_user_dic_lock = PTHREAD_MUTEX_INITIALIZER;

const t_int_id_buf int_id_buf_clear={};


//---------------------------------------------------------------------

#define FIND_TITAXCKEY_BY_TOKENVAL_NL_(a_token_val_,a_dic_) __extension__ ({           \
const TitaxUserDic* v_dic__=(a_dic_);                                                  \
if (!v_dic__) v_dic__=titax_user_dic_get_instance();                                   \
TitaxCKey * v_key_ret__=NULL;                                                          \
if ( (a_token_val_) &&  v_dic__)                                                       \
   v_key_ret__=((TitaxCKey*const)void_map_val(v_dic__->txtoken_map, (a_token_val_) )); \
(v_key_ret__);                                                                         \
})

//------------------------------------------------------------------------------


static void ck_free_void(void* const v)
{
   TitaxCKey_free((TitaxCKey*const)v);
}


TitaxCKey* TitaxCKey_new(  const char * const restrict hash,
                           const char * const restrict str,
                           size_t user_id                   )
{
   if ( hash && *hash ) {

      TitaxCKey* const ck=(TitaxCKey*const)tx_safe_malloc(sizeof(TitaxCKey));

      if (ck){

         const size_t c=strlen(hash);
         if ( c ) {

            tx_safe_memcpy(ck->hash,hash,(MAX_CK_HASH_SZ>c?c:MAX_CK_HASH_SZ));
         }

         if (str && ( ck->str_sz = strlen(str) ) ) {

            tx_safe_memcpy(ck->str,str,(MAX_CK_HASH_SZ>ck->str_sz?ck->str_sz:(ck->str_sz=MAX_CK_HASH_SZ)));

         }

         ck->user_id = user_id;

         return ck;
      }
   }

   return NULL;
}

bool TitaxCKey_free(TitaxCKey * const restrict ck)
{
   if (  ck && 
         /* it is ok for as long as the TitaxCKey 
            type doesn't have any pointers (as members) */
         zm( ck, sizeof(TitaxCKey) )                        ) {

      tx_safe_free(ck);

      return true;
   }
   return false;
}


bool titax_user_free(TitaxUser* const restrict u)
{
   if (  u  && 
         /* it is ok for as long as the TitaxUser 
            type doesn't have any pointers (as members) */
         zm( u, sizeof(TitaxUser) )                         ) {

      tx_safe_free(u);

      return true;
   }
   return false;
}

//---------------------------------------------------------------------
static TitaxUserDic* titax_user_dic_get_instance()
{

   if (!g_titax_user_dic) {

      TitaxUserDic* const tmp=(TitaxUserDic*const)tx_safe_malloc(sizeof(TitaxUserDic));

      if (tmp){
         ///DO NOT add free val function because val is shared across multiple lists/maps   f.e. void_map_new(NULL);
         tmp->md5val_map = void_map_new(NULL); //<- trace and remove 

         tmp->txtoken_map = void_map_new(ck_free_void);

         tmp->reload_ctx = 0;

         TitaxUserDic * const old = g_titax_user_dic;
         if (  old ) {

            g_titax_user_dic = NULL;

            void_map_free(old->md5val_map);

            void_map_free(old->txtoken_map);

            zm( old, sizeof(TitaxUserDic) );

            tx_safe_free(old);
         }

         g_titax_user_dic = tmp;
      }
   }
   return (g_titax_user_dic); 
}

bool  titax_user_dic_free_instance()
{
   bool ret=false;
   /* move OUT */
   tsa_lock(&g_user_dic_lock);

   TitaxUserDic* const tud = g_titax_user_dic;

   if ( tud ) {

      g_titax_user_dic = NULL;

      void_map_free(tud->md5val_map);
      tud->md5val_map = NULL;

      void_map_free(tud->txtoken_map);
      tud->txtoken_map = NULL;

      tud->reload_ctx = 0;

      tx_safe_free(tud);

      ret=true;
   }

   tsa_unlock(&g_user_dic_lock);
   return ret;
}

//------------------------------------------------------------------------------

void titax_user_dic_sort()
{
   tsa_lock(&g_user_dic_lock);

   TitaxUserDic* const tud=titax_user_dic_get_instance();

   if ( tud ) {

      void_map_sort(tud->txtoken_map);

      void_map_sort(tud->md5val_map);
   }

   tsa_unlock(&g_user_dic_lock);
}

//TODO::RETEST ME!!!!
TitaxCKey* titax_user_dic_add_token(const StringList * const restrict params)
{
   if (params && params->length>=5 && params->arr &&
      (params->arr[0] && *params->arr[0]) &&
      (params->arr[1] && *params->arr[1]) &&
      (params->arr[2] && *params->arr[2]) &&
      (params->arr[3] && *params->arr[3]) &&
      (params->arr[4] && *params->arr[4])
   ){
      ssize_t id = INVALID_;
      if (tx_safe_atol(params->arr[0], &id)) {
         tsa_lock(&g_user_dic_lock);
         TitaxUserDic* const tud=titax_user_dic_get_instance();
         if (tud) {
            TitaxCKey* ck = NULL;
            if (!(ck=FIND_TITAXCKEY_BY_TOKENVAL_NL_(params->arr[3], tud))){

               if (!void_map_add2(g_titax_user_dic->txtoken_map, params->arr[3],(ck=TitaxCKey_new(params->arr[3],params->arr[4],(size_t)id)))){
                  TitaxCKey_free(ck);
                  ck=NULL;
               }
            }
            tsa_unlock(&g_user_dic_lock);
            return ck;
         }
         tsa_unlock(&g_user_dic_lock);
      }
   }
   return NULL;
}

void token_map_add_elem( const char* const restrict token_md5, TitaxCKey* const restrict val ) 
{
   tsa_lock(&g_user_dic_lock);

   TitaxUserDic* const tud = titax_user_dic_get_instance();
   if ( tud ) {

      void_map_add2(tud->txtoken_map, token_md5, val);
   }

   tsa_unlock(&g_user_dic_lock);
}

void token_map_clear() 
{
   tsa_lock(&g_user_dic_lock);

   TitaxUserDic* const tud=titax_user_dic_get_instance();
   if ( tud ) {

      void_map_clear(tud->txtoken_map);
   }

   tsa_unlock(&g_user_dic_lock);
}


//---------------------------------------------------------------------
#ifdef TTN_ATESTS
TitaxUser* titax_user_dic_find_by_md5val_NL_4tests( const char* const restrict md5val )
{
   TitaxUserDic* tud = NULL;
   if (md5val && ((tud=g_titax_user_dic) || (tud=titax_user_dic_get_instance()))){

      return ((TitaxUser*)void_map_val(tud->md5val_map, md5val));
   }

   return NULL;
}
#endif

//---------------------------------------------------------------------
TitaxCKey* TitaxCKey_find_by_tokenval(const char* const restrict token_val)
{
   tsa_lock(&g_user_dic_lock);
   TitaxCKey* const r = FIND_TITAXCKEY_BY_TOKENVAL_NL_(token_val,NULL);
   tsa_unlock(&g_user_dic_lock);
   return r;
}

bool titax_user_get_name_by_md5( const char * const restrict md5val,
                                 char* const restrict uname, 
                                 const size_t uname_sz               )
{
   bool ret=false;
   tsa_lock(&g_user_dic_lock);

   TitaxUserDic* const tud = titax_user_dic_get_instance();
   if (tud) {

      TitaxUser * const user = (TitaxUser*) void_map_val(tud->md5val_map, md5val);
      if ( user ) {

         strlcpy(uname, user->name, uname_sz);
         ret=true;
      }
   }

   tsa_unlock(&g_user_dic_lock);
   return ret;
}
