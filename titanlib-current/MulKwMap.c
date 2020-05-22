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
/*
- Author: jinyedge
- Comment:
   Library for multi-bytes keyword content filtering.
*/


#include "MulKwMap.h"
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static MulKwMap* g_mul_kw_map;
pthread_mutex_t g_mul_kw_lock = PTHREAD_MUTEX_INITIALIZER;

//---------------------------------------------------------------------
MulKwMap* mul_kw_map_get_instance(){
   if(!g_mul_kw_map){
      g_mul_kw_map = (MulKwMap*)tx_safe_malloc(sizeof(MulKwMap));
      g_mul_kw_map->map = string_map_new();
   }

   return g_mul_kw_map;
}

//---------------------------------------------------------------------
size_t mul_kw_map_size(){
   //optimistic
   return g_mul_kw_map->map->list->length;
}

//---------------------------------------------------------------------
void mul_kw_map_add(char*const  kw, const int score){
   char buf[10];
   (void)tx_safe_snprintf(buf,sizeof(buf), "%d", score);
   string_map_add(g_mul_kw_map->map, kw, buf);
}

//---------------------------------------------------------------------
void mul_kw_map_clear(){
   string_map_clear(g_mul_kw_map->map);
}

//---------------------------------------------------------------------
void mul_kw_map_print_all(){
   string_map_print_all(g_mul_kw_map->map);
}

//---------------------------------------------------------------------
size_t mul_kw_map_score_doc(const char* const restrict text, int* const restrict blocked_kw_flag, char * const restrict blocked_keywords, const size_t bksz){
   if(g_mul_kw_map && g_mul_kw_map->map->list->length!=0 && text && blocked_kw_flag && blocked_keywords && bksz){
      size_t sum = 0;
      int score = 0;
      size_t sz=(!blocked_keywords[0]?0:strlen(blocked_keywords));
      MulKwMap* const gmap_=g_mul_kw_map;
      const size_t max=gmap_->map->kw_list->length;
      char** const arr_=gmap_->map->kw_list->arr;
      for(size_t i = 0; i < max ; ++i){
         const char* const kw = arr_[i];
         if (kw){
            const size_t kw_sz=strlen(kw);
            if(kw_sz && strnstr(text, kw,kw_sz)){
               if((sz+kw_sz) < bksz-1){
                  //FIXME::implicit memmove;
                  const size_t r_=(blocked_keywords[0]?tx_safe_snprintf(blocked_keywords,bksz, "%s, %s", blocked_keywords, kw):tx_safe_snprintf(blocked_keywords, bksz,"%s", kw));
                  if (r_) sz=r_;
                  else continue;
               }
               if ((score = string_map_val_int(gmap_->map, kw))>0) sum += (size_t)score;
               if(score >= 1000){
                  *blocked_kw_flag = 1;
                  break;
               }
            }
         }
      }
      return sum;
   }
   return 0;
}
