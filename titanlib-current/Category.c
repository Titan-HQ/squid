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


#include "Category.h"
#include <assert.h>
#include <threads.h>



static CATEGORY sCatTable[MAX_CATEGORIES];
pthread_rwlock_t sCatLock = PTHREAD_RWLOCK_INITIALIZER;
static CATEGORY custom_sCatTable[MAX_CATEGORIES];
pthread_rwlock_t custom_sCatLock = PTHREAD_RWLOCK_INITIALIZER;

//---------------------------------------------------------------------

TX_INTERNAL_INLINE
bool get_CategoryString_(const bool custom_cat,t_category cat,char * const restrict out, const size_t out_sz){
   if (cat){
      uint_fast64_t i=0;
      while(cat>0){
         if ((cat & 0x0000000000000001ULL) && UWITHIN_(MAX_CATEGORIES,i)){
            if (out[0])
               (void)strlcat(out, ",",out_sz);
            if (strlcat(out,(!custom_cat?sCatTable[i].name:custom_sCatTable[i].name),out_sz)>=out_sz){
               return true;
            }
         }
         cat >>= 1;
         ++i;
      }
      if (!out[0]) (void)strlcpy(out, "Unclassified",out_sz);
      return true;
   }
   return (false);
}
//---------------------------------------------------------------------
bool createCategoryString(const t_category cat,char * const out, const size_t out_sz ){
   return (get_CategoryString_(false,cat,out,out_sz));
}
//---------------------------------------------------------------------
CATEGORY * getCatTable(){
   return (sCatTable);
}
//---------------------------------------------------------------------
CATEGORY * getcustomCatTable(){
   return (custom_sCatTable);
}
//---------------------------------------------------------------------
char* categoryGetName(const t_category category){
   return  (UWITHIN_(MAX_CATEGORIES,category)?sCatTable[category].name:0);
}
//---------------------------------------------------------------------
void categoryClear(const t_category category){
   if (UWITHIN_(MAX_CATEGORIES,category))
      sCatTable[category].name[0]=0;
      //(void)zm(sCatTable[category].name, sizeof(sCatTable[category].name));
}
//---------------------------------------------------------------------
bool categorySetName(const t_category category, const char *name){
   return (UWITHIN_(MAX_CATEGORIES,category) && strlcpy(sCatTable[category].name,name,sizeof(sCatTable[category].name))<sizeof(sCatTable[category].name));
}
//---------------------------------------------------------------------
bool custom_createCategoryString(const t_category cat,char * const out,const size_t out_sz){
   return (get_CategoryString_(true,cat,out,out_sz));
}
//---------------------------------------------------------------------
char* custom_categoryGetName(const t_category category){
   return (UWITHIN_(MAX_CATEGORIES,category)?custom_sCatTable[category].name:0);
}
//---------------------------------------------------------------------
void custom_categoryClear(const t_category category){
   if (UWITHIN_(MAX_CATEGORIES,category))
      custom_sCatTable[category].name[0]=0;
      //(void)zm(custom_sCatTable[category].name,sizeof(custom_sCatTable[category].name));
}
//---------------------------------------------------------------------
bool custom_categorySetName(const t_category category, const char *const name){
   return (UWITHIN_(MAX_CATEGORIES,category) && strlcpy(custom_sCatTable[category].name,name,sizeof(custom_sCatTable[category].name))<sizeof(custom_sCatTable[category].name));
}
