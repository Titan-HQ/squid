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

#include "Extension.h"
#include "edgelib.h"
#include "global.h"
#include <assert.h>
#include <stdlib.h>
#include <string.h>


typedef struct{
   size_t   sz;
   char*    ext;
}t_file_ext;

// File extension.
typedef struct{
   size_t         count;
   t_file_ext *   extList;
} fileExtensionListType;

static fileExtensionListType* sFileExtensionTable = NULL;
pthread_rwlock_t sFileExtensionLock = PTHREAD_RWLOCK_INITIALIZER;


//---------------------------------------------------------------------
// File extension.
//---------------------------------------------------------------------
const char * fileExtensionBlocked(  const char* restrict src, 
                                    const size_t sz,
                                    const t_ttn_ext_categories category,
                                    const bool greedy_search               )
{
   if (sFileExtensionTable && sz && src &&  UWITHIN_( (uint32_t)ttn_ext_max, (uint32_t)category )){

      const fileExtensionListType* const list = &sFileExtensionTable[(size_t)category];
      assert(list);
      if (!greedy_search){
         if (list->count){
            uint_fast64_t i=0;
            const uint_fast64_t max=list->count;
            while(i<max){
               const char * const ext_=list->extList[i].ext;
               const size_t sz_=list->extList[i++].sz;
               if (ext_ && sz_==sz && !strncasecmp(src,ext_,sz)){
                  return ext_;
               }
            }
         }
         return NULL;
      }
      if (list->count){
         uint_fast64_t i=0;
         const uint_fast64_t max=list->count;
         while(i<max){
            const char * const ext_=list->extList[i].ext;
            const size_t sz_=list->extList[i++].sz;
            if (ext_ && sz_ && sz_<=sz && !strncasecmp(src,ext_,sz_)){
               return ext_;
            }
         }
      }
      
   }
   return NULL;
}

void fileExtensionPrintAll() 
{
   if (sFileExtensionTable){
      struct elems{size_t i_; const size_t max_; size_t parent_;};
      for (struct elems e={.max_=ttn_ext_max};e.i_<e.max_;++e.i_){
         for (struct elems se={.max_=sFileExtensionTable[e.i_].count,.parent_=e.i_};se.i_<se.max_;++se.i_){
            const char * const ext=sFileExtensionTable[se.parent_].extList[se.i_].ext;
            const size_t sz=sFileExtensionTable[se.parent_].extList[se.i_].sz;
            printf("Type:%zu:[%zu:%zu:%s]\n",se.parent_,se.i_,sz,(ext?ext:"<NULL>"));
         }
      }
   }
}

bool fileExtensionAdd(  const t_ttn_ext_categories category, 
                        const char * const ext              )
{
   if (ext &&  WITHIN_( (uint32_t)ttn_ext_min, (uint32_t)ttn_ext_max, (uint32_t)category)){
      // Check extensionTable is allocated
      if(!sFileExtensionTable){

         sFileExtensionTable = (fileExtensionListType*)tx_safe_calloc(ttn_ext_max, sizeof(fileExtensionListType));

         if(!sFileExtensionTable){
            //NEVER release the lock 
            //pthread_rwlock_unlock(&sFileExtensionLock);
            return false;
         }
      }
      
      // If it's NULL here, then someone screwed up the code above
      assert(sFileExtensionTable != NULL);

      // Add the file extension to the appropriate list
      fileExtensionListType * const fileext_=&sFileExtensionTable[(size_t)category];
      assert(fileext_);
      const size_t new_count = (fileext_->count+1);   
      fileext_->extList=(t_file_ext*)realloc(fileext_->extList, sizeof(t_file_ext) * new_count);

      if(fileext_->extList){
         fileext_->count = new_count;
         fileext_->extList[new_count - 1].sz=0;
         fileext_->extList[new_count - 1].ext = str_dup_ex(ext,&fileext_->extList[new_count - 1].sz);
         return true;
      }
   }
   return false;
}

bool fileExtensionsLoad(   const t_ttn_ext_categories category, 
                           const char * const exts, 
                           const char * const sep                 )
{
   if (exts && *exts && sep && *sep &&  WITHIN_( (uint32_t)ttn_ext_min, (uint32_t)ttn_ext_max, (uint32_t)category)){

      // Check extensionTable is allocated
      if(!sFileExtensionTable && !(sFileExtensionTable = (fileExtensionListType*)tx_safe_calloc(ttn_ext_max, sizeof(fileExtensionListType)))){
         //NEVER release the lock 
         return false;
      }

      //assert(sFileExtensionTable != NULL);  
      size_t esz=strlen(exts);
      char trimmed[esz+1];
      esz=trim_ex(exts,trimmed,sizeof(trimmed));
      ssize_t ectx=INVALID_;
      if (esz && (ectx=count_substr(trimmed,esz,sep,strlen(sep)))>0){
         fileExtensionListType * const fileext_=&sFileExtensionTable[(size_t)category];
         assert(fileext_);
         tx_safe_free(fileext_->extList);
         if ((fileext_->extList=(t_file_ext*)tx_safe_malloc(sizeof(t_file_ext) * (size_t)(ectx+1)))){
            char *lasts = NULL;
            char * extension = strtok_r(trimmed,"\n", &lasts);
            size_t new_count=0;
            while(
                  (extension)
                  && (extension+1)<=(trimmed+esz)  
                  && ((('.'==*extension)  && (++extension)) || (extension))
                  && ((new_count=(fileext_->count++)) || 1)
                  && (fileext_->extList[new_count].ext = str_dup_ex(extension,&fileext_->extList[new_count].sz))
                  && (extension = strtok_r(NULL,"\n", &lasts))
               );
            return (fileext_->count>0);
         }
      }
   }
   return false;
}

void fileExtensionsClear(const t_ttn_ext_categories category)
{
   struct {uint_fast64_t i_; fileExtensionListType * const fileext_;} e_={
      .fileext_=(sFileExtensionTable?&sFileExtensionTable[(size_t)category]:0)
   };
   if (e_.fileext_){
      for (;e_.i_<e_.fileext_->count;++e_.i_){
         tx_safe_free(e_.fileext_->extList[e_.i_].ext);
         e_.fileext_->extList[e_.i_].ext=NULL;
         e_.fileext_->extList[e_.i_].sz=0;
      }
      e_.fileext_-> count = 0;
      tx_safe_free(e_.fileext_->extList);
      e_.fileext_->extList = NULL;
   }
}
