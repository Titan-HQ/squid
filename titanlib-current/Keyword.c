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


#include "Keyword.h"
#include "ctree.h"
#include <assert.h>
#include <ctype.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#define MAX_KEYWORD_NAME  31
#define BLOCKING_SCORE 1000

TXATR bool convert_to_lower(char * const);

/* Protection around keywordctree accesses */
pthread_rwlock_t keywordctreeLock= PTHREAD_RWLOCK_INITIALIZER;

static 
CTREE* keywordctree = NULL;

typedef struct keywordNode_T{
   char name[MAX_KEYWORD_NAME+1];
   struct keywordNode_T *next;
} keyNode;

//---------------------------------------------------------------------
static keyNode* getNewNode(){
   return (keyNode*)tx_safe_calloc(1, sizeof(keyNode));
}/* End of getNewNode */

//---------------------------------------------------------------------

static bool addKeyInList(keyNode** const restrict keyList, char* const restrict keywordFound, const size_t ksz){

   if (keywordFound && convert_to_lower(keywordFound)){

      if (!*keyList){

         if ((*keyList = getNewNode()) && strlcpy((*keyList)->name,keywordFound,sizeof((*keyList)->name))>=sizeof((*keyList)->name)){
            tx_safe_free(*keyList);
            *keyList=NULL;
            return false;
         }

      } else {

         /* Go through the list to search whether this key exists or not 
          * If key exists, do nothing, else add
          */
         keyNode * node = *keyList;
         keyNode *lastNode = node;
         while(node != NULL){
            if(strncmp(node->name,keywordFound,ksz) == 0) break;
            lastNode = node;
            node = node->next;
         }

         if(!node){
            keyNode * newNode = getNewNode();
            if(newNode){
               if (strlcpy(newNode->name,keywordFound,sizeof(newNode->name))<sizeof(newNode->name)){
                  lastNode->next = newNode; 
               } else {
                  tx_safe_free(newNode);
                  return false;
               }
            }
         }

      }
      return true;
   }
   return false;

}/* End of addKeyInList */

//---------------------------------------------------------------------
void keywordsDestroy(){
   CtreeDestruct(keywordctree);
   keywordctree = NULL;
   keywordctree = Ctree();
}

//---------------------------------------------------------------------
int keywordAdd(const char* const restrict keyword, const size_t score){
   /* Check whether the entry is a valid one or not */

   assert(keyword && "keywordAdd failed");
   if (WITHIN_(1,MAX_KEYWORD_NAME,strlen(keyword))){
      CtreeAdd(keywordctree, keyword, score, 0);
      return 1;
   }
   return 0;
   
}

//---------------------------------------------------------------------
ssize_t scoreDocument(const char* matchStr, const size_t reqLen, int* const restrict blockedOutright, char* const restrict blockKeyWordList,const size_t bknsz){

   tsa_rd_lock(&keywordctreeLock);

   const char* const endStr = matchStr+reqLen;
   char keywordFound[MAX_KEYWORD_NAME + 1];
   (void)zm(keywordFound,sizeof(keywordFound));
   *blockedOutright = 0;
   keyNode* rootNode = NULL;
   size_t score=0;
   size_t success;

   do{
      const char* const tmpKeyword= matchStr;
      success=0;
      const size_t value= CtreeLookup(keywordctree,(const char ** const)&matchStr,endStr,&success);
      if(value){
         keywordFound[0]=0;
         ptrdiff_t d_=0;
         //it should always be a valid diff
         const bool diff_status=ptr_diff(matchStr,tmpKeyword,&d_);
         //report error and exit without assert
         assert( diff_status && "scoreDocument ptr diff failed\n");
         const size_t ksz=(size_t)d_;
         (void)strlcpy(keywordFound, tmpKeyword, STRLCPY_SIZE_(ksz,sizeof(keywordFound)));
         //Copy the keyword name to the list
         if (!addKeyInList(&rootNode,keywordFound,ksz)) {
            tsa_rd_unlock(&keywordctreeLock);
            return INVALID_;
         }
         // We've found a keyword that blocks the page outright
         if(value == BLOCKING_SCORE){
            *blockedOutright = 1;
            break;
         } else {
            score+=value;
         }
      } 
   } while(matchStr < endStr);

   /* that is why we can't remove the internal locking without refactoring */
   tsa_rd_unlock(&keywordctreeLock);

   /* Write out the keywords in the list and clean up the memory */
   if(rootNode){
      keyNode* node = rootNode;
      size_t len = 0;
      while(node != 0){
         keyNode* tmpNode = node;
         len += strlen(node->name);
         if(len < 470){
            //no point to report about errors
            if(blockKeyWordList[0] == '\0'){
               (void)strlcpy(blockKeyWordList,node->name,bknsz);
            } else {
               (void)strlcat(blockKeyWordList," ",bknsz);
               (void)strlcat(blockKeyWordList,node->name,bknsz);
            }
          }
          node = node->next;
          tx_safe_free(tmpNode);
          tmpNode = 0;
      }
   }
   return ((ssize_t)score);
}
