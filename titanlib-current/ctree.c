
#include "ctree.h"
#include "normalize.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

static int memory_statistic=0;
static int treenode_statistic=0;
static int entrycnt_statistic=0;
static int duplicate_statistic=0;
static int insert_error_statistic=0;

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */
int get_Ctree_memory_statistic()
{
    return(memory_statistic);
}
////////////////////////////////////////////////////////////////////////////////

//
// Character tree for lexical lookup
//
// Tree nodes need not have branches (branches are contained
// in the array of tree node pointers (ptr).
// Lexemes are terminated with is_lexeme flag 
// in tree node. When is_lexeme flag is true the
// value of val (the score) of the lexeme is valid.
// In the case where one word is a prefix of another
// a node marked as a lexeme may have a valid array
// of tree node pointer (ptr) contining the lexical
// enties for which This current lexeme is a prefix.
//

void CtreeDestruct(CTREE* const This){
   if(This){
      if(This->ptr){
         uint_fast64_t i;
         for ( i=0; i<NORMALIZE_SIZE; ++i){
            if( This->ptr[i]!=NULL ){
               CtreeDestruct(This->ptr[i]);
               This->ptr[i]=NULL;
            }
         }
         free(This->ptr);
      }
      free(This);
   }
}

//
// Ctree
//
// Construtor for the Ctree node
//
CTREE* Ctree(){
   CTREE* const This = calloc(1, sizeof(CTREE));
   memory_statistic+=sizeof(CTREE);
   treenode_statistic+=1;

   This->ptr=NULL;
   This->val=0;
   This->org=0;
   This->is_constant=(size_t)false;
   This->is_lexeme=(size_t)false;
   return This;
}

//
// CtreePrepareContent
//
// Initializes the array of Tree node pointers in
// a Tree node inpreparation for adding a lexical entry
// 
void CtreePrepareContent(CTREE* const This){
   if ( This->ptr == NULL ){
      This->ptr = calloc(NORMALIZE_SIZE+1, sizeof(CTREE*)); 
      memory_statistic+=sizeof(CTREE*)*(NORMALIZE_SIZE+1);
   }
}

//
// CtreeAdd
//
// Adds a lexeme pointed to by x to the 
// character tree
//
void CtreeAdd(CTREE* const This, const char* const x, const size_t score, const size_t constant){

   if ( N[(u_char)*x] == 0 ){
      // attempt to insert a non normalized character
      insert_error_statistic++;
      return;
   }
   CtreePrepareContent(This);
   if( This->ptr[N[(u_char)*x]]==NULL ){
      //
      // If there is no entry in the array then add one
      //
      This->ptr[N[(u_char)*x]]=Ctree();
   }
   if ( *(x+1) == '\0' ){
      if ( This->ptr[N[(u_char)*x]]->is_lexeme ){
      duplicate_statistic++;
      }
      // This is the last character of the lexeme
      This->ptr[N[(u_char)*x]]->val=score;
      This->ptr[N[(u_char)*x]]->is_lexeme=(size_t)true;
      if ( constant ){
         // ie an entry that cannot be deleted
         This->ptr[N[(u_char)*x]]->org=score;
         This->ptr[N[(u_char)*x]]->is_constant=(size_t)true;
      }
   } else {
      // not last character so continue adding
      CtreeAdd(This->ptr[N[(u_char)(*x)]],x+1,score,constant);
   }
}

//
// CtreeLookup
//
// Seach for lexemes from memory pointer current.
// If lexeme if found memory pointer current advanced
// past lexeme in input and score for lexeme returned.
// no match found then current advanced by 1 character 
// and score of 0 returned.
//
size_t CtreeLookup(const CTREE* const This, const char** const current, const char* const limit,size_t * const success) {
   CTREE* next = 0;
   if (*current!=limit &&  This && This->ptr && (next=This->ptr[N[(u_char)**current]])){
      size_t newresult=0;
      if ( next->is_lexeme ) {
      // lexical lookup will succeed
         if (next->ptr){
            // save This result and use it if no longer
            // match is found
            const char* saved_position = ++(*current);
            newresult = CtreeLookup(next, current, limit, success);
            if ( *success ) return newresult;
            *current=saved_position;
         } else {
            // There are no longer matches so advance
            // past end of lexeme and return
            (*current)++;
         }
         *success=1;
         return next->val;
      }
      // Not a lexeme but in dictionary
      const char* saved_position = ++(*current);
      newresult = CtreeLookup(next, current, limit, success);
      if ( *success ) return newresult;
      *current=saved_position;
      return 0;
   }
   (void)(current && ((*current)++));
   *success=0;
   return 0;
}

//
// CtreeDelete
//
// Doesnt modify tree structure, only sets score to 0 
// or restores org value for constant entries
//
void CtreeDelete(CTREE* const This, const  char* const x){
   if ( !This || !x ) return;
   if ( *x=='\0' ){
      //
      // This is the entry we are lookin for
      //
      if ( !This->is_lexeme ){
         return;        // cant happen
      }
      if ( This->is_constant ) {
         This->val = This->org;
      } else{
         This->val =0;
      }
   } else {
      //
      // Keep lookin for last value
      //
      if(This->ptr != NULL){
         CtreeDelete(This->ptr[N[(u_char)(*x)]],x+1);
      }
   }
}

void CtreePrintStats(){
   (void)printf("Ctree memory used   = %d\n",memory_statistic);
   (void)printf("Ctree nodes         = %d\n",treenode_statistic);
   (void)printf("Ctree entries       = %d\n",entrycnt_statistic);
   (void)printf("Ctree duplicates    = %d\n",duplicate_statistic);
   (void)printf("Ctree insert errors = %d\n",insert_error_statistic);
}
