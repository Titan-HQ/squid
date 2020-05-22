/*
 *  $Id$
 */

#include "txal.h"
#include "global.h"
#include "mytypes.h"
#include <assert.h>

/* TO BE REMOVED */

#define LOOP_MAX  0xffff
typedef struct{
   bool                          run_in_reverse;
   bool                          use_raw;
   t_a_item_action               action;
   t_a_items_list **             plist; 
   t_looping_method *            method;
   void *                        extra_arg;
} t_al_looper_call;

typedef struct{
   t_a_item_action      pAction;
   t_a_item *           pDest;
   void*                pVal;
   size_t               pValSZ;
   size_t               pValBufSZ;
   int64_t              pExtra;
} t_al_item_value_ex_call;

static  bool al_default_loop_cleaner_(t_lm_call * const);
static  bool al_default_loop_deep_cloner_(t_lm_call * const);
static  bool al_default_loop_printer_(t_lm_call * const);
static  bool al_item_value_ex_(t_al_item_value_ex_call * const);
static  bool al_looper5_(t_al_looper_call * const );

#define DEFAULT_LOOPER__          al_looper5_
#define DEFAULT_VALUE_OPERATOR__  al_item_value_ex_

#define MK_AL_LOOPER_CALL(a_list_,a_runmethod_,a_runaction_,                     \
                           a_extra_,a_reverse_,a_raw_) __extension__ ({          \
   t_al_looper_call v_var_;                                                      \
   v_var_.plist=a_list_;                                                         \
   v_var_.method=a_runmethod_;                                                   \
   v_var_.action=a_runaction_;                                                   \
   v_var_.extra_arg=a_extra_;                                                    \
   v_var_.run_in_reverse=a_reverse_;                                             \
   v_var_.use_raw=a_raw_;                                                        \
   DEFAULT_LOOPER__(&v_var_);                                                    \
})

#define MK_AL_ITEM_VALUE_EX_CALL(a_dest_,a_action_,a_val_,a_valsz_,              \
                                 a_valbufsz_,a_extra_) __extension__ ({          \
   t_al_item_value_ex_call v_var_;                                               \
   v_var_.pDest=a_dest_;                                                         \
   v_var_.pAction=a_action_;                                                     \
   v_var_.pVal=a_val_;                                                           \
   v_var_.pValSZ=a_valsz_;                                                       \
   v_var_.pValBufSZ=a_valbufsz_;                                                 \
   v_var_.pExtra=a_extra_;                                                       \
   DEFAULT_VALUE_OPERATOR__(&v_var_);                                            \
})

/*
 * =================================================================================================================================================
 */

struct elems {
    uint_fast64_t i_;
    uint_fast64_t mx_;
    t_a_item *const a_;
    t_lm_call call_;
    t_looping_method * method_;
};

bool al_looper5_(t_al_looper_call * const  restrict pcall){
   if (pcall && pcall->method){
      const t_a_items_list * const l_=(*(pcall->plist));
      if (l_){
         const size_t mx=(!pcall->use_raw?l_->c:l_->s);
         if (mx>0){
            if (!pcall->run_in_reverse){
               CLUN_(8)
               for (struct elems e={
                  .mx_=mx,
                  .a_=l_->a,
                  .call_.extra=pcall->extra_arg,
                  .call_.action=pcall->action,
                  .method_=pcall->method
               };e.i_<e.mx_;++e.i_){
                  e.call_.id=e.i_;
                  e.call_.item=&(e.a_[e.i_]);
                  if (e.method_(&e.call_)) continue;
                  break;
                  //if (!e.method_(&e.call_))  return (true);
               }
               return true;
            }
            CLUN_(8)
            for (struct elems e={
               .mx_=mx,
               .a_=l_->a,
               .call_.extra=pcall->extra_arg,
               .call_.action=pcall->action,
               .method_=pcall->method
            };e.i_<e.mx_;){
               e.call_.id=e.mx_;
               e.call_.item=&(e.a_[--e.mx_]);
               if (e.method_(&e.call_)) continue;
               break;
               //if (!e.method_(&e.call_))  return (true); ;
            }
            return true;
         }
      }
   }
   return false;
}


TX_INTERNAL_INLINE 
void al_print_item_(const size_t id, const t_a_item * const item){
   (void)printf("> item:%zu:(%zu:%s|%ld)\n",id,item->vilen,(char*)item->vi,item->viextra);
}

bool al_item_value_ex_(t_al_item_value_ex_call * const  pcall){

   if (pcall && pcall->pDest){
      t_a_item * const pDest=pcall->pDest;
      switch (pcall->pAction){
         case ia_free:{
            if (pDest->vi)
            tx_safe_free(pDest->vi);
         }
         /* fall through */

         case ia_release:{
            pDest->vi=NULL;
            pDest->vibufsz=0;
            pDest->viextra=0;
         }
         /* fall through */

         case ia_clear:{
            pDest->vilen=0;
            return true;
         }
         /* no break */

         case ia_write:{
            pDest->vi=pcall->pVal;
            pDest->vibufsz=pcall->pValBufSZ;
            pDest->vilen=pcall->pValSZ;
            pDest->viextra=pcall->pExtra;
            return true;
         }
         /* no break */

         case ia_override:{
            if (pcall->pValSZ && pcall->pVal){
               (void)((pcall->pValSZ>pcall->pValBufSZ) && (pcall->pValBufSZ=pcall->pValSZ));
               if (pcall->pValBufSZ<=pDest->vibufsz){
                  (void)zm(pDest->vi,pDest->vibufsz);
                  (void)tx_safe_memcpy(pDest->vi,pcall->pVal,pcall->pValSZ);
                  pDest->vilen=pcall->pValSZ;
                  pDest->viextra=pcall->pExtra;
                  return true;
               }
               void * const tmp=tx_safe_realloc(pDest->vi,pcall->pValBufSZ);
               if  (tmp){
                  pDest->vibufsz=pcall->pValBufSZ;
                  pDest->vi=tmp;
                  (void)tx_safe_memcpy(pDest->vi,pcall->pVal,pcall->pValSZ);
                  pDest->vilen=pcall->pValSZ;
                  pDest->viextra=pcall->pExtra;
                  return true;
               }

            }
            return false;
         }
         /* no break */

         //default
         case ia_none: 
         /* fall through */
         case ia_new:  
         /* fall through */
         case ia_dump: 
         /* fall through */
         case ia_run:return false;
      }
   }
   return false;
}

TX_INTERNAL_INLINE
bool al_item_value_(t_a_item * const restrict pDest,const t_a_item * const restrict pSource,const t_a_item_action pAction){
   return (MK_AL_ITEM_VALUE_EX_CALL(pDest,pAction,pSource->vi,pSource->vilen,pSource->vibufsz,pSource->viextra));
}

bool al_default_loop_cleaner_(t_lm_call * const restrict scall){
   return (MK_AL_ITEM_VALUE_EX_CALL(scall->item,scall->action,0,0,0,0));
}

bool al_default_loop_deep_cloner_(t_lm_call * const restrict scall){
   return (al_item_value_(&((t_a_item*)scall->extra)[scall->id],scall->item,scall->action));
}

bool al_default_loop_printer_(t_lm_call * const restrict scall){
   if  (scall && scall->action==ia_dump){
      (void)al_print_item_(scall->id,scall->item);
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
bool al_grow_ex_(t_a_items_list ** const restrict pList,const size_t pNewSZ){
   if (!pNewSZ){return false;}
   if ((*pList)){
      if ((*pList)->s>pNewSZ){return false;}
      if ((*pList)->s==pNewSZ){return true;}
   } else {
      (*pList)=(t_a_items_list*)tx_safe_malloc(sizeof (t_a_items_list));
      (*pList)->c=0;
      (*pList)->s=0;
      (*pList)->default_grow_sz=0;
      (*pList)->clear_items=0;
      (*pList)->clone_items=0;
   }
   //WARNING !!!!
   (*pList)->a=tx_safe_realloc_ex((*pList)->default_grow_sz?(*pList)->a:0,(*pList)->s * sizeof(t_a_item),pNewSZ * sizeof(t_a_item));
   (void)(!((*pList)->default_grow_sz) && ((*pList)->default_grow_sz=pNewSZ));
   (*pList)->s=pNewSZ;
   return true;

}

TX_INTERNAL_INLINE
bool al_clear_items_ex_(t_a_items_list ** pList,const t_a_item_action pAction,const ssize_t pID,const bool pUseRaw,void * pExtra){
   if (INVALID_<pID){
      if (!pUseRaw){
         if ((size_t)pID>(*pList)->c-1){return false; }
      } else {
         if ((size_t)pID>(*pList)->s-1){return false; }
      }
      return  (MK_SCALL (pAction,(size_t)pID,&((*pList)->a[(size_t)pID]),0,(*pList)->clear_items));
   }
   if (!(*pList)){return (false);} 
   if (! (MK_AL_LOOPER_CALL (pList,(*pList)->clear_items,pAction,pExtra,false,pUseRaw))){
      return false;
   }
   (*pList)->c=0;
   return true;
}

TX_INTERNAL_INLINE
bool al_free_item_list_(t_a_items_list ** pSource,const t_a_item_action pAction,const bool pUseRaw,void * extra){
   if ((*pSource)){
      al_clear_items_ex_(pSource,pAction,INVALID_,pUseRaw,extra);
      tx_safe_free((*pSource)->a);
      (*pSource)->a=NULL;
      (*pSource)->s=0;
      (*pSource)->c=0;
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
bool al_shallow_copy_items_(const t_a_item * const restrict pSource,const size_t pSourceSZ, t_a_item * const restrict pDest, const size_t pDestSZ){
   return (pSource && pDest && pSourceSZ<=pDestSZ && (!pSourceSZ || tx_safe_memcpy(pDest,pSource,pSourceSZ*sizeof(t_a_item))));
}

TX_INTERNAL_INLINE
bool al_deep_copy_items_(t_a_items_list ** pSource, t_a_items_list *const* const restrict pDest){
   return(pSource && (*pSource) && *pDest &&  (*pSource)->c && (MK_AL_LOOPER_CALL(
         pSource,
         (*pSource)->clone_items,
         ia_override,
         (*pDest)->a,
         false,
         false)
      ));
}

TX_INTERNAL_INLINE
bool al_copy_on_init_(t_a_items_list * pSource,t_a_items_list ** const restrict pOut, const size_t pIOSZ, const bool pDeep){
   
   if (pOut && (!pSource ||  pSource->s<=pIOSZ) && al_grow_ex_(pOut,pIOSZ)){
      if (pSource && (*pOut)){
         (*pOut)->c=pSource->c;
         (*pOut)->default_grow_sz=(pSource->default_grow_sz*2);
         (*pOut)->clear_items=pSource->clear_items;
         (*pOut)->clone_items=pSource->clone_items;
         return (pDeep?al_deep_copy_items_(&pSource,pOut)
               :al_shallow_copy_items_(pSource->a,pSource->s,(*pOut)->a,(*pOut)->s));
      }
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
bool  al_free_(t_a_items_list ** const restrict pSource,const t_a_item_action pAction,const bool pUseRaw, void * extra){
   if (*pSource){
      al_free_item_list_(pSource,pAction,pUseRaw,extra);
      (*pSource)->clear_items=NULL;
      (*pSource)->clone_items=NULL;
      (*pSource)->default_grow_sz=0;
      (*pSource)->s=0;
      tx_safe_free(*pSource);
      *pSource=0;
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
bool al_remove_(t_a_items_list * pList,const ssize_t pID,const t_a_item_action pAction){
   if (pList){
      if (INVALID_<pID){
         (void)al_clear_items_ex_(&pList,pAction,(pList->c==(size_t)pID?pID-1:pID),false,NULL);
         (void)(pList->c==(size_t)pID && (pList->c--));
         return true;
      }
      (void)al_clear_items_ex_(&pList,pAction,pID,false,NULL);
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
ssize_t al_item_set_value_(t_a_items_list ** const restrict pList,const ssize_t pItemID,void * restrict pValue, const size_t pValueSZ,const bool pOverride,const int64_t pExtra){
   if ( (*pList) && INVALID_<pItemID && (size_t)pItemID<=(*pList)->c &&
         (((*pList)->c<(*pList)->s) ||   (al_grow_ex_(pList,(*pList)->s+(*pList)->default_grow_sz))) && 
          (MK_AL_ITEM_VALUE_EX_CALL(&((*pList)->a[pItemID]),(pOverride?ia_override:ia_write),pValue,pValueSZ,0,pExtra))){ 
      ((size_t)pItemID==(*pList)->c) && ((*pList)->c++);
      return pItemID;
   }
   return INVALID_;
}

TX_INTERNAL_INLINE
size_t al_get_gap_size_(const t_a_items_list * const restrict pList, ssize_t * const restrict pStartIndex){
   *pStartIndex=INVALID_;
   if (pList){
      uint_fast64_t i=0;
      struct elems{uint_fast64_t * const i_; const uint_fast64_t max_; const t_a_item * const sarr_;ssize_t * const index_;};
      for (struct elems e={
         .i_=&i,
         .max_=pList->c,
         .sarr_=pList->a,
         .index_=pStartIndex
      };*e.i_<e.max_;++(*e.i_)){
         if (INVALID_<*e.index_){
            if  (e.sarr_[*e.i_].vi && e.sarr_[*e.i_].vilen) return *e.i_;
            continue;
         }
         (void)( ! (e.sarr_[*e.i_].vi && e.sarr_[*e.i_].vilen) && (*e.index_=(ssize_t)*e.i_));
      }
      return i; 
   }
   return 0;
}

TX_INTERNAL_INLINE 
ssize_t al_get_frag_size_(const t_a_items_list * const  restrict pList, ssize_t const fstart){
   if (pList && INVALID_<fstart){
      ssize_t ctx=INVALID_;
      struct elems{size_t i_;const size_t max_;const t_a_item * const sarr_; ssize_t * const ctx_; }; 
      for (struct elems e={
         .i_=(size_t)fstart,
         .max_=pList->c,
         .sarr_=(const t_a_item * const)pList->a,
         .ctx_=&ctx
      };e.i_<e.max_;++e.i_){
         if (! (e.sarr_[e.i_].vi && e.sarr_[e.i_].vilen))return (*e.ctx_);
         if ((*e.ctx_)++==INVALID_) ++(*e.ctx_);
      }
      return ctx;
   }
   return INVALID_;
}

/*
 * =================================================================================================================================================
 * PUBLIC
 */

bool al_init_ex(t_a_items_list**const restrict pList,const size_t pSize,t_looping_method * const pInitItemMethod,t_looping_method * const pClearItemsMethod,t_looping_method * const pCloneItemsMethod){
   if (pSize && pList && !(*pList) && al_copy_on_init_(0,pList,pSize,false)){ 
      ((*pList)->clear_items=(pClearItemsMethod?pClearItemsMethod:&al_default_loop_cleaner_));
      ((*pList)->clone_items=(pCloneItemsMethod?pCloneItemsMethod:&al_default_loop_deep_cloner_));
      return ((pInitItemMethod && ((*pList)->c=pSize))? (MK_AL_LOOPER_CALL(pList,pInitItemMethod,ia_new,0,false,false)):true);
   }
   return false;
}

bool al_run(t_a_items_list* pList,t_looping_method * pRunMethod,const bool pRunReversed,const bool pUseRaw,void * pExtra){
   if (pList && (pRunMethod && (pList->c || pUseRaw))){
      return  (MK_AL_LOOPER_CALL(&pList,pRunMethod,ia_run,pExtra,pRunReversed,pUseRaw));
   }
   return false;
}

t_a_items_list * al_clone(t_a_items_list * pSource,const bool pDeep){
   if (pSource){
      t_a_items_list * ret=NULL;
      if (al_copy_on_init_(pSource,&ret,pSource->s,pDeep)){
         return ret;
      }
   }
   return NULL;
}

bool al_clone_ex(t_a_items_list * pSource,t_a_items_list ** const restrict pDest, const bool pDeep){
   return (pSource && al_copy_on_init_(pSource,pDest,pSource->s,pDeep));
}

bool al_copy(t_a_items_list * pSource,t_a_items_list * pDest,const bool pDeep){
   return (pSource && pDest && al_copy_on_init_(pSource,&pDest,pDest->s,pDeep));
}

bool al_clear_all(t_a_items_list * plist){
   return  (al_clear_items_ex_(&plist,ia_clear,INVALID_,false,NULL));
}

bool al_clear(t_a_items_list * plist, const ssize_t pID){
   return  (al_clear_items_ex_(&plist,ia_clear,pID,false,NULL));
}

bool al_free(t_a_items_list ** const restrict plist,const ssize_t pID, const bool pForceFree){
   return  (al_clear_items_ex_(plist,ia_free,pID,pForceFree,NULL));
}

bool al_free_all(t_a_items_list ** const restrict plist, const bool pForceFree){
   return  (al_clear_items_ex_(plist,ia_free,INVALID_,pForceFree,NULL));
}

bool al_free_all_and_free_list(t_a_items_list **const restrict plist,bool pForceFree){
   return  (al_free_(plist,ia_free,pForceFree,NULL));
}

bool al_release(t_a_items_list** const restrict plist,const int pID){
   return  (al_clear_items_ex_(plist,ia_release,pID,false,NULL));
}

bool al_release_all(t_a_items_list**const restrict plist){
   return  (al_clear_items_ex_(plist,ia_release,INVALID_,false,NULL));
}

bool al_release_all_and_free_list(t_a_items_list**const restrict plist){
   return  (al_free_(plist,ia_release,false,NULL));
}

size_t al_count(const t_a_items_list * restrict plist){
   return (plist?plist->c:0);
}

size_t al_sz(const t_a_items_list * restrict plist){
    return (plist?plist->s:0);
}

bool al_grow(t_a_items_list **const restrict pList,const size_t pNewSZ){
   return  (al_grow_ex_(pList,pNewSZ));
}

ssize_t al_push(t_a_items_list * pList,void * restrict pValue){
   return (pList?al_item_set_value_(&pList,(ssize_t)pList->c,pValue,0,false,0):INVALID_);
}

ssize_t al_push_ex(t_a_items_list * pList,void * restrict pValue,const int64_t pExtra){
   return (pList?al_item_set_value_(&pList,(ssize_t)pList->c,pValue,0,false,pExtra):INVALID_);
}

ssize_t al_safe_push_ex(t_a_items_list * pList,void * restrict pValue,const size_t pValSZ){
   return (pList?al_item_set_value_(&pList,(ssize_t)pList->c,pValue,pValSZ,true,0):INVALID_);
}

ssize_t al_push_array(t_a_items_list * pList,char * restrict pValue){
   assert(pValue && "al_push_array failed");
   return (pList?al_item_set_value_(&pList,(ssize_t)pList->c,(void *)pValue,strlen(pValue),false,0):INVALID_);
}

ssize_t al_safe_push_array(t_a_items_list * pList,char * restrict pValue){
   assert(pValue && "al_safe_push_array failed");
   return (pList?al_item_set_value_(&pList,(ssize_t)pList->c,pValue,strlen(pValue),true,0):INVALID_);
}

bool al_pop(t_a_items_list * const restrict pList){
   return (pList && pList->c && al_remove_(pList,(ssize_t)pList->c,ia_free));
}

bool al_rpop(t_a_items_list * const restrict pList){
   if (!pList || !pList->c) {return false;}
   return  (al_remove_(pList,(ssize_t)pList->c,ia_release));
}

bool al_safe_pop(t_a_items_list * const restrict pList){
   if (!pList || !pList->c) {return false;}
   return  (al_remove_(pList,(ssize_t)pList->c,ia_clear));
}

void * al_get(const t_a_items_list * const restrict pList,const ssize_t pID){
   if (pList && pList->a && INVALID_<pID && (size_t)pID<pList->c)
      return pList->a[(size_t)pID].vi;
   return 0;
}

void * al_raw_get(const t_a_items_list * const restrict pList,const ssize_t pID){
   if (pList && pList->a && INVALID_<pID && (size_t)pID<pList->s)
      return pList->a[(size_t)pID].vi;
   return 0;
}


bool al_get_ex(const t_a_items_list * const restrict pList,const ssize_t pID, void ** restrict pOut){
   if (pList && pList->a && INVALID_<pID && (size_t)pID<=pList->c-1){
      (*pOut)=pList->a[(size_t)pID].vi;
      return true;
   }
   return false;
}

bool al_set(t_a_items_list * pList,const ssize_t pID, void * restrict pValue){
   return (pList && pList->a && INVALID_<pID && (size_t)pID<=pList->c-1 && al_item_set_value_(&pList,pID,pValue,0,false,0)>=0);
}

bool al_set_ex(t_a_items_list * pList,const ssize_t pID, void * restrict pValue,const int64_t pExtra){
   return (pList && pList->a && INVALID_<pID && (size_t)pID<=pList->c-1 && al_item_set_value_(&pList,pID,pValue,0,false,pExtra)>=0);
}

bool al_safe_set_ex(t_a_items_list * pList,const ssize_t pID, void * restrict pValue,const size_t pValSZ){
   return (pList && pList->a && INVALID_<pID && (size_t)pID<=pList->c-1 && al_item_set_value_(&pList,pID,pValue,pValSZ,true,0)>=0);
}

bool al_safe_set_array(t_a_items_list * pList,const ssize_t pID, char * restrict pValue){
   return (pList && pList->a && INVALID_<pID && (size_t)pID<=pList->c-1 && al_item_set_value_(&pList,pID,pValue,(pValue?strlen(pValue):0),true,0)>=0);
}

t_a_item * al_item(t_a_items_list * pList,const ssize_t pID){
   return  (pList && pList->a && INVALID_<pID && (size_t)pID<=pList->c-1?&pList->a[(size_t)pID]:NULL);
}

bool al_compact(t_a_items_list * const restrict  pList){
   ssize_t gidx=0;
   uint_fast64_t idx=0;
   while(idx<LOOP_MAX){
      size_t gs=al_get_gap_size_(pList,&gidx);
      if (INVALID_==gidx){
         //no gaps at all or anymore
         return 1;
      }
      ssize_t fsz=al_get_frag_size_(pList,(ssize_t)gs);
      if ( gs>=pList->c && INVALID_==fsz){
         (void)((size_t)gidx<(pList->c-1) && (pList->c=(size_t)(gidx+1)));
         return 1;
      }
      assert(INVALID_<fsz && "al_compact err1");
      const int64_t gb_idx=(int64_t)(gs-(size_t)gidx);
      assert(gb_idx>=0 && "al_compact err2");
      t_a_item gap_b[(size_t)gb_idx];
      (void)tx_safe_memcpy(gap_b,pList->a+(size_t)gidx,sizeof(gap_b));
      (void)tx_safe_memcpy(pList->a+(size_t)gidx,pList->a+gs, ((size_t)fsz)*sizeof(t_a_item));
      (void)tx_safe_memcpy(pList->a+(size_t)gidx+(size_t)fsz,gap_b,sizeof(gap_b));
      pList->c=((size_t)gidx+(size_t)fsz);
      idx++;
   }
   return 0;
}

void al_dump(t_a_items_list * pList, t_looping_method * const pPrinterMethod){
   if (!pList){(void)printf("list is null:\ncount:0\nsize:0\n");return;}
   (void)printf("list:\ncount:%zu\nsize:%zu\nDefPrinter:%d\n",pList->c,pList->s,pPrinterMethod?0:1);
   if (!pPrinterMethod){
      MK_AL_LOOPER_CALL(&pList,&al_default_loop_printer_,ia_dump,0,false,false);
      return;
   }
   MK_AL_LOOPER_CALL(&pList,pPrinterMethod,ia_dump,0,false,false);

}

void al_rdump(t_a_items_list * pList,t_looping_method * const  pPrinterMethod){
   if (!pList){printf("list is null:\ncount:0\nsize:0\n");return;}
   (void)printf("list:\ncount:%zu\nsize:%zu\nDefPrinter:%d\n",pList->c,pList->s,pPrinterMethod?0:1);
   if (!pPrinterMethod){
      MK_AL_LOOPER_CALL(&pList,&al_default_loop_printer_,ia_dump,0,true,false);
       return;
   }
   MK_AL_LOOPER_CALL(&pList,pPrinterMethod,ia_dump,0,true,false);
}

void al_raw(t_a_items_list * pList){
   if (!pList){(void)printf("RAW -> list is null:\ncount:0\nsize:0\n");return;}
   (void)printf("RAW -> list:\ncount:%zu\nsize:%zu\n",pList->c,pList->s);
   MK_AL_LOOPER_CALL(&pList,&al_default_loop_printer_,ia_dump,0,false,true);
}

void * al(const t_a_items_list * const restrict pList,const ssize_t pID){
   return (al_get(pList,pID));
}

bool al_init(t_a_items_list ** const restrict pList,const size_t pSize,t_looping_method * const pClearItemsMethod,t_looping_method * const pCloneItemsMethod){
   return (al_init_ex(pList,pSize,NULL,pClearItemsMethod,pCloneItemsMethod));
}

bool al_simple_init(t_a_items_list **const restrict pList,const size_t pSize){
   return (al_init(pList,pSize,NULL,NULL));
}
