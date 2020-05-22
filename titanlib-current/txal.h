/*
 * $Id$
 */

/* TO BE REMOVED */

#ifndef TXAL_H_
#define TXAL_H_

#include "mytypes.h"
#include "global.h"

#ifdef __cplusplus
extern "C" {
#endif


typedef enum{
   ia_none=0,
   ia_clear=1,
   ia_release=2,
   ia_free=3,
   ia_write=4,
   ia_override=5,
   ia_new=6,
   ia_dump=7,
   ia_run=8,
}t_a_item_action;

typedef struct{
   void *      vi;
   size_t      vibufsz;
   size_t      vilen;
   int64_t     viextra;
}t_a_item;

typedef struct{
   size_t            id;
   t_a_item*         item;
   void *            extra;
   t_a_item_action   action;
}t_lm_call;

#define MK_SCALL(a_act_,a_iid_,a_pitem_,a_ext_,a_method_) __extension__ ({       \
   t_lm_call v_var_;                                                             \
   v_var_.action=a_act_;                                                         \
   v_var_.id=a_iid_;                                                             \
   v_var_.item=a_pitem_;                                                         \
   v_var_.extra=a_ext_;                                                          \
   a_method_(&v_var_);                                                           \
})

typedef bool (t_looping_method)(t_lm_call * const);

typedef struct {
   size_t               c;
   size_t               s;
   size_t               default_grow_sz;
   t_a_item *           a;
   t_looping_method *   clear_items;
   t_looping_method *   clone_items;
   bool                 sorted;
}t_a_items_list;

#ifdef __cplusplus
}
#endif

TXATR bool al_init_ex(t_a_items_list** const ,const size_t,t_looping_method *const,t_looping_method *const,t_looping_method *const);
TXATR bool al_init(t_a_items_list ** const,const size_t,t_looping_method * const,t_looping_method * const);
TXATR bool al_simple_init(t_a_items_list **const,const size_t);
TXATR bool al_run(t_a_items_list*,t_looping_method *, const bool,const bool,void *);
TXATR bool al_clear_all(t_a_items_list * const);
TXATR bool al_clear(t_a_items_list * const, const ssize_t);
TXATR bool al_free(t_a_items_list ** const,const ssize_t,const bool);
TXATR bool al_free_all(t_a_items_list **const,const bool);
TXATR bool al_free_all_and_free_list(t_a_items_list **const,const bool);
TXATR bool al_release_all(t_a_items_list **const);
TXATR bool al_release(t_a_items_list **const,const int);
TXATR bool al_release_all_and_free_list(t_a_items_list**const);
TXATR size_t al_count(const t_a_items_list *const);
TXATR size_t al_sz(const t_a_items_list *const);
TXATR t_a_items_list * al_clone(t_a_items_list *,const bool);
TXATR bool al_clone_ex(t_a_items_list * ,t_a_items_list ** const,const bool);
TXATR bool al_copy(t_a_items_list *,t_a_items_list * const ,const bool);
TXATR bool al_grow(t_a_items_list **const,const size_t);
TXATR ssize_t al_push(t_a_items_list * const,void *);
TXATR ssize_t al_push_ex(t_a_items_list *,void *,const ssize_t);
TXATR ssize_t al_safe_push_ex(t_a_items_list *,void *,const size_t);
TXATR ssize_t al_push_array(t_a_items_list *, char *);
TXATR ssize_t al_safe_push_array(t_a_items_list *, char *);
TXATR bool al_pop(t_a_items_list *);
TXATR bool al_rpop(t_a_items_list *);
TXATR bool al_safe_pop(t_a_items_list *);
TXATR void * al_get(const t_a_items_list * const ,const ssize_t);
TXATR void * al(const t_a_items_list * const,const ssize_t);
TXATR void * al_raw_get(const t_a_items_list * const,const ssize_t);
TXATR bool al_get_ex(const t_a_items_list * const,const ssize_t, void **);
TXATR bool al_set(t_a_items_list * const,const ssize_t,void *);
TXATR bool al_set_ex(t_a_items_list * const,const ssize_t, void *,const ssize_t);
TXATR bool al_safe_set_ex(t_a_items_list * const,const ssize_t,void *,const size_t);
TXATR bool al_safe_set_array(t_a_items_list *const ,const ssize_t,char *);
TXATR t_a_item * al_item(t_a_items_list * const ,const ssize_t);
TXATR bool al_compact(t_a_items_list * const);
TXATR void al_dump(t_a_items_list * ,t_looping_method * const );
TXATR void al_rdump(t_a_items_list * , t_looping_method * const );
TXATR void al_raw(t_a_items_list * );


#endif /* TXAL_H_ */
