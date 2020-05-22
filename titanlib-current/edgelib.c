/*
 * $Id$
 */

#include "edgelib.h"
#include "global.h"
#include "txhash.h"
#include <arpa/inet.h>
#include <assert.h>
#include <ctype.h>
#include <search.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>


////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */

static unsigned int g_StringList_instances_c = 0;
static unsigned int g_StringList_instances_d = 0;
unsigned int get_StringList_active_instances()
{
    return( g_StringList_instances_c - g_StringList_instances_d );
}

static unsigned int g_StringMap_instances_c = 0;
static unsigned int g_StringMap_instances_d = 0;
unsigned int get_StringMap_active_instances()
{
    return( g_StringMap_instances_c - g_StringMap_instances_d);
}

////////////////////////////////////////////////////////////////////////////////


TXATR char* str_dup(const char*const);
static int str_cmp(const void*, const void*);
static int str_rcmp(const void*, const void*);
static void raii_free_( void * p )
{
    void * p_ = * (void **) p;
    if ( p_ )
        free(p_);
}

#define LIST_REMOVE_LAST_TEMPLATE_(a_list_cptr_,a_free_code_) __extension__ ({   \
   if ( (a_list_cptr_) && (a_list_cptr_)->size>0 ){                              \
      void** v_arr_=(void**)(a_list_cptr_)->arr;                                 \
      if (v_arr_){                                                               \
         {                                                                       \
            a_free_code_;                                                        \
         }                                                                       \
         v_arr_[--(a_list_cptr_)->size]=NULL;                                    \
         (a_list_cptr_)->length = (a_list_cptr_)->size;                          \
         true;                                                                   \
      }                                                                          \
   }                                                                             \
   false;                                                                        \
})

//------------------------------------------------------------------------
// String.
//------------------------------------------------------------------------

//------------------------------------------------------------------------
//REDUNDAND
size_t str_starts_with(const char* const restrict line, const char*const restrict kw){
   // Check input.
   if(IS_EMPTY(line) || IS_EMPTY(kw)){
      return 0;
   }

   if(strncmp(line, kw, strlen(kw)) == 0){
      return 1;
   }
   return 0;
}
//------------------------------------------------------------------------

TX_INTERNAL_INLINE
ssize_t parse_kv_(const char * kv, const size_t kvsz, const char * const restrict key, const size_t ksz, const char** restrict out_val){
   ssize_t i=0;
   if (kv && kvsz && key && ksz && kvsz>ksz && (i=ttn_strncspn(kv,kvsz," ",1))>0){
      const char * val=(const char *)(kv+i);
      ptrdiff_t dsz=0;
      if (ptr_diff(val,kv,&dsz) && dsz==(ptrdiff_t)ksz && *val==' ' && val++){
         (void)(out_val && (*out_val=val));
         if ( (i=(ssize_t)(kvsz-(ksz+1)))>0 && (size_t)i==strlen(val)) return i; //extra test (strlen)
      }
   }
   return INVALID_;
}

#ifdef TTN_ATESTS
ssize_t kv_extract_val( const char * kv,
                        const size_t kvsz,
                        const char * const restrict key,
                        const size_t ksz,
                        const char** restrict out_val    )
{
   return parse_kv_(kv,kvsz,key,ksz,out_val);
}
#endif
//------------------------------------------------------------------------

TX_INTERNAL_INLINE
const char* trimmed_(const char* line,const uint_fast64_t lsz, size_t * const restrict outlen){
   // Check input.
   if (line){
      const char* line_= line;
      // Trim left.
      uint_fast64_t i_=0;
      while(i_<lsz && isspace(line_[i_]) && ++i_);
      if (i_) line_+=i_;
      
      if (i_<lsz){
         // Trim right
         uint_fast64_t len=strnlen(line_,lsz-i_);
         while(len && isspace(line_[len-1]) && (--len));
         *outlen=len;
         return line_;
      }
      *outlen=0;
      return line_;
   }
   return NULL;
}

TX_INTERNAL_INLINE
char* trimmed_no_const(char* line,const uint_fast64_t lsz, size_t * const restrict outlen){
   // Check input.
   if (line){
      char* line_= line;
      // Trim left.
      uint_fast64_t i_=0;
      while(i_<lsz && isspace(line_[i_]) && ++i_);
      if (i_) line_+=i_;

      if (i_<lsz){
         // Trim right
         uint_fast64_t len=strnlen(line_,lsz-i_);
         while(len && isspace(line_[len-1]) && (--len));
         *outlen=len;
         return line_;
      }
      *outlen=0;
      return line_;
   }
   return NULL;
}

TX_INTERNAL_INLINE
size_t trim_(const char* line, char * const restrict buf, const uint_fast64_t buf_max_sz){
   if (line && buf && buf_max_sz){
      size_t len=0;
      const char * const trimmed=trimmed_(line,strlen(line),&len);
      if (trimmed && strlcpy(buf, trimmed, STRLCPY_SIZE_(len,buf_max_sz))<buf_max_sz){
         return len;
      }
   }
   return 0;
}


/**
 * trim_ptr
 * this method does not allocate a new string buffer it just returns a pointer to the existing one (input string)
 * @param line    :input string
 * @param lsz     :input string len
 * @param outlen  :out str length
 * @return        :out string ptr 
 */
char* trim_ptr(char* line,const size_t lsz, size_t * const restrict outlen){
   return trimmed_no_const(line,lsz,outlen);
}


/**
 * 
 * @param line          : input string
 * @param buf           : out buffer
 * @param buf_max_sz    : out buffer max size (+1 for null byte)
 * @return 
 */
size_t trim_ex(const char* line,char * const restrict buf, const size_t buf_max_sz){
   if (line && buf && buf_max_sz)
      return trim_(line,buf,buf_max_sz);
   return 0;
}


size_t trim_quotes(const char* const restrict line, const size_t line_sz,char * const restrict outbuf, const size_t out_buf_max_sz){
   // Check input.
   if (line && line_sz && (line_sz<=out_buf_max_sz)){
      uint_fast64_t n=0;
      uint_fast64_t r=0;
      while (n<line_sz){
         if(line[n]!='"' && line[n]!='\'' && (outbuf[r]=line[n])){
            ++r;++n;
            continue;
         } else ++n;
      }
      return r;
   }
   return 0;
}

//------------------------------------------------------------------------
char* ptrim(char* line,const size_t lsz){
   size_t len=0;
   const char * const trimmed=trimmed_(line,lsz,&len);
   if (trimmed){
      char* const buf = (char*const)tx_safe_malloc(len+1);
      //intentional use of strncpy
      if (buf && strncpy(buf, trimmed, len)){
         buf[len]=0;
         return buf;
      } else {
         tx_safe_free(buf);
      }
   }
   return NULL;
}

//------------------------------------------------------------------------
// StringList
//------------------------------------------------------------------------

TX_INTERNAL_INLINE
bool string_list_pass_value_( StringList* const restrict list, 
                              char * value )
{
    if ( value ) {

        uint_fast64_t i = 0;
        const uint_fast64_t l = list->buf_size_;
        char** sarr = list->arr;
        while ( i < l ) {
            
            if( !sarr[i] ) {

                sarr[i] = value;
                list->size++;
                list->length = list->size;
                return true;
            }
            ++i;
        }
    }

    return false;
}

TX_INTERNAL_INLINE
StringList* string_list_new_( const size_t buf_size )
{
    StringList* const  list =(StringList*const)tx_safe_malloc(sizeof(StringList));
    if ( list ) {

        list->buf_size_ = buf_size;
        list->size = 0;
        list->length = list->size;
        if ( ( list->arr = (char**)tx_safe_malloc(sizeof(char*) * (list->buf_size_+1) ) ) ) {

            /* DI */
            g_StringList_instances_c++;
            return list;
        } 
        else  
            string_list_free(list);
    }
    return NULL;
}

TX_INTERNAL_INLINE
bool string_list_clear_(StringList* const restrict  list)
{
    if ( list ) {

      struct elems{uint_fast64_t i_; const uint_fast64_t max_; char** arr_;};
      for ( struct elems e={ .max_=list->size,
                             .arr_=list->arr }; 
            e.i_ < e.max_;
            ++e.i_ ) {

         tx_safe_free((void*const)e.arr_[e.i_]);
         e.arr_[e.i_]=NULL;
      }
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
bool string_list_free_( StringList* const restrict list )
{
   if ( list && string_list_clear_( list ) && list->arr ) {

      tx_safe_free(list->arr);
      list->arr = 0;
      tx_safe_free(list);
      /* DI */
      g_StringList_instances_d++;
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
bool auto_string_list_resize_( StringList* const restrict list )
{
    StringList* temp_list = NULL;
    if ( list && 
         list->arr && 
         ( temp_list = string_list_new_( list->buf_size_ ) ) && 
         temp_list->arr ) {

      // Copy to temp_arr.
      tx_safe_memcpy( temp_list->arr, list->arr, (sizeof(char**) * list->buf_size_) );
      // Free old arr.
      tx_safe_free( list->arr );
      // Get new arr.
      list->buf_size_ <<= 1;
      if ( ( list->arr = (char**)tx_safe_malloc( sizeof(char*) * list->buf_size_ ) ) ) {

         uint_fast64_t i_ = 0;
         const uint_fast64_t l_ = list->buf_size_;
         char** arr = list->arr;
         //The build-in loop unroller might do better job in optimizing this loop
         while(i_<l_) arr[i_++] = NULL;
         tx_safe_memcpy( list->arr, temp_list->arr, (sizeof(char**) * temp_list->buf_size_ ) );
         string_list_free_( temp_list );
         return true;
      }
   }

   string_list_free_( temp_list );
   return false;
}

TX_INTERNAL_INLINE
bool string_list_add_ex_( StringList* const restrict list, 
                         const char* const restrict line, 
                         size_t sz )
{
    if ( list->size >= list->buf_size_ && !auto_string_list_resize_( list ) ) {

        return false;
    }

    if ( line && sz ) {

        char * const value = str_dup_ex(line,&sz);

        if ( string_list_pass_value_( list, value ) ) {

           return true;
        }

        tx_safe_free( value );
    }

    return false;
}

TX_INTERNAL_INLINE
bool del_from_list_( StringList* const restrict list,
                     const  char* const restrict line,
                     const bool free_ )
{
    ssize_t idx=INVALID_;
    size_t i = 0;
    const size_t l=list->size;
    char** sarr=list->arr;
    // Resize.
    while( i<l ) {
        if ( sarr[i] && !strcmp(sarr[i],line) ) {

            idx=(ssize_t)i;
            goto string_list_del_continue;
        }
        ++i;
    }

    if (idx!=INVALID_){

        string_list_del_continue:
        if (sarr[idx]){

            if (free_) {

                free((void*)sarr[idx]);
            }
            sarr[idx]=NULL;
        }

        i =(size_t)++idx;
        //The build-in loop unroller might do better job in optimizing this loop
        while( i<l ){
            sarr[i-1]=sarr[i]; ++i;
        }

        list->size--;
        list->length = list->size;
        return true;
    }
    return false;
}

TX_INTERNAL_INLINE
ssize_t string_list_get_gap_size_( StringList * const restrict  pList,
                                   ssize_t *const restrict pIndex )
{
    *pIndex=INVALID_;
    if (pList && pList->arr && 0<pList->size){
        uint_fast64_t i = 0;
        const uint_fast64_t ilen = pList->buf_size_;
        const char*const* const sarr=(const char*const* const)pList->arr;
        while(i<ilen){
            if (!sarr[i] && INVALID_==*pIndex){

                *pIndex=(ssize_t)i;
            } else if (sarr[i] && INVALID_<*pIndex){

                return (ssize_t)i;
            }
            ++i;
        }
        return (ssize_t)i;
    }
    return INVALID_;
}

TX_INTERNAL_INLINE 
ssize_t string_list_get_fragmentation_size( StringList * const restrict pList,
                                            const uint_fast64_t fstart )
{
    if (pList && pList->arr && 0<pList->size) {

        uint_fast64_t i = fstart;
        const uint_fast64_t ilen = pList->buf_size_;
        const char*const* const sarr=(const char*const* const)pList->arr;
        ssize_t ctx=INVALID_;
        while(i<ilen){

            if (sarr[i++]){

                if (ctx++==INVALID_) {

                    ++ctx;
                }
            }
            else
                return ctx;
        }

        return ctx;
    }

    return INVALID_;
}

StringList* string_list_new()
{
    return string_list_new_( DEF_LIST_SIZE );
}

bool string_list_clear( StringList* const restrict list )
{
    if ( string_list_clear_(list) ) {
        list->size = 0;
        list->length = list->size;
        return true;
    }
    return false;
}

bool string_list_free( StringList* const restrict list )
{
    return string_list_free_(list);
}

bool string_list_resize( StringList* const restrict list )
{
    return auto_string_list_resize_(list);
}

void string_list_print_all( StringList* const restrict list )
{
    if (!list) return;
    uint_fast64_t i = 0;
    const uint_fast64_t ilen=list->size;
    char** sarr=list->arr;
    while(i<ilen){
        printf("%lu, %s\n", i, sarr[i]?sarr[i]:"<null>");
        ++i;
    }
}

bool string_list_del( StringList* const restrict list,
                      const  char* const restrict line )
{
    return del_from_list_(list,line,true);
}


void string_list_sort( StringList* const restrict list )
{
    // Check input.
    if (list && list->arr && 0<list->size){

        qsort(list->arr,list->size, sizeof(list->arr[0]), str_cmp);
    }
}

void string_list_rsort( StringList* const restrict list )
{
    // Check input.
    if (list && list->arr && 0<list->size){

        qsort(list->arr, list->size, sizeof(list->arr[0]), str_rcmp);
    }
}

char* string_list_find( StringList* const restrict list,
                        const char* kw )
{
    if (list && list->arr && 0<list->size && kw){

        const char** const pkw = &kw;
        void* const res = bsearch(pkw, list->arr,list->size, sizeof(list->arr[0]), str_cmp);
        return (res?*(char**const)res:NULL);
    }
    return NULL;
}

static char* string_list_find_kv( const StringList* const restrict list,
                                  const char* const restrict kw )
{
    ssize_t idx = 0;
    if (list->size && (idx = string_map_bsearch_by_kval(list->arr, list->size, kw))>INVALID_){

        return list->arr[idx];
    }
    return NULL;
}

ssize_t string_list_find_index_by_kw( const StringList* const restrict pList,
                                      const char* const restrict pKw)
{
    return string_map_bsearch_by_kval(pList->arr, pList->size, pKw);
}

bool string_list_compact(StringList * const restrict pList)
{
    uint_fast64_t idx=0;
    char** arr=pList->arr;
    while(idx<LOOP_MAX){

        ssize_t gidx=INVALID_;
        ssize_t gs=string_list_get_gap_size_(pList,&gidx);
        if (!((INVALID_==gs) && (INVALID_==gidx))){

            ssize_t fsz=string_list_get_fragmentation_size(pList,(uint_fast64_t)gs);
            if (!((INVALID_==gidx) || (INVALID_==fsz))){

                if (!( gs>=(ssize_t)pList->size && INVALID_==fsz)){

                    if ( !( INVALID_<fsz &&

                            tx_safe_memcpy( ((void **)arr+gidx),
                                            ((void **)arr+gs),
                                            (sizeof(void**)*(size_t)fsz) ) &&

                            zm ( ((void **)arr+(size_t)(gidx+fsz)),
                                 (sizeof(void**) * (size_t)(gs+fsz-(gidx+fsz)) )) ) ) {
                        printf("string_list_compact failed!!!\n");
                        exit(-1);
                    }

                    pList->size=(size_t)(gidx+fsz);
                    pList->length=pList->size;
                    idx++;
                    continue;

                } 
                else {

                    if (gidx<(ssize_t)(pList->size-1)){
                        //no gap, size is too big
                        pList->size=(size_t)gidx+1;
                        pList->length=pList->size;
                    }
                }
            }
        }
        return true;
    }
    return false;
}

bool string_list_lookup_key( t_StringList_lookup_call * const restrict  lookup )
{
    struct elems { uint_fast64_t i_; 
                   const uint_fast64_t max_; 
                   char** const arr_; 
                   const char * const key_; 
                   size_t ksz_; };

    for ( struct elems e={ .max_=lookup->list->length,
                           .arr_=lookup->list->arr,
                           .key_=lookup->key,
                           .ksz_=lookup->key_sz };
          e.i_ < e.max_;
          ++e.i_ ) {

        if( e.arr_[e.i_] && 
            *e.arr_[e.i_] && 
            *e.arr_[e.i_]!='#' && 
            strnstr( e.arr_[e.i_], e.key_, e.ksz_ ) ){

            lookup->lookup_idx=(ssize_t)e.i_;
            return true;
        }
    }
    return false;
}

size_t string_list_count_item( StringList* const restrict list,
                               const char* const restrict line )
{
    uint_fast64_t i=0;
    const uint_fast64_t l=list->size;
    uint_fast64_t c=0;
    const char*const* const arr=(const char*const* const)list->arr;
    while(i<l){

        if ( arr[i] && !strcmp(arr[i],line)) {

            ++c;
        } 
        ++i;
    }
    return c;
}

//------------------------------------------------------------------------
// tools
//------------------------------------------------------------------------

TX_INTERNAL_INLINE
StringList* split_(  const char* const restrict line,
                     const char* const restrict delim, 
                     const uint_fast64_t count_max )
{
   if ( line && delim ) {
      // Replace.
      const size_t delim_len = strlen( delim );
      StringList* const list = string_list_new();

      if ( list ) {

         size_t sc = 0;
         const char* pline = NULL;
         uint_fast64_t i_ = 0;

         if ( !count_max ) {

            for ( pline = line; *pline; pline++ ) {

               if ( !strncmp( pline, delim, delim_len ) ) {

                  pline += delim_len - 1;
                  string_list_add_ex_( list, pline - (i_ + delim_len - 1), i_ );
                  ++sc;
                  i_ = 0;
                  continue;
               }
               ++i_;
            }
         }
         else {

            for ( pline = line; *pline; pline++ ) {

               if ( sc<count_max && !strncmp(pline, delim, delim_len) ) {

                  pline += delim_len - 1;
                  string_list_add_ex_( list, pline - (i_ + delim_len - 1), i_ );
                  ++sc;
                  i_ = 0;
                  continue;
               }
               ++i_;
            }
         }

         pline += delim_len - 1;
         string_list_add_ex_( list, pline - (i_ + delim_len - 1), i_ );
         return list;
      }
      return NULL;
   }
   return string_list_new();//is this ok ??
}


//------------------------------------------------------------------------
StringList* split_ex(   char* const restrict line,
                        const char* const restrict delim, 
                        const size_t count_max  )
{
   return split_(line,delim,count_max);
}

StringList* split(   const char* const restrict line,
                     const char* const restrict delim )
{
   return split_(line,delim,0);
}

//------------------------------------------------------------------------
StringList* split_by_space(   const char* const restrict line,
                              const size_t lsz  )
{
   if ( line && lsz ) {

      size_t dup_line_sz = lsz;
      __attribute__((cleanup (raii_free_))) char * dup_line = str_dup_ex( line, &dup_line_sz );

      if ( dup_line && dup_line_sz ) {

         /* in-place space normalization  */
         dup_line_sz = str_rep_space_as_in_place( dup_line, dup_line_sz, ' ' );
         if ( dup_line_sz ) {

            char * trimmed_line = trimmed_no_const( dup_line, 
                                                    dup_line_sz, 
                                                    &dup_line_sz );

            if ( trimmed_line && dup_line_sz ) {

               /* terminate the line */
               trimmed_line[ dup_line_sz ] = 0; 
               StringList* const list = split_( trimmed_line, " ", 0 );
               if ( list ) {

                  return list;
               }
            }
         }
      }
   }

   return string_list_new();
}

//------------------------------------------------------------------------
TX_INTERNAL_INLINE
bool join_(StringList* const restrict list,const char* const restrict glue, char * const restrict buf, const uint_fast64_t bsz){
   if (list && glue && buf && bsz){
      // Init buf.
      buf[0]=0;
      const uint_fast64_t lsize=list->size;
      if (lsize){
         const char*const* const arr_=(const char*const* const)list->arr;
         uint_fast64_t i_=0;
         if (!arr_[i_] || !(strlcpy(buf, arr_[i_],bsz)>=bsz)){
            while(++i_<lsize){
               if (!arr_[i_] ||  !((strlcat(buf, glue,bsz)>=bsz) || (strlcat(buf, arr_[i_],bsz)>=bsz)) ) continue;
               return false; //too long 
            }
            return true; //ok
         }
      }
   }
   return false; //invalid
}


bool join(StringList* const restrict list,const char* const restrict glue, char * const restrict buf, const size_t bsz){
   return (join_(list,glue,buf,bsz));
}

//------------------------------------------------------------------------
//TODO:: check all references/calls

char*  pjoin(StringList* const restrict list,const char* const restrict glue){
 if (list && glue){
      // Init buf.
      const size_t lsize = list->size;
      const char*const * const arr=(const char*const * const)list->arr;
      uint_fast64_t i=0;
      uint_fast64_t size = 0;
      while(i<lsize){
         if (arr[i]) 
            size += strlen(arr[i++]);
         else
            ++i;
      }
      // Check input.
      if (size>0 && (size +=(lsize>0?(strlen(glue) * (lsize - 1)):0) )){
         ++size;
         char* const buf = (char*const )tx_safe_malloc(size);
         if (buf && join_(list,glue,buf,size)) return buf;
         tx_safe_free(buf);
      }
   }
   return NULL; 
}


//------------------------------------------------------------------------
static int str_cmp(const void* restrict s1, const void*  restrict s2){
   const char * const cs1=*(char *const*)s1;
   const char * const cs2=*(char *const*)s2;

   return strcmp( cs1, cs2 );

}

//------------------------------------------------------------------------
static int str_rcmp(const void* restrict s1, const void* restrict s2){
   const char * const cs1=*(char *const*)s1;
   const char * const cs2=*(char *const*)s2;
   const int r=strcmp(cs1, cs2);
   return ( r  * -1 );

}

//------------------------------------------------------------------------
// StringMap.
//------------------------------------------------------------------------
StringMap* string_map_new(){
   StringMap* map = (StringMap*const)tx_safe_malloc(sizeof(StringMap));
   if (map){
      map->size = 0;
      map->list = string_list_new();
      map->kw_list = string_list_new();
      /* DI */
      g_StringMap_instances_c++;
      return map;
   }
   return NULL;
}

//------------------------------------------------------------------------
bool string_map_clear(StringMap*const restrict map){
   return (string_list_clear(map->list) && 
   string_list_clear(map->kw_list) && 
   !(map->size = 0));
}

//------------------------------------------------------------------------
bool string_map_free(StringMap*const restrict map){
   if (map && map->list && string_list_free(map->list) && !(map->list = 0)
   && map->kw_list && string_list_free(map->kw_list) && !( map->kw_list = 0)){
      tx_safe_free(map);
      /* DI */
      g_StringMap_instances_d++;
      return true;
   }
   return false;
}

//------------------------------------------------------------------------
void string_map_print_all(StringMap*const restrict map){
   string_list_print_all(map->list);
}

//------------------------------------------------------------------------
bool string_map_empty(StringMap*const restrict  map){
   uint_fast64_t i = 0;
   const uint_fast64_t ilen = map->list->size;
   const char*const* const arr=(const char*const* const)map->list->arr;
   while(i<ilen){
     char*  ptr = strchr(arr[i], ' ');//?? space - why ??
     *(++ptr)=0;
     ++i;
   }
   map->size = 0;
   return true;
}

//------------------------------------------------------------------------
bool string_map_add( StringMap* const restrict map, 
                     const char* const restrict src_kw,
                     const char* const restrict src_val )
{
    if ( map && src_kw && *src_kw && src_val && *src_val ) {

        const ssize_t idx = string_map_bsearch_by_key( map->kw_list->arr, 
                                                       map->kw_list->size, 
                                                       src_kw );
        char * kw = NULL;
        size_t len = 0;
        if( idx == INVALID_ ) {

            if ( !( kw = tx_safe_calloc( MAX_MAP_KW_SIZE + 1, 1 ) ) ) {

                return false;
            }

            len = strlcpy( kw, src_kw, MAX_MAP_KW_SIZE + 1);
        }
        else {

            len = strlen( src_kw );
        }

        len += strlen( src_val ) + 2;
        char * const kw_val = tx_safe_malloc( len );
        if ( !kw_val ) { 

            tx_safe_free( kw );
            return false;
        }

        if( idx == INVALID_ ) {

            tx_safe_snprintf( kw_val, len, "%s %s", kw, src_val );
            if ( string_list_pass_value_( map->list, kw_val ) ) {

                string_list_sort( map->list );
                if ( string_list_pass_value_( map->kw_list, kw ) ) {

                    string_list_sort( map->kw_list );
                    map->size++;
                    return true;
                }

                string_list_del( map->list, kw_val );
            }

            tx_safe_free( kw );
        }
        else {

            tx_safe_snprintf( kw_val, len, "%s %s", src_kw, src_val );
            tx_safe_free( map->list->arr[idx] );
            if ( ( map->list->arr[idx] = kw_val ) ) {

                return true;
            }
        }

        tx_safe_free( kw_val );
    }

    return false;
}

//------------------------------------------------------------------------
void string_map_sort(StringMap* const restrict map){
   string_list_sort(map->list);
}

//---------------------------------------------------------------------
bool string_map_val(    const StringMap* const restrict map,
                        const char* const restrict  kw,
                        char * const restrict buf,
                        const size_t bsz                    )
{
    if ( map && map->list && kw && buf ) {
        buf[0]=0;
        char* const kw_val = string_list_find_kv(map->list, kw);

        if ( kw_val ){

            const char * val = NULL;

            const ssize_t i= parse_kv_(kw_val,strlen(kw_val),kw,strlen(kw),&val);

            if ( i > 1) {

                strlcpy(buf,val,STRLCPY_SIZE_((size_t)i,bsz));

                return true;
            }
        }
    }

    return false;
}

//---------------------------------------------------------------------
bool string_map_find(StringMap* const restrict  map,const  char* const restrict  kw){
   if (map && map->list && kw){
      char* const kw_val = string_list_find_kv(map->list, kw);
      return (kw_val && parse_kv_(kw_val,strlen(kw_val),kw,strlen(kw),0)>0);
   }
   return false;
}

//---------------------------------------------------------------------
int string_map_val_int(const StringMap* const restrict map, const char* const restrict kw){
   if (map && map->list && kw){
      char* const kw_val = string_list_find_kv(map->list, kw);
      const char * val=NULL;
      int r=0;
      if (kw_val && parse_kv_(kw_val,strlen(kw_val),kw,strlen(kw),&val)>1 && tx_safe_atoi(val,&r)) return r;
   }
   return 0; 
}

struct string_map_bsearch_elems_{int_fast64_t left_; int_fast64_t right_; char** const arr_;  const char * const key_ ;const size_t ksz_; uint_fast64_t mid_; int_fast64_t cmpval_;ssize_t s_;char bkw_[MAX_MAP_KW_SIZE+1];};

//---------------------------------------------------------------------
ssize_t string_map_bsearch_by_kval(char** const restrict arr,const size_t size,const char* const restrict key){

   if (arr && size && key ){

      for(struct string_map_bsearch_elems_ e={
         .right_=(int_fast64_t)size -1,
         .arr_=arr,
         .key_=key,
         .ksz_=strlen(key)
      }; 
      e.left_ <= e.right_;
      (void)( (e.cmpval_ > 0 && (e.left_ = (int_fast64_t)(e.mid_ + 1) )) || (e.right_ = (int_fast64_t)(e.mid_ - 1)))){
         e.mid_=(uint_fast64_t)(e.left_ + e.right_)>>1;
         if (e.arr_[e.mid_] && (e.s_=ttn_strncspn(e.arr_[e.mid_],strlen(e.arr_[e.mid_])," ",1))>0){
            (void)strlcpy(e.bkw_,e.arr_[e.mid_],STRLCPY_SIZE_((size_t)e.s_,sizeof(e.bkw_)));
            if (0!=(e.cmpval_=strcmp(e.key_,e.bkw_))){
                continue;
            } else  return (ssize_t)e.mid_;
         } break;
      }
   }
   return INVALID_;
}


ssize_t string_map_bsearch_by_key(char** const restrict arr,const size_t size,const char* const restrict key){
   if (arr && size && key && *key ){

      for(struct string_map_bsearch_elems_ e={
         .right_=(int_fast64_t)size - 1,
         .arr_=arr,
         .key_=key,
         .ksz_=strlen(key)
      }; e.left_ <= e.right_;
      (void)( (e.cmpval_ > 0 && (e.left_ = (int_fast64_t)(e.mid_ + 1) )) || (e.right_ = (int_fast64_t)(e.mid_ - 1)))){
         e.mid_=(uint_fast64_t)(e.left_ + e.right_)>>1;
         if (e.arr_[e.mid_]){
            if (0!=(e.cmpval_=strcmp(e.key_,e.arr_[e.mid_]))){
                continue;
            } else  return (ssize_t)e.mid_;
         } break;
      }
   }
   return INVALID_;
}

//------------------------------------------------------------------------
// StringTree.
//------------------------------------------------------------------------
TX_INTERNAL_INLINE
VoidList* void_list_new_(const size_t buf_size, void (*val_free)(void*)){
   VoidList* const list = (VoidList*const)tx_safe_malloc(sizeof(VoidList));
   if (list){
      list->buf_size_ = buf_size;
      list->size = 0;
      list->length = list->size;
      list->arr = (void**)tx_safe_malloc(sizeof(void*) * list->buf_size_);
      list->val_free = val_free;
      for(uint_fast64_t i_ = 0; i_ < list->buf_size_; ++i_){
         list->arr[i_] = NULL;
      }
      return list;
   }

   return NULL;
}

TX_INTERNAL_INLINE
bool void_pair_free_(VoidPair* const restrict vp, void (*val_free)(void*)){
   if (vp){
     if(vp->kw) free(vp->kw);
     vp->kw = 0;
     if(vp->val && val_free) val_free(vp->val);
     vp->val = 0;
     free(vp);
   }
   return true;
}

TX_INTERNAL_INLINE
void void_map_clear_(VoidList* const restrict  pList,const int pJustClear){
   if (pList && pList->arr){
      struct elems{ uint_fast64_t i_; const uint_fast64_t max_; void** arr_; const int jc_; void (*val_free_)(void*);};
      for (struct elems e={
         .max_=pList->size,
         .arr_=pList->arr,
         .jc_=pJustClear,
         .val_free_=pList->val_free
      };e.i_<e.max_;++e.i_){
         (void)(!e.jc_ && e.arr_[e.i_] && void_pair_free_((VoidPair*const)e.arr_[e.i_], e.val_free_));
         e.arr_[e.i_]=0;
      }
   }
}

TX_INTERNAL_INLINE
void void_list_clear_(VoidList* const restrict list){
   if (list && list->arr && list->size){
      for(uint_fast64_t i_ = 0; i_ < list->size; ++i_){
         if(list->arr[i_]){
            // If there's a free function.
            if(list->val_free){
               list->val_free(list->arr[i_]);
            }
            list->arr[i_] = 0;
         }
      }
      list->size = 0;
      list->length = list->size; 
   }
}

TX_INTERNAL_INLINE
void void_list_free_(VoidList* const restrict list){
   if (list){
      if(list->arr){
         void_list_clear_(list);

         free(list->arr);
         list->arr = NULL;
      }
      free(list);
   }
}

TX_INTERNAL_INLINE
bool void_list_resize_(VoidList* const restrict list){
   if (list){
      VoidList* const temp_list = void_list_new_(list->buf_size_, list->val_free);
      if (temp_list){
        // Copy to temp_arr.
        (void)tx_safe_memcpy(temp_list->arr, list->arr, (sizeof(void**) * list->buf_size_));

        void_map_clear_(list,1);
        free(list->arr);
        list->arr = 0;

        // Get new arr.
        list->buf_size_ <<= 1;
        list->arr = (void**)tx_safe_malloc(sizeof(void*) * list->buf_size_);

        (void)tx_safe_memcpy(list->arr, temp_list->arr, (sizeof(void**) * temp_list->buf_size_));
        void_list_free_(temp_list);
        return true;
      }
   }
   return false;
}

TX_INTERNAL_INLINE
bool void_list_add_(VoidList* const restrict  list,void* v)
{
   if (list && v){
      if (list->size >= list->buf_size_) (void)void_list_resize_(list);
      if (list->arr){

         const uint_fast64_t max_ = list->buf_size_;
         for ( uint_fast64_t i_ = 0; i_<max_ ; ++i_) {

            if ( !list->arr[ i_ ] ) {

               list->arr[ i_ ] = v ;
               list->length  = ++list->size;
               return true;
            }
         }
      }
   }
   return false;
}

TX_INTERNAL_INLINE
void void_list_sort_(VoidList* const restrict list, int (*void_cmp)(const void*, const void*const)){
   // Check input.
   if (list && list->arr && 0<list->size){
      qsort(list->arr,list->size, sizeof(list->arr[0]), void_cmp);
   }
}

TX_INTERNAL_INLINE
bool void_list_remove_last_(VoidList*  const restrict list,const bool free_){
   return (LIST_REMOVE_LAST_TEMPLATE_(list,if(free_ && list->val_free && list->arr[list->size-1]) list->val_free((void*)list->arr[list->size-1])));
}

TX_INTERNAL_INLINE
ssize_t void_list_get_gap_size(VoidList * const restrict pList, ssize_t * restrict pIndex){
   *pIndex=INVALID_;
   if (pList){
      struct elems {uint_fast64_t i_; const uint_fast64_t max_;void** arr_;};
      for (struct elems e={
         .max_=pList->size,
         .arr_=pList->arr
      };e.i_<e.max_;++e.i_){
         if (!e.arr_[e.i_]){
            if (*pIndex==INVALID_){
               *pIndex=(ssize_t)e.i_;
            }
         } else {
            if (*pIndex>INVALID_){
               return (ssize_t)e.i_;
            }
         }
      }
      return (ssize_t)(pList->size-1);
   }
   return INVALID_;
}

TX_INTERNAL_INLINE
ssize_t void_list_compact_(VoidList *const restrict pList){
   uint_fast64_t idx=0;
   while(idx<LOOP_MAX){
      ssize_t gidx=INVALID_;
      ssize_t gi=void_list_get_gap_size(pList,&gidx);
      if ((gi==INVALID_) && (gidx==INVALID_)){
         return INVALID_;
      }
      if ((gi>=(ssize_t)pList->size) && (gidx==INVALID_)){
         //no gaps at all
         return 0;
      }
      if ((gi>=(ssize_t)pList->size) && (gidx>INVALID_)){
         //gap is at the end of list
         pList->size-=(size_t)(gi-gidx);
         pList->length-=(size_t)(gi-gidx);
         return (gi-gidx);
      } else {
         //gap detected
         const size_t list_size=(sizeof(void**)*pList->buf_size_);
         const size_t gap_size=(sizeof(void**)*(size_t)(gi-gidx));
         if (list_size && gap_size && (list_size-gap_size)>0){
            (void)tx_safe_memcpy((void **)pList->arr+gidx,(void **)pList->arr+gidx+(gi-gidx), (list_size-gap_size)   );
            (void)zm((void **)pList->arr+(list_size-gap_size), gap_size);
         }
      }
      idx++;
   }
   return INVALID_;
}

//------------------------------------------------------------------------
// VoidMap.
//------------------------------------------------------------------------
VoidPair* void_pair_new(const char* const restrict kw,void* restrict val){
   if (kw && *kw){
      VoidPair* const vp = (VoidPair*const)tx_safe_malloc(sizeof(VoidPair));
      if (vp){
         size_t l_=0;
         vp->kw = str_dup_ex(kw,&l_);
         assert(vp->kw && l_ && "void_pair_new failed");
         vp->val = val;
         vp->kh = str2Murmur(vp->kw,l_);
         return vp;
      }
   }

   return NULL;
}

//------------------------------------------------------------------------
bool void_pair_free(VoidPair* const restrict vp, void (*val_free)(void*)){
   return void_pair_free_(vp,val_free);
}

//------------------------------------------------------------------------
static int vp_cmp(const void* restrict v1, const void* restrict v2){
   if ((!v1) || (!v2)){
      return -2;
   }
   const VoidPair *const vp1= (*(VoidPair*const*const)v1);
   const VoidPair *const vp2=(*(VoidPair*const*const)v2);
   if ((!vp1) || (!vp2)){
      return -2;
   }

   const unsigned long ul1 = vp1->kh;
   const unsigned long ul2  = vp2->kh;

   if(ul1 == ul2){
      return 0;
   } else if(ul1 > ul2){
      return 1;
   } else {
      return -1;
   }
}

VoidMap* void_map_new(void (*val_free)(void*)){
   VoidMap* const map = (VoidMap*const)tx_safe_malloc(sizeof(VoidMap));
   if (map){
      map->list = void_list_new_(DEF_LIST_SIZE,val_free);
      map->kw_list = string_list_new();
      map->val_free = val_free;
      map->size = 0;
      return map;
   }

   return NULL;
}

//------------------------------------------------------------------------

void void_map_clear(VoidMap* const restrict map){
   if (map){
      void_map_clear_(map->list,0);
      map->list->size = 0;
      map->list->length = map->list->size;
      map->size = 0;
      string_list_clear_(map->kw_list);
   }
}

//------------------------------------------------------------------------
void void_map_free(VoidMap* const restrict map){
   if(!map){
      return;
   }

   void_map_clear_(map->list,0);

   if(map->list){
      void_list_free_(map->list);
      map->list = 0;
   }

   if(map->kw_list){
      string_list_free(map->kw_list);
      map->kw_list = 0;
   }

   free(map);
}

//------------------------------------------------------------------------
bool void_map_add2(VoidMap* const restrict map,const char* const restrict kw, void* const restrict val){
   if(kw){
      VoidPair* const vp=void_pair_new(kw, val);
      if (vp){
         if (void_list_add_(map->list, (void * const)vp)){
            if (string_list_add(map->kw_list, kw)){
               map->size++;
               return true;
            }
            (void)void_list_remove_last_(map->list,false);
         }
         (void)void_pair_free_(vp,NULL);
      }
   }
   return false;
}

bool void_map_remove_by_kw(VoidMap*const restrict pMap,const char* const restrict pKw){
///probably it could be better in terms of performance to move all calls/references to compacting functions
///and sorting function outside this method but the rest of methods is not safe enough to work on lists with nulls
/// - see void_map_bsearch
   ssize_t idx=void_map_find_index_by_kw(pMap,pKw);
   if (!(idx==INVALID_)){
      VoidPair * const lvp = (VoidPair*const)pMap->list->arr[idx];
      (void)void_pair_free_(lvp, pMap->val_free);
      pMap->list->arr[idx]=0;
      idx=void_list_compact_(pMap->list);
      if (INVALID_<idx){
         pMap->size-=(size_t)idx;
         idx=string_list_find_index_by_kw(pMap->kw_list, pKw);
         if (INVALID_<idx){
            if (pMap->kw_list->arr[idx]){
               free(pMap->kw_list->arr[idx]);
               pMap->kw_list->arr[idx]=0;
               (void)string_list_compact(pMap->kw_list);
            }
         }
         void_map_sort(pMap);
         return true;
      }
   }
   return false;
}


//------------------------------------------------------------------------
void void_map_sort(VoidMap* const restrict map){
   void_list_sort_(map->list, vp_cmp);
}

//------------------------------------------------------------------------
void* void_map_val(const VoidMap* const restrict map,const  char* const restrict kw){
   VoidPair* const vp = void_map_find(map, kw);
   return (vp && vp->val?vp->val:NULL);
}

//---------------------------------------------------------------------
ssize_t void_map_search_vp(const VoidMap* const restrict pMap,const VoidPair* const restrict pVP){
   if (pMap && pVP){
      uint_fast64_t left = 0,right = pMap->list->size-1;
      void ** arr_=pMap->list->arr;
      while(left <= right){
         const uint_fast64_t mid = ((left + right) >>1);
         VoidPair* const lvp=(VoidPair*const)arr_[mid];
         if (lvp){
               if(pVP!=lvp){
                  (void)( (pVP->kh > lvp->kh && (left = mid + 1)) || (right = mid - 1));
               } else return (ssize_t)mid; 
         } else{
            if (pVP==lvp) return (ssize_t)mid;
            break;
         }
      }
   }
   return INVALID_;
}

//---------------------------------------------------------------------
ssize_t void_map_bsearch( void** arr, const  size_t size, const  char* const restrict key )
{

   if ( arr && key && *key && size ) {

      int_fast64_t left = 0, right = (int_fast64_t)(size - 1);

      const t_hash ul = str2Murmur( key, strlen( key ) ); 

      while ( left <= right ) {

         const int_fast64_t mid = ( ( left + right ) >> 1 );

         if ( arr[ mid ] ) {

            const t_hash kh = ( (VoidPair *)arr[ mid ] )->kh;

            if ( kh == ul ) {

               /* item : found */
               return (ssize_t)mid;
            }

            if ( ul < kh ) {

               right = mid - 1;
            } 
            else {

               left = mid + 1;
            }
         } 
         else {

            /* error : the null hole */
            break;
         }
      }
   }

   return INVALID_;
}

//------------------------------------------------------------------------
VoidPair* void_map_find(const VoidMap* map,const  char* const restrict kw)
{
   if ( map && map->list && kw && *kw ) {

      const ssize_t idx = void_map_bsearch( map->list->arr, map->list->size, kw );
      if ( INVALID_<idx ) {

         return map->list->arr[idx]; 
      }
   }

   return NULL;
}
//------------------------------------------------------------------------
ssize_t void_map_find_index_by_vp(const VoidMap* const restrict pMap,const  VoidPair* const restrict pVp){
   return  void_map_search_vp(pMap,pVp);
}

//------------------------------------------------------------------------
ssize_t void_map_find_index_by_kw(const VoidMap* const restrict pMap,const char* const restrict pKw){
   void ** arr = pMap->list->arr;
   return  void_map_bsearch(arr, pMap->list->size, pKw);
}

//------------------------------------------------------------------------
// File.
//------------------------------------------------------------------------
bool file_exists(const char * const restrict filename){
   struct stat buf;
   return (filename && 0==stat(filename, &buf));
}

//------------------------------------------------------------------------
ssize_t file_size(const char* const restrict filename){
   
   if (filename && file_exists(filename)){
      FILE* fp = fopen(filename, "r");
      if (fp){
         (void)fseek(fp, 0, SEEK_END);
         const size_t size =(size_t)ftell(fp);
         (void)fclose(fp);
         return (ssize_t)size;
      }
      return INVALID_;
   }
   return 0;
}

//------------------------------------------------------------------------
StringList* read_text_file(const char* const restrict filename, const int max_line){
   StringList* const list = string_list_new_(DEF_LIST_SIZE);
   if (list && file_exists(filename)){
      FILE* fp=fopen(filename, "r");
      if(fp){
         char buf[256]={};
         if (!max_line){
            while(fgets(buf, sizeof(buf), fp)){
               (void)string_list_add(list, buf);
            }
         } else {
            int i = 0;
            while(i++ > max_line && fgets(buf, sizeof(buf), fp)){
               (void)string_list_add(list, buf);
            }
         }
         fclose(fp);
         return list;
      }
   }

   return list;
}

//------------------------------------------------------------------------
int write_text_file_ex(const char* const restrict filename,const char* const restrict  line,const bool create_if_not_exists){

   if(! file_exists(filename) && !create_if_not_exists){
      return 0;
   }

   FILE* fp = fopen(filename, "w");
   if(fp){
      (void)fprintf(fp, "%s", line);
      (void)fclose(fp);
      return 1;
   }
   return 0;
}

//------------------------------------------------------------------------
int append_text_file(const char*const restrict filename, char*const restrict line){
   if (file_exists(filename)){
      FILE* fp = fopen(filename, "a");
      if (fp){
         (void)fprintf(fp, "%s", line);
         (void)fclose(fp);
         return 1;
      }
   }
   return 0;
}

//------------------------------------------------------------------------
void file_dirname(const char*const restrict filename, char * const restrict buf,const size_t bsz){
   char* temp = 0;
   assert(filename && "file_dirname");
   buf[0]=0;

   if((temp = strrchr(filename, '/'))){
      const size_t l=(strlen(filename) - strlen(temp));
      (void)strlcpy(buf, filename,STRLCPY_SIZE_(l,bsz));
   }

   if(filename[strlen(filename) - 1] != '/'){
      return;
   }

   if((temp = strrchr(buf, '/'))){
      const size_t l=(strlen(filename) - strlen(temp));
      (void)strlcpy(buf, filename,STRLCPY_SIZE_(l,bsz));
   }
}

//------------------------------------------------------------------------
void file_basename(const char*const restrict filename, char*const restrict buf,const size_t bsz){
   char* temp = NULL;
   (void)strlcpy(buf, filename,bsz);
   if((temp = strrchr(filename, '/'))){
      (void)strlcpy(buf, ++temp,bsz);
   }
}

//------------------------------------------------------------------------
void file_extension(const char*const restrict filename, char*const restrict buf,const size_t bsz){
   (void)strlcpy(buf, "",bsz);
   char* temp=strrchr(filename, '.');
   if(temp){
      (void)strlcpy(buf, ++temp,bsz);
   }
}

//------------------------------------------------------------------------
// Misc.
//---------------------------------------------------------------------

bool exbin(const char*const restrict cmd, const size_t buf_len,char *const restrict  buf){
   FILE* fp = NULL;
   if ((fp = popen(cmd, "r")) != 0){
      bool r_=true;
      if(buf && buf_len){
         const size_t nread = fread(buf, sizeof(char), buf_len, fp);
         if (! (0==nread && (feof(fp) || ferror(fp))) )  {
            buf[((nread < buf_len - 1)?nread:(buf_len - 1))]=0; 
         } else
            r_=false;
      }
      pclose(fp);
      return r_;
   }
   return false;
}

////////////////////////////////////////////////////////////////////////////////
int write_text_file(const char*const restrict  filename, const char*const restrict  line){
   return write_text_file_ex(filename,line,false);
}

bool string_list_add(StringList* const restrict list,const char* const restrict line)
{

   return ( line && list  ?

            string_list_add_ex_( list, line, strlen( line ) ) :

            false );
}

bool mk_string_list_lookup_call(t_StringList_lookup_call *const  restrict call,const char * const  restrict key, const size_t key_sz){
   call->key=key;
   call->key_sz=key_sz;
   call->lookup_idx=INVALID_;
   return string_list_lookup_key(call);
}

bool get_cfg_key_value(char * key_val_str,char * const restrict out_val,size_t * const restrict out_len,const size_t out_mem_max_sz){
   StringList* const kv_list = split_ex((char*const)key_val_str, "=",1);
   bool r_=false;
   if (kv_list && kv_list->length==2 && ((*out_len)=trim_(kv_list->arr[1],out_val,out_mem_max_sz))){
      char get_cfg_key_value_buf[(*out_len)+1];
      (void)zm(get_cfg_key_value_buf,sizeof(get_cfg_key_value_buf));
      r_=(
            //1st copy
            ((*out_len)=trim_quotes(out_val,(*out_len),get_cfg_key_value_buf,(*out_len)))
            &&
            //2nd copy
            tx_safe_memcpy(out_val,get_cfg_key_value_buf,(*out_len))
         );
   }
   if (kv_list) string_list_free(kv_list);
   return r_;
}
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//          methods imported from the old stringutils
////////////////////////////////////////////////////////////////////////////////
typedef enum{
   CC_AUTO_FLIP_CASE=0,
   CC_TO_LOWER=1,    
   CC_TO_UPPER=2
}t_case_conv;


/* In-place conversion from '%20' to ' ' */
void unEscapeSpace(char* restrict t) {
   if(!t) {
      return;
   }

   int offset=0;
   while ( *t ) {
     // detect
      if (*(t+offset) == '%'
            && *(t+offset+1) == '2'
            && *(t+offset+2) == '0') {
         // detect
         *t++=' ';// overwrite the space
         offset+=2;
         *t=*(t+offset);
         continue;
      }
      // or advance  shuffle
      if ( offset ) {

        *t=*(t+offset);
      }

      t++;
   }
}

TX_INTERNAL_INLINE
char* str_dup_(const char* const restrict  pStr,size_t * const restrict pLen)
{
   if (pStr){
      const size_t sz = (( pLen && (*pLen) )?(*pLen):strlen(pStr));
      char* const outbuf  = (char*const)tx_safe_malloc(sz+1);
      if (outbuf){
         if ((*pStr) && sz) (void)strlcpy(outbuf,pStr,sz+1);
         if ( pLen ) *pLen = sz;
         return outbuf;
      }
   }
   return NULL;
}

TX_INTERNAL_INLINE
char * last_(char * restrict pStr,const char pC,size_t * const restrict pStrlen){
   if ( pStr &&  pStrlen && *pStr && *pStrlen ){
      pStr += (*pStrlen - 1);
      ssize_t l=(ssize_t)*pStrlen;
      for (;((*pStr) && (l >= 0) && (*pStr == pC)); --l,--pStr);
      char * r = pStr;
      if ( l<0 ){
         l = 0;
         r = NULL;
      }
      *pStrlen = (size_t)l;
      return (r);
   }
   return NULL;
}

TX_INTERNAL_INLINE
bool convert_case_in_place_(char * restrict s_,const size_t sl_,const t_case_conv act_) {
   if (s_ && *s_ && sl_>0){
         size_t l=0;
         switch (act_) {
            case CC_TO_LOWER: {
               while(*s_ && (*s_=TO_LOWER_C(*s_)) && (l++<sl_) && (++s_));
            }break;
            case CC_TO_UPPER: {
               while(*s_ && (*s_=TO_UPPER_C(*s_)) && (l++<sl_) && (++s_));
            }break;
            default: {
               while(*s_ && ((IS_LOWER_C(*s_) && (*s_=TO_UPPER_C(*s_))) || (*s_=TO_LOWER_C(*s_))) && (l++<sl_) && (++s_));
            }break;
         }
      return true;
   }
   return false;
}

TX_INTERNAL_INLINE
char ascii2num_(const char c) {
   switch (c){
      case '0' ... '9': return (c-'0');
      case 'A' ... 'F': return (c- 'A' + 10);
      default: return (c- 'a' + 10);
   }
}

//added handling of spaces encoded as "+"
//TODO: better handling of the escape characters (bl of ||)
TX_INTERNAL_INLINE
bool url_decode_ex_(char* url,const size_t sz,size_t * decoded,const bool plus4space) {
   if (url && url[0] && sz){
      size_t dec_=0;
      if (!decoded) decoded=&dec_;
      *decoded=0;
      struct elems {size_t i_; char * res_;};
      if (!plus4space){
         for (struct elems e={.res_=(char*)url};e.i_<sz;(void)((((url[e.i_]!='%') 
         && ((*e.res_++=url[e.i_]) || true)) || ((e.i_++)
         && (((*e.res_ =(char)(ascii2num_(url[e.i_++])<<4)) || true)
         && ((*e.res_++ |= ascii2num_(url[e.i_])) || true)))) 
         && (++*decoded)),e.i_++);
      } else {
         for (struct elems e={.res_=(char*)url};e.i_<sz;(void)((((url[e.i_]!='%' 
         && url[e.i_]!='+' ) && ((*e.res_++=url[e.i_]) || true))
         || (((url[e.i_]=='%' && e.i_++) && (((*e.res_ =(char)(ascii2num_(url[e.i_++])<<4)) 
         || true) && ((*e.res_++ |= ascii2num_(url[e.i_])) || true))) 
         || ((url[e.i_]=='+') && (*e.res_++=' '))))
         && (++*decoded)),e.i_++);
      }
      return (*decoded && !(*((char*)(url+*decoded))=0));
   }
   return false;
}

/////////////////////////////////////////////////////////////////////////////////

__attribute__((malloc))
char* str_dup_ex(const char* const restrict pStr,size_t * const restrict pOutLen)
{
   if (pStr){
      return (str_dup_(pStr,pOutLen));
   }
   return NULL;
}

__attribute__((malloc))
char* str_dup(const char* const restrict pStr)
{
   if (pStr){
      size_t sz=strlen(pStr);
      return str_dup_(pStr,&sz);
   }
   return NULL;
}

///-----PUBLIC-----
/*last index of char */
ssize_t last_index(char * const restrict pStr, const char pC) {
   assert(pStr && "last_index failed" );
   size_t len=strlen(pStr);
   return (last_(pStr,pC,&len)?(ssize_t)len:INVALID_);
}

/*last pointer to char  */
char * last_char(char * const restrict pStr, const char pC) {
   assert(pStr && "last_char failed" );
   size_t len=strlen(pStr);
   return last_(pStr,pC,&len);
}

/* In-place convert case  to opposite  */
bool convert_case_in_place(char * const restrict pStr) {
   return (pStr && *pStr && convert_case_in_place_(pStr,strlen(pStr),CC_AUTO_FLIP_CASE));
}


bool convert_to_lower(char * const restrict pStr) {
   return (pStr && *pStr && convert_case_in_place_(pStr,strlen(pStr),CC_TO_LOWER));
}

bool convert_to_lower_ex(char * const restrict pStr,const size_t sz) {
   return (pStr && *pStr && convert_case_in_place_(pStr,sz,CC_TO_LOWER));
}

/* In-place uppercasing of a string */
bool convert_to_upper(char * const restrict pStr) {
   return (pStr && *pStr && convert_case_in_place_(pStr,strlen(pStr),CC_TO_UPPER));
}

/* In-place uppercasing of a string */
bool convert_to_upper_ex(char * const restrict pStr,const size_t sz) {
   return (pStr && *pStr && convert_case_in_place_(pStr,sz,CC_TO_UPPER));
}

ssize_t count_substr(const char * const restrict line, const size_t lsz, const char * const restrict sstr, const size_t sssz){
   if (line && lsz && sstr &&  sssz ){
      ssize_t ctx=0;
      const char * line_=line;
      const char * const end_=(line+lsz);
      while(  
            (line_+sssz)<end_
            && ((line_=strstr(line_,sstr)))
            && (++ctx)
            && (line_+=sssz)
         );
      return ctx;
   }
   return INVALID_;
}

size_t cleanup_url(const char * const restrict src,const size_t srcsz, char *  const restrict out, const size_t outsz,const bool appendpath ){  
   ptrdiff_t curlsz=(ptrdiff_t)srcsz;
   if (outsz &&  curlsz && src && *src && out){
      const char *  curl=src;
      /* Strip off any preamble */
      char * part=NULL;
      ptrdiff_t dsz=0;
      if ((part=strnstr(curl,"://",(size_t)curlsz)) && ptr_diff(part+3,curl,&dsz) && dsz){
         curl+=dsz;
         curlsz-=dsz;
      }
      //rtrim
      while( *curl && !IS_ALPHA_C(*curl) && !IS_NUM(*curl) && (curl++) && (curlsz--));

      ptrdiff_t missing_part_start=0;
      const char * pmissing_part=NULL;
      size_t pmissing_part_sz=0;

      if (*curl && (part=strnstr(curl,"/",(size_t)curlsz))
         && ptr_diff(part,curl,&curlsz) && curlsz
         && appendpath && ptr_diff(part,src,&missing_part_start) && missing_part_start) {
         pmissing_part=(src+missing_part_start);
         pmissing_part_sz=(srcsz-(size_t)missing_part_start);
      }
      if(appendpath && !missing_part_start){
         pmissing_part="/";
         pmissing_part_sz=1;
         missing_part_start=curlsz;
      }
      if ((part=strnstr(curl,":",(size_t)curlsz))) (void)ptr_diff(part,curl,&curlsz);
      if (MAX_URL<curlsz) curlsz=MAX_URL;
      char oBUF[curlsz+1];
      (void)zm(oBUF,sizeof(oBUF));
      (void)strlcpy(oBUF,curl,sizeof(oBUF));
      (void)convert_to_lower_ex(oBUF,(size_t)curlsz);
      part=(oBUF+curlsz);
      //rtrim
      while((part>oBUF) && !IS_ALPHA_C(*part) && !IS_NUM(*part) && (part--));
      part++;(*part)=0; 
      curlsz=0;
      (void)ptr_diff(part,oBUF,&curlsz);
      part=oBUF;

      //ltrim
      while( (part<(oBUF+curlsz)) && !IS_NUM(*part) && !IS_ALPHA_C(*part)  && (*part=0) && (part++));
      dsz=0;
      (void)ptr_diff(part,oBUF,&dsz);

      (void)( ((0>(curlsz-dsz)) && !(curlsz=0)) || (curlsz-=dsz));
      if (outsz<(size_t)(curlsz+appendpath)) curlsz=(ptrdiff_t)(outsz-1);
      if (strlcpy(out,part,outsz)>=outsz) return 0;
      if ((appendpath && missing_part_start) && (curlsz+=pmissing_part_sz) && strlcat(out,pmissing_part,outsz)>=outsz) return 0;
   }
   return (size_t)curlsz;
}

TX_INTERNAL_INLINE
size_t map_str_parts_(const char * const restrict str,const size_t ssz,const int sep, t_strptr * const restrict map, const size_t msz ){
   if ((str && ssz && map && msz)){
      const char * ext_end=NULL;
      size_t ext_sz=ssz;
      uint_fast64_t i=0;
      uintptr_t max=(uintptr_t)(str+ssz);
      while(max && i<msz &&  (ext_end=(const char*)memrchr(str,sep,ext_sz)) ){
         map[i].ptr_=ext_end+1;
         ptrdiff_t pd=0;
         if (ptr_diff((const char *const)max,map[i].ptr_,&pd)){
            map[i].sz_=(size_t)pd;
            max=(uintptr_t)ext_end;
            ext_sz-=(map[i].sz_+1);
            ++i;
         } else 
          return 0;
      }
      return i;
   }
   return 0;
}

TX_INTERNAL_INLINE
bool map_path_from_url_(   const char * const restrict url,
                           const size_t usz,
                           const char ** const restrict mapped_path,
                           size_t * const restrict mapped_psz           )
{
   ptrdiff_t dsz=0;
   return (
         (url && usz && mapped_path && mapped_psz) &&
         ((((*mapped_path)=strnstr(url,"://",usz)) && ptr_diff(((*mapped_path)+=3),url,&dsz) && ((*mapped_psz)=usz-(size_t)dsz)) || (((*mapped_path)=url) && ((*mapped_psz)=usz))) &&
         ((((*mapped_path)=strnstr((*mapped_path),"/",(*mapped_psz))) && !(dsz=0) && ptr_diff((++(*mapped_path)),url,&dsz) && ((*mapped_psz)=usz-(size_t)dsz)) || ((*mapped_psz)=0)) &&
         (*mapped_psz) && (*mapped_path)
   );
}

bool map_path_from_url(const char * const restrict url,const size_t usz,const char ** const restrict mapped_path, size_t * const restrict mapped_psz){
   return map_path_from_url_(url,usz,mapped_path,mapped_psz);
}

size_t map_str_parts(const char * const restrict str,const size_t ssz,const int sep, t_strptr * const restrict map, const size_t msz ) {
   return map_str_parts_(str,ssz,sep,map,msz);
}

size_t map_extentions_from_url(  const char * const restrict url,
                                 const size_t usz,
                                 t_strptr * const restrict map, 
                                 const size_t msz                 )
{
   const char* match_str=NULL;
   size_t match_str_sz=0;

   if ( map && msz && map_path_from_url_( url, usz, &match_str, &match_str_sz ) ) {

      return map_str_parts_(match_str,match_str_sz,'.',map,msz);
   }
   return 0;
   
}

void strrev_in_place(char * restrict p) {
   char *q = p;
   while(q && *q) ++q;
   for(--q; p < q; ++p, --q)
      (void)(*p = *p ^ *q),
      (void)(*q = *p ^ *q),
      (void)(*p = *p ^ *q);
}

size_t str_dedup_in_place(char * const restrict in, const size_t isz){
   if (in && isz){
      size_t l=0;
      for (size_t c=0;in[l] && c<isz;(void)(in[l]!=in[c] && (in[++l]!=in[c]) && (in[l]=in[c])),++c);
      return (!in[l]?l:l+1);
   }
   return 0;
}

size_t str_space_nomalization_in_place(char * const restrict in, const size_t isz){
   if (in && isz){      
      size_t l=0;
      for (size_t c=1; in[l] && c<isz;(void)((in[l]!=in[c] || !isspace(in[l]) ) && (in[++l]=in[c])),++c);
      return (!in[l]?l:l+1);
   }
   return 0;
}

size_t str_rep_space_as_in_place(char * const restrict in, const size_t isz,const char as){
   if (in && isz){
      (void)(isspace(in[0]) && (in[0]=as));
      size_t l=0;
      for (size_t c=1;in[l] && c<isz;(void)((in[l]!=in[c] || as!=in[l]) && (( (!(isspace(in[c]) && as!=in[c])) && ((in[++l]=in[c])||1) ) || (as!=in[l] && (in[++l]=as)))),++c);
      return (!in[l]?l:l+1);
   }
   return 0;
}

#define HEX_BYTE_SZ 3

bool url_encode(  const char* const restrict url,
                  const size_t url_sz,
                  const size_t out_sz,
                  char * restrict out            )
{

   if (  url != out  &&

         url         && 

         out         &&

         url_sz      &&

         out_sz         ) {

      size_t i_=0;

      const char * const out_max = out + out_sz;

      while (  url_sz > i_    && 

               url[ i_ ]      &&

               out_max > out     ) {

         switch ( url[ i_ ] ){

            case '0' ... '9':
            case 'A' ... 'Z':
            case 'a' ... 'z':
            case '-':
            case '_':
            case '.':
            case '~':{

               *out++ = url[ i_++ ];

               continue;
            }

            default:{

               if ( out_max > out + HEX_BYTE_SZ ) {

                  const uint8_t hi_ = (uint8_t)( ( url[ i_ ] & 0x0F0 ) >> 4 );

                  const uint8_t lo_ = (uint8_t)( url[ i_ ] & 0x0F );

                  static const uint8_t enc_[] = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

                  memcpy( out, ( uint8_t[ HEX_BYTE_SZ ] ){ '%', enc_[ hi_ ], enc_[ lo_ ] }, HEX_BYTE_SZ );

                  out +=  HEX_BYTE_SZ;

                  ++i_;

                  continue;
               }

               /* else not enough space to encode, break, break, break! */
            } break;

         } /* switch */

         break; /* break, break, break! */

      } /* while */

      *out = 0; /* terminate for safety */

      ptrdiff_t diff=0;

      return (    i_ == url_sz                        || 

                  /* it's OK if the input is shorter than expected */
                  !url[i_]                            ||

                  /* 
                   * it's OK if the out buffer is shorter than input
                   * and there is at least one byte copied/encoded
                   */ 

                  (  ptr_diff( out_max, out, &diff )  &&

                     out_sz > (size_t)diff               )  );
   }

   return false;
}

bool url_decode_ex(char* url,const size_t sz,size_t * decoded,const bool plus4space) {
   return url_decode_ex_(url,sz,decoded,plus4space);
}

bool url_decode(char* url,const bool plus4space) {
   return (url && url_decode_ex_(url,strlen(url),NULL,plus4space));
}

#include <glib.h>
char * utf8_str2down(char * str, const size_t len){
   return g_utf8_strdown((gchar*)str,(gssize)len);
}

bool utf8_valid(char * str, const size_t len, const char **const restrict end){
   return (bool)(g_utf8_validate((gchar*)str,(gssize)len,end));
}

int utf8_cmp(const char * const l_, const char * const restrict r_){
   return g_utf8_collate((const gchar*)l_,(const gchar*)r_);
}

size_t utf8_length(char * str, const size_t len){

   return ( str && *str && len                                 ?

            (size_t)g_utf8_strlen( (gchar*)str, (gssize)len )  :

            0                                                     );
}

bool utf8_free(char * str){
   g_free(str);
   return true;
}
