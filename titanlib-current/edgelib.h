/*
 * $Id$
 */
#ifndef EDGELIB_H
#define EDGELIB_H
#include <stddef.h>
#include <search.h>
#include "global.h"
#include "txhash.h"
#include "ttn_tools_c.h"


#ifdef __cplusplus
extern "C" {
#endif


//---------------------------------------------------------------------
// Define.
//---------------------------------------------------------------------
#define IS_EMPTY(value) (value == NULL || ! value[0])
#define MAX_MAP_KW_SIZE 255
#define DEF_LIST_SIZE 200
#define LOOP_MAX  0xffff

typedef struct{
   size_t         size;
   size_t         buf_size_;
   size_t         length;
   char**         arr;
} StringList;

typedef struct{
   size_t         size;
   StringList*    list;
   StringList*    kw_list;
} StringMap;

typedef struct{
   size_t         size;
   StringList*    kw_list;
   void*          root;
} StringTree;

typedef struct{
   size_t         size;
   size_t         buf_size_;
   size_t         length;
   void**         arr;
   void           (*val_free)(void*);
} VoidList;

typedef struct{
   char*          kw;
   void*          val;
   t_hash         kh;
} VoidPair;

typedef struct{
   size_t         size;
   VoidList*      list;
   StringList*    kw_list;
   void           (*val_free)(void*);
} VoidMap;

typedef struct{
   size_t         size;
   StringList*    kw_list;
   void*          root;
   void           (*val_free)(void*);
} VoidTree;

typedef struct{
   StringList*    list;
   ssize_t        lookup_idx;
   const char *   key;
   size_t         key_sz;
}t_StringList_lookup_call;


//---------------------------------------------------------------------
// String.
//---------------------------------------------------------------------

char* ptrim(char* ,const size_t);
size_t str_starts_with(const char*const  line, const char*const  kw);
ssize_t str_cmp_trimmed(const char*const, const char*const);
//---------------------------------------------------------------------
// StringList.
//---------------------------------------------------------------------
StringList* string_list_new(void);
void string_list_sort(StringList* const list);
void string_list_rsort(StringList* const list);
ssize_t string_list_find_index_by_kw(const StringList* const  pList,const char* const  pKw);
bool string_list_compact(StringList * const pList);
//---------------------------------------------------------------------
// StringMap.
//---------------------------------------------------------------------
StringMap* string_map_new(void);
bool string_map_clear(StringMap* const);
bool string_map_free(StringMap* const);
void string_map_print_all(StringMap* const);
bool string_map_empty(StringMap* const);
bool string_map_add(StringMap* const, const char* const, const char* const);
void string_map_sort(StringMap* const);
bool string_map_find(StringMap* const, const char* const);
bool string_map_val(const StringMap* const, const char* const, char * const, const size_t);
int string_map_val_int(const StringMap* const, const char* const);
ssize_t string_map_bsearch_by_kval(char** const, const size_t, const char* const);
ssize_t string_map_bsearch_by_key(char** const, const size_t, const char* const);


//---------------------------------------------------------------------
// StringTree.
//---------------------------------------------------------------------
VoidPair* void_pair_new(const char* const kw,void* val);
bool void_pair_free(VoidPair* const  vp, void (*val_free)(void*));
void vp_list_sort(VoidList* const  list);
VoidMap* void_map_new(void (*val_free)(void*));
void void_map_clear(VoidMap* const map);
void void_map_free(VoidMap*const  map);
bool void_map_add2(VoidMap*const  map,const  char* const kw, void*const  val);
bool void_map_remove_by_kw(VoidMap*const  pMap,const char*const  pKw);
void void_map_sort(VoidMap* const map);
void* void_map_val(const VoidMap* const map,const  char*const  kw);
ssize_t void_map_bsearch(void** arr, const size_t size,const  char*const  key);
ssize_t void_map_search_vp(const VoidMap*const  pMap,const VoidPair*const  pVP);
VoidPair* void_map_find(const VoidMap*const  map, const  char*const  kw);
ssize_t void_map_find_index_by_vp(const VoidMap*const  pMap,const VoidPair*const  pVp);
ssize_t void_map_find_index_by_kw(const VoidMap*const  pMap,const char*const  pKw);

//---------------------------------------------------------------------
// File.
//---------------------------------------------------------------------
bool file_exists(const char* const filename);
ssize_t file_size(const char* const filename);

int append_text_file(const char*const  filename, char* line);
void file_dirname(const char*const  filename, char *const buf,const size_t);
void file_basename(const char* const filename, char *const buf,const size_t);
void file_extension(const char* const filename, char*const buf,const size_t);

//---------------------------------------------------------------------
// Misc.
//---------------------------------------------------------------------
bool exbin(const char* const cmd, const size_t buf_len,char *const  buf);

#ifdef __cplusplus
}
#endif

TXATR StringList* read_text_file(const char*const, const int);
TXATR  int write_text_file_ex(const char*const, const char*const,const bool);
TXATR int write_text_file(const char*const,const char*const);


/**
 * trim_ex
 * @param line          : input string
 * @param buf           : out buffer
 * @param buf_max_sz    : out buffer max size (+1 for null byte)
 * @return 
 */
TXATR size_t trim_ex(const char*, char * const, const size_t);

/**
 * trim_ptr
 * this method does not allocate a new string buffer it just returns a pointer to the existing one (input string)
 * @param line    :input string
 * @param lsz     :input string len
 * @param outlen  :out str length
 * @return        :out string ptr 
 */
TXATR char* trim_ptr(char* ,const size_t, size_t * const);

TXATR size_t trim_quotes(const char* const , const size_t, char * const , const size_t);
TXATR StringList* split_ex(char* const ,const char* const , const size_t);
TXATR StringList* split(const char* const ,const char* const );
TXATR StringList* split_by_space(const char*const,const size_t);
TXATR bool join(StringList* const list, const char* const  glue, char * const buf, const size_t bsz );
TXATR char*  pjoin(StringList* const list, const char* const glue);

TXATR bool string_list_clear(StringList* const );
TXATR void string_list_print_all(StringList* const );
TXATR char* string_list_find(StringList* const list, const char*const kw);
TXATR bool string_list_del(StringList* const list,const  char* const line);
TXATR bool string_list_add(StringList* const,const char* const);
TXATR bool string_list_free(StringList*const list);
TXATR bool string_list_resize(StringList*const  list);
TXATR bool string_list_lookup_key(t_StringList_lookup_call * const );
TXATR size_t string_list_count_item(StringList*const ,const char*const );

TXATR bool mk_string_list_lookup_call( t_StringList_lookup_call *const,
                                       const char * const,
                                       const size_t );

TXATR bool get_cfg_key_value(char * ,char * const ,size_t * const  ,const size_t);
   

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//methods imported from the old stringutils
////////////////////////////////////////////////////////////////////////////////
 /*last index of char */
TXATR ssize_t  last_index(char * const pStr, const char pC);

/*last pointer to char  */
TXATR char * last_char(char * const pStr, const char pC);

/* In-place convert case  to opposite  */
TXATR bool convert_case_in_place(char * const);

/* In-place lowercasing of a string */
TXATR bool convert_to_lower(char * const);
TXATR bool convert_to_lower_ex(char * const,const size_t);


/* In-place uppercasing of a string */
TXATR bool convert_to_upper(char *const);
TXATR bool convert_to_upper_ex(char * const,const size_t);

/* In-place conversion of '%20' to ' ' */
TXATR void unEscapeSpace(char *);

/* duplicate str - sub str*/
TXATR char* str_dup_ex(const char* const ,size_t * const);
TXATR char* str_dup(const char*const);


TXATR void strrev_in_place(char * );


/**
 * str_dedup_in_place
 * 
 * When the isz is lower than the actual length of the in_str (e.g. to apply dedup to the part of the string)
 * then the resulting str (in part above the isz limit) might contain unpredictable bytes.
 * 
 * @param in_str  :input string
 * @param isz     :size of the input string
 * @return        :size of the new string or part of it
 */
TXATR size_t str_dedup_in_place(char * const, const size_t);

/**
 * str_space_nomalization_in_place
 * 
 * When the isz is lower than the actual length of the in_str (e.g. to apply normalization to the part of the string)
 * then the resulting str (in part above the isz limit) might contain unpredictable bytes.
 * 
 * @param in_str  :input string
 * @param isz     :size of the input string
 * @return        :length of the new (normalized) string or part of it
 * e.g.
 * a) [aaabbbccc]:9=>[abc]:3
 * b) [aaabbbccc]:8=>[abcbbbccc]:3
 */
TXATR size_t str_space_nomalization_in_place(char * const, const size_t);

/**
 * str_rep_space_as_in_place (this method will normalize the string as well)
 * 
 * When the isz is lower than the actual length of the in_str (e.g. to apply the method to the part of the string)
 * then the resulting str (in part above the isz limit) might contain unpredictable bytes.
 * 
 * @param in_str  :input string
 * @param isz     :size of the input string
 * @param as      :symbol to replace spaces (e.g.\t\32) with 
 * @return        :size of the new string or part of it
 */
TXATR size_t str_rep_space_as_in_place(char * const, const size_t,const char);

/**
 * @name                url_encode
 * @abstract            encode string as urlencoded
 * @param url[in]       clear string
 * @param url_sz[in]    clear string length
 * @param out_sz[out]   enc buffer size 
 * @param out[out]      enc buffer
 * @return              t/f
 * @note it's OK if the input is shorter than expected (url_sz)
 * @note it's OK if the out buffer is shorter than input and there is at least one byte copied/encoded
 */
TXATR bool url_encode(const char* const , const size_t, const size_t, char *const );
/**
 * @name                   url_decode_ex
 * @abstract               decode inplace url encoded string
 * @param url[in]          input string 
 * @param sz[in]           input string size
 * @param decoded[out]     decoded string size
 * @param plus4space[in]   decode pluses as spaces
 * @return                 t/f
 */
TXATR bool url_decode_ex(char* ,const size_t,size_t *,const bool);
/**
 * @name                   url_decode
 * @abstract               decode inplace url encoded string
 * @param url[in]          input string
 * @param plus4space[in]   decode pluses as spaces
 * @return                 t/f
 */
TXATR bool url_decode(char* ,const bool);

/**
 * 
 * @param 
 * @param 
 * @param 
 * @param 
 * @return 
 */
TXATR ssize_t count_substr(const char * const, const size_t, const char * const, const size_t);

/**
 * 
 * @param url
 * @param usz
 * @param mapped_path
 * @param mapped_psz
 * @return 
 */
TXATR bool map_path_from_url(const char * const url,const size_t usz,const char ** const mapped_path, size_t * const mapped_psz);

/**
 * 
 * @param url
 * @param usz
 * @param sep
 * @param map
 * @param msz
 * @return 
 */
TXATR size_t map_str_parts(const char * const,const size_t,const int, t_strptr * const, const size_t );

/**
 * 
 * @param url
 * @param usz
 * @param map
 * @param msz
 * @return 
 */
TXATR size_t map_extentions_from_url(const char * const url,const size_t usz,t_strptr * const map, const size_t msz );

/**
 * @name             cleanup_url
 * @abstract         Routine called to 'normalise' the url so that we can use it without worrying about port numbers etc
 * @note             Caller bears the responsibility to provide enough space in the dst ptr 
 * @param src        src url (possibly malformed)
 * @param srcsz      length 
 * @param out        out buffer 
 * @param outsz      out buffer max size
 * @param appendpath flag (1/0) what to do with the path of the src url
 * @return           length of new url (might include path)
 */
TXATR size_t cleanup_url(const char * const ,const size_t, char * const ,const size_t,const bool );


TXATR  char * utf8_str2down(char * , const size_t);
TXATR  bool utf8_valid(char *, const size_t, const char **const);
TXATR  size_t utf8_length(char * , const size_t);
TXATR  bool utf8_free(char *);
TXATR  int utf8_cmp(const char *const, const char * const);

////////////////////////////////////////////////////////////////////////////////


#ifdef TTN_ATESTS   
TXATR ssize_t kv_extract_val(const char * kv, const size_t kvsz, const char * const key, const size_t ksz, const char** out_val);
#endif


////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */

TXATR unsigned int get_StringList_active_instances(void);
TXATR unsigned int get_StringMap_active_instances(void);
#endif /* EDGELIB_H */
