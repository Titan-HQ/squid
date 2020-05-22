/*
 * $Id: global.c 7345 2013-01-15 18:56:10Z dawidw
 *
 * Copyright (c) 2005-2013, Copperfasten Technologies, Teoranta.  All rights
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


#include "global.h"
#include <assert.h>
#include <limits.h>
#include <pthread.h>
#include <stdalign.h>
#include <stdarg.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#if ( !defined(__GNUC__) && !defined(__GNUG__) ) 
tx_static_assert_true(  __FreeBSD_version >= MIN_OS_FB_11 || __clang_major__ <= 6,
                        "Unable to compile using the LLVM 7 or 8 on the FreeBSD 10 : std lib error" );
#endif

#include "log.h"

TX_INTERNAL_INLINE
int strtoi32_(const char *nptr,char **endptr,int base) {
   long long int r_=0;
   errno=0;
   (void)TEST_STRTOX_(nptr,r_,strtoll(nptr, endptr, base),INT_MIN,INT_MAX);
   return ((int)r_);
}

TX_INTERNAL_INLINE
unsigned int strtoui32_(const char *nptr,char **endptr,int base) {
   unsigned long long int r_=0; 
   errno=0;
   (void)(((!nptr && (errno=EINVAL))  ||  (nptr[0]=='-' && (errno=ERANGE) && (r_=UINT_MAX))) || (TEST_STRTOX_UI_(nptr,r_,strtoull(nptr, endptr, base),UINT_MAX)));
   return ((unsigned int)r_);   
}

TX_INTERNAL_INLINE
unsigned long int strtoui64_(const char *nptr,char **endptr,int base){
   unsigned long long  int r_=0;
   errno=0;
   (void)(( (!nptr && (errno=EINVAL))  ||  (nptr[0]=='-' && (errno=ERANGE) && (r_=ULONG_MAX))) || (TEST_STRTOX_UI_(nptr,r_,strtoull(nptr, endptr, base),ULONG_MAX)));
   return ((unsigned long int)r_);
}

TX_INTERNAL_INLINE
long int strtoi64_(const char *nptr,char **endptr,int base){
   long long  int r_=0;
   errno=0;
   (void)(TEST_STRTOX_(nptr,r_,strtoll(nptr, endptr, base),LONG_MIN,LONG_MAX));
   return ((long int)r_);
}

TX_INTERNAL_INLINE
long long int strtoll_(const char *nptr,char **endptr,int base){
   long long  int r_=0;
   errno=0;
   (void)(TEST_STRTOX_(nptr,r_,strtoll(nptr, endptr, base),LLONG_MIN,LLONG_MAX));
   return (r_);
}

TX_INTERNAL_INLINE
unsigned long long int strtoull_(const char *nptr,char **endptr,int base){
   unsigned long long  int r_=0;
   errno=0;
   (void)(((!nptr && (errno=EINVAL))  ||  (nptr[0]=='-' && (errno=ERANGE) && (r_=ULLONG_MAX))) || (TEST_STRTOX_UI_(nptr,r_,strtoull(nptr, endptr, base),ULLONG_MAX)));   
   return (r_);
}

TX_INTERNAL_INLINE
bool tx_get_info_sz_ex_(int pMIB[], size_t * size) {
   return (sysctl(pMIB, 4, 0,size, 0, 0)==0);
}

TX_INTERNAL_INLINE
bool tx_get_info_(char* const buffer, size_t * const size, const t_tx_proc_inf pType,const bool pCalcSZ) {
   
   if (buffer && size){
      int mib[4];
      switch (pType){
         case tpi_args:{
            mib[0] = CTL_KERN;
            mib[1] = KERN_PROC;
            mib[2] = KERN_PROC_ARGS;
            mib[3] = getpid();
         }break;
         case tpi_path: {
            mib[0] = CTL_KERN;
            mib[1] = KERN_PROC;
            mib[2] = KERN_PROC_PATHNAME;
            mib[3] = -1;
         }break;
      }
      size_t cb;
      //get size
      if (pCalcSZ){
         cb = 0;
         if (!tx_get_info_sz_ex_(mib,&cb)){return false;}
         //if (sysctl(mib, 4, 0, &cb, 0, 0)){return (false);};
         if (cb>(*size)){return false;}
      }

      //get value
      cb = (*size);
      if (!sysctl(mib, 4, buffer,&cb, 0, 0)){
         *size = (unsigned int)cb;
         return true;
      }
   }
   return false;
}


TX_INTERNAL_INLINE
bool tx_get_info_sz_(const t_tx_proc_inf pType, size_t * const size) {
   
   if (size){
      int mib[4];
      switch (pType){
         case tpi_args:{
            mib[0] = CTL_KERN;
            mib[1] = KERN_PROC;
            mib[2] = KERN_PROC_ARGS;
            mib[3] = getpid();
         }break;
         case tpi_path:{
            mib[0] = CTL_KERN;
            mib[1] = KERN_PROC;
            mib[2] = KERN_PROC_PATHNAME;
            mib[3] = -1;
         }break;
      }

      //get size
      size_t cb=0;
      if (tx_get_info_sz_ex_(mib,&cb)){
         *size = (unsigned int)cb;
         return true;
      }
   }
   return false;
}

//modern
TX_INTERNAL_INLINE
void * tx_safe_realloc_(void * const o,size_t dsz,size_t nsz){
   
   if (nsz){
      void * const n=calloc(1,nsz);
      //if(n && o && (((dsz>nsz) && (dsz=nsz)) || (dsz)) && tx_safe_memcpy(n,o,dsz)) *((char*const)n+dsz)=0;
      if(n && o && (((dsz>nsz) && (dsz=nsz)) || (dsz))) (void)tx_safe_memcpy(n,o,dsz);
      if(n && o) (void)tx_safe_free(o);
      return n;
   }
   assert(0 && "tx_saferealloc crap!!!");//FIXME::remove me 
   return NULL;
}

TX_INTERNAL_INLINE
bool data_buff_grow_(t_data_buff * const db,const size_t nsz)
{
   if (db){ 

      if ( nsz > db->db_sz ){

         if (  (  db->db_sz && UINT_MAX > db->db_sz + nsz ) ||

                  UINT_MAX > nsz<<1                            ) {

            db->db_sz += ( db->db_sz ? nsz : nsz<<1 );

         } 
         else
            db->db_sz = UINT_MAX;

         db->db=(char*)tx_safe_realloc_( db->db, db->data_sz, db->db_sz );

         if ( !db->db ) {

            titax_log(  LOG_ERROR,
                        "ASSERT :: %s:%d tx_safe_realloc_ failed - dying!\n",
                        __func__,
                        __LINE__                                              );

            exit(-1);  
         }
      }

      return true;
   }

   return false;
}

TX_INTERNAL_INLINE
bool data_buff_zero_(t_data_buff * const db){
   return (db && db->db_sz && zm(db->db,db->db_sz) && !(db->data_sz=0));
}

////////////////////////////////////////////////////////////////////////////////

void tx_safe_free(void * const p){
   if (p) free(p);
}

void * tx_safe_realloc_ex(void * const o,size_t dsz,size_t nsz){
   return (tx_safe_realloc_(o,dsz,nsz));
}

bool tx_get_info_sz(t_tx_proc_inf pType, size_t * size) {
   return (tx_get_info_sz_(pType,size));
}

bool tx_get_info(char* buffer, size_t * size,t_tx_proc_inf pType,bool pCalcSZ) {
   return (tx_get_info_(buffer,size,pType,pCalcSZ));
}

bool tx_get_args_ex(char* pBuff, size_t * pBuffSZ){
   return (tx_get_info_(pBuff,pBuffSZ,tpi_args,true));
}

bool tx_get_path_ex(char* pBuff, size_t * pBuffSZ){
   return (tx_get_info_(pBuff,pBuffSZ,tpi_path,true));
}

char * tx_get_args(size_t * pOutSize){
   size_t t_sz;
   size_t * sz=(!pOutSize?&t_sz:pOutSize);
   if (!tx_get_info_sz_(tpi_args,sz)){return NULL;}
   char * rbuff=tx_safe_malloc((*sz));
   if (!rbuff){return NULL;}
   if (!tx_get_info_(rbuff,sz,tpi_args,false)){
      tx_safe_free(rbuff);
      return NULL;
   }
   return rbuff;
}

char * tx_get_path(size_t * pOutSize){
   size_t t_sz;
   size_t * sz=(!pOutSize?&t_sz:pOutSize);
   if (!tx_get_info_sz_(tpi_path,sz)){return NULL;}
   char * rbuff=tx_safe_malloc((*sz));
   if (!rbuff){return NULL;}
   if (!tx_get_info_(rbuff,sz,tpi_path,false)){
      tx_safe_free(rbuff);
      return NULL;
   }
   return rbuff;
}


ssize_t ttn_out_raw(const char * const format, ...){
   va_list ap;
   va_start(ap,format);
   ssize_t l=0;
   if ((l=vsnprintf(0, 0, format, ap))>0){
      char buf[l+1];
      (void)zm(buf,sizeof(buf));
      (void)vsnprintf(buf,(size_t) l, format, ap);
      (void)write(1,buf,(size_t)l);
      va_end ( ap );
      return l;
   }
   va_end ( ap );
   return l;
}

void * tx_safe_malloc(const size_t sz){
   return (tx_safe_realloc_(NULL,0,sz));
}

__attribute__((malloc))
void * tx_safe_calloc(const size_t n,const size_t sz){
   return (tx_safe_realloc_(NULL,0,n*sz));
}

__attribute__((malloc,nonnull))
void * tx_safe_realloc(void * p,const size_t nsz){
   return (tx_safe_realloc_(p,0,nsz));
}

__attribute__((nonnull))
void * tx_safe_memcpy(void * const d,const void * const s,const size_t l){
   return (!OVERLAP(d,s,l)?memcpy(d,s,l):memmove(d,s,l));
}

size_t tx_safe_snprintf(char * const restrict b,const size_t n,const char * const restrict f,...){
   if (b && n && f){
      va_list args;
      va_start (args, f);
      const int r_=vsnprintf(b,n,f, args);
      va_end (args);
      if (INVALID_<r_) return (size_t)r_;
   }
   assert(0 && "tx_safe_snprintf error");
}


/////////////////////////////////////////////////////////////////////////////////EXP
//alias
size_t sm(void * const restrict b_, const size_t bs_,const char c_){
   if (b_ && bs_){
      const void * ptr=memset(b_,c_,bs_);
      assert(ptr && "memset failed");
      if (c_) assert((((char*)b_)[bs_-1]==c_) && "memset failed");
   }
   return bs_;
}

bool tx_safe_atoi(const  char * const p,int * o){
   *o=strtoi32_(p, (char **)NULL, 10);
   return (EINVAL!=errno && ERANGE!=errno);
}

bool tx_safe_atoui(const  char * const p,unsigned int * o){
   *o=strtoui32_(p, (char **)NULL, 10);
   return (EINVAL!=errno && ERANGE!=errno);
} 

bool tx_safe_atoul(const  char * const p,unsigned long int * o){
   *o=strtoui64_(p, (char **)NULL, 10);
   return (EINVAL!=errno && ERANGE!=errno);
} 

bool tx_safe_hextoul(const  char * const p,unsigned long int * o){
   *o=strtoui64_(p,(char **)NULL, 16);
   return (EINVAL!=errno && ERANGE!=errno);
} 

bool tx_safe_atol(const  char * const p, long int * o){
   *o=strtoi64_(p, (char **)NULL, 10);
   return (EINVAL!=errno && ERANGE!=errno);
} 

bool tx_safe_atoll(const  char * const p, long long int * o){
   *o=strtoll_(p, (char **)NULL, 10);
   return (EINVAL!=errno && ERANGE!=errno);
} 

bool tx_safe_atoull(const  char * const p, unsigned long long int * o){
   *o=strtoull_(p, (char **)NULL, 10);
   return (EINVAL!=errno && ERANGE!=errno);
} 

bool tx_safe_atob(const  char * const p,bool * o){
   errno=0;
   unsigned int r_=0;
   return (p && tx_safe_atoui(p,&r_) && ( (*o=!(!r_)) || true));
}

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */

static unsigned int g_DataBuff_instances_c = 0;
static unsigned int g_DataBuff_instances_d = 0;
unsigned int get_DataBuff_active_instances()
{
    return( g_DataBuff_instances_c - g_DataBuff_instances_d );
}
////////////////////////////////////////////////////////////////////////////////

t_data_buff * data_buff_new(const size_t sz){
   t_data_buff * const r=(t_data_buff * const)tx_safe_malloc(sizeof(t_data_buff));
   assert(r);
   if (sz) (void)data_buff_grow_(r,sz);
   /* DI */
   g_DataBuff_instances_c++;
   return (r);
}

bool data_buff_free(t_data_buff ** const restrict db){
   if (db && *db){
      (void)data_buff_zero_((*db));
      tx_safe_free((*db)->db);
      (*db)->db=NULL;
      (*db)->db_sz=0;
      (*db)->data_sz=0;
      tx_safe_free((*db));
      /* DI */
      g_DataBuff_instances_d++;
      (*db)=NULL;
      return true;
   }

   return false;
}

__attribute__((nonnull))
bool data_buff_grow(t_data_buff * const  restrict db,const size_t nsz){
   return (data_buff_grow_(db,nsz));
}

__attribute__((nonnull))
bool data_buff_zero(t_data_buff * const restrict db){
   return (data_buff_zero_(db));
}

bool data_buff_write(   t_data_buff * const restrict db,
                        const char * const restrict in, 
                        const size_t in_sz               )
{
   if ( in && in_sz && db && db->db && db->db_sz>in_sz ) {

      db->db[0]=0;

      const size_t dsz = strlcat( db->db, in, db->db_sz );

      if ( dsz< db->db_sz && dsz == in_sz ) {

         db->data_sz=in_sz;

         return true;
      }
   }

   return false;
}

ssize_t data_buff_read( t_data_buff * const restrict db,
                        char * const restrict out,
                        size_t out_sz                    ) {

   return ((db && out && out_sz && db->db && db->data_sz && (out_sz<db->data_sz?out_sz:(out_sz=db->data_sz))&& tx_safe_memcpy(out,db->db,out_sz))?(ssize_t)out_sz:INVALID_);
}

/* if building on FreeBSD older than 11.0 then conditionaly terminate the TSA (TSA_OFF) */

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
void tsa_lock( pthread_mutex_t * restrict mtx )
{
   pthread_mutex_lock(mtx);
}

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
bool tsa_try_lock( pthread_mutex_t * restrict mtx )
{
   return !(bool)(pthread_mutex_trylock(mtx));
}

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
void tsa_unlock( pthread_mutex_t * restrict mtx )
{
   pthread_mutex_unlock(mtx);
}

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
bool tsa_try_unlock( pthread_mutex_t * restrict mtx )
{
   return !pthread_mutex_unlock(mtx);
}

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
void tsa_rd_lock( pthread_rwlock_t * restrict mtx )
{
   pthread_rwlock_rdlock(mtx);
}

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
bool tsa_try_rd_lock( pthread_rwlock_t * restrict mtx )
{
   return !(bool)(pthread_rwlock_tryrdlock(mtx));
}

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
void tsa_rd_unlock( pthread_rwlock_t * restrict mtx )
{
   pthread_rwlock_unlock(mtx);
}

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
void tsa_wr_lock( pthread_rwlock_t * restrict mtx )
{
   pthread_rwlock_wrlock(mtx);
}


/* quirks */
#if (    ( __FreeBSD_version < MIN_OS_FB_11 ) || \
         ( __clang_major__ == 6 && __clang_minor__ == 0 &&  __clang_patchlevel__ <= 1 ) || \
         ( __clang_major__ >= 4 )  )

   TSA_OFF
#endif
bool tsa_try_wr_lock( pthread_rwlock_t * restrict mtx )
{
   return !(bool)(pthread_rwlock_wrlock(mtx));
}

#if (  __FreeBSD_version < MIN_OS_FB_11 )
   TSA_OFF
#endif
void tsa_wr_unlock( pthread_rwlock_t * restrict mtx )
{
   pthread_rwlock_unlock(mtx);
}

/*
t_bit
int mib[4];
mib[0] = CTL_KERN;
mib[1] = KERN_PROC;
mib[2] = KERN_PROC_PATHNAME;
mib[3] = -1;
char buf[1024];
size_t cb = sizeof(buf);
sysctl(mib, 4, buf, &cb, NULL, 0);
*/
