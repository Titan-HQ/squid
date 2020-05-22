/*
 * $Id$
 */

#ifndef TTN_TSA
#define TTN_TSA

#include "global.h"

/* Thread Safety Analyzer */

#ifndef TTN_ANNOTATE
   #if defined(__clang__) && (!defined(SWIG))
      #define TTN_ANNOTATE(...) __attribute__((__VA_ARGS__)) 
   #else 
      #define TTN_ANNOTATE(...)
   #endif
#endif

#ifndef TTN_LIB_INLINE_ANNOTATE
   #if defined(__clang__) && (!defined(SWIG))
      #define TTN_LIB_INLINE_ANNOTATE(...) extern __attribute__((always_inline,gnu_inline,__VA_ARGS__)) inline
   #else 
      #define TTN_LIB_INLINE_ANNOTATE(...)
   #endif
#endif

#ifndef TTN_CANNOTATE
   #if (__clang_major__ >= 4 || __clang_minor__ > 4)
      #define TTN_CANNOTATE(N,O) TTN_ANNOTATE( N )
   #else
      #define TTN_CANNOTATE(N,O) TTN_ANNOTATE( O )
   #endif
#endif

#ifndef TTN_LI_CANNOTATE
   #if (__clang_major__ >= 4 || __clang_minor__ > 4)
      #define TTN_LI_CANNOTATE(N,O) TTN_LIB_INLINE_ANNOTATE( N )
   #else
      #define TTN_LI_CANNOTATE(N,O) TTN_LIB_INLINE_ANNOTATE( O )
   #endif
#endif

/*******************************************************************************/

/* TSA mutex class capability */
#ifndef TSA_CAP_MTX
   #define TSA_CAP_MTX TTN_CANNOTATE( capability("mutex"), lockable )
#endif

/* TSA scoped mutex class capability */
#ifndef TSA_CAP_SCOPED_MTX
   #define TSA_CAP_SCOPED_MTX TTN_ANNOTATE( scoped_lockable )
#endif

/* TSA disable */
#ifndef TSA_OFF
   #define TSA_OFF TTN_ANNOTATE( no_thread_safety_analysis )
#endif

/*******************************************************************************/

/* TSA guard required for the variable */
#ifndef TSA_GUARDED_BY
   #define TSA_GUARDED_BY(...) TTN_ANNOTATE( guarded_by(__VA_ARGS__) )
#endif

/* TSA exclusive capability tracer required */
#ifndef TSA_CAP_TR_RQ
   #define TSA_CAP_TR_RQ(...)   TTN_CANNOTATE(\
           requires_capability(__VA_ARGS__), \
           exclusive_locks_required(__VA_ARGS__) )
#endif

/* TSA shared capability tracer required */
#ifndef TSA_CAP_SH_TR_RQ
   #define TSA_CAP_SH_TR_RQ(...)    TTN_CANNOTATE(\
           requires_shared_capability(__VA_ARGS__), \
           shared_locks_required(__VA_ARGS__) )
#endif

/*******************************************************************************/

/* TSA exclusive acquire */
#ifndef TSA_AQ
   #define TSA_AQ(...) TTN_CANNOTATE(\
        acquire_capability(__VA_ARGS__), \
        exclusive_lock_function(__VA_ARGS__) )
#endif

/* LIB INLINE TSA exclusive acquire */
#ifndef LI_TSA_AQ
   #define LI_TSA_AQ(...) TTN_LI_CANNOTATE(\
        acquire_capability(__VA_ARGS__),\
        exclusive_lock_function(__VA_ARGS__) )
#endif

/* TSA exclusive release */
#ifndef TSA_RE
   #define TSA_RE(...)  TTN_CANNOTATE(\
        release_capability(__VA_ARGS__),\
        unlock_function(__VA_ARGS__) )
#endif
      
/* TSA release all types of locks */
#ifndef TSA_RE_ALL
   #define TSA_RE_ALL(...) TTN_ANNOTATE( unlock_function(__VA_ARGS__) )
#endif

/* LIB INLINE TSA exclusive release */
#ifndef LI_TSA_RE
   #define LI_TSA_RE(...) TTN_LI_CANNOTATE(\
        release_capability(__VA_ARGS__),\
        unlock_function(__VA_ARGS__) )
#endif

/* TSA shared acquire */
#ifndef TSA_SH_AQ
   #define TSA_SH_AQ(...) TTN_CANNOTATE(\
        acquire_shared_capability(__VA_ARGS__),\
        shared_lock_function(__VA_ARGS__) )
#endif

/* LIB INLINE TSA shared acquire */
#ifndef LI_TSA_SH_AQ
   #define LI_TSA_SH_AQ(...) TTN_LI_CANNOTATE(\
        acquire_shared_capability(__VA_ARGS__),\
        shared_lock_function(__VA_ARGS__) )
#endif

/* TSA shared release */
#ifndef TSA_SH_RE
   #define TSA_SH_RE(...) TTN_CANNOTATE(\
        release_shared_capability(__VA_ARGS__),\
        unlock_function(__VA_ARGS__) )
#endif

/* LIB INLINE TSA shared release */
#ifndef LI_TSA_SH_RE
   #define LI_TSA_SH_RE(...) TTN_LI_CANNOTATE(\
        release_shared_capability(__VA_ARGS__),\
        unlock_function(__VA_ARGS__) )
#endif

/* TSA try acquire */
#ifndef TSA_TRY_AQ
   #define TSA_TRY_AQ(...) TTN_CANNOTATE(\
         try_acquire_capability(__VA_ARGS__),\
         exclusive_trylock_function(__VA_ARGS__) )
#endif

/* TSA try shared acquire */
#ifndef TSA_TRY_SH_AQ
   #define TSA_TRY_SH_AQ(...) TTN_CANNOTATE(\
            try_acquire_shared_capability(__VA_ARGS__),\
            shared_trylock_function(__VA_ARGS__) )
#endif

/* TSA try release */
#ifndef TSA_TRY_RE_RE
   #define TSA_TRY_RE(...) TSA_RE( __VA_ARGS__ )
#endif
/*******************************************************************************/

/* 
 * TSA compatibility wrappers for FreeBSD 10
 * on FreeBSD 11 these wrappers aren't necessary 
 * as the pthread locking methods are already properly annotated
 */

/**
 * @fn tsa_lock
 * @abstract tsa compatible wrapper for the pthread_mutex_lock
 * @param mtx[in]: pthread_mutex_t *
 * @return void
 */
TXATR void tsa_lock( pthread_mutex_t * mtx  ) TSA_AQ( *mtx );

/**
 * @fn tsa_try_lock
 * @abstract tsa compatible wrapper for the pthread_mutex_trylock
 * @param mtx[in]: pthread_mutex_t *
 * @return bool
 */
TXATR bool tsa_try_lock( pthread_mutex_t * mtx  ) TSA_TRY_AQ( true, *mtx );

/**
 * @fn tsa_unlock
 * @abstract tsa compatible wrapper for the pthread_mutex_unlock
 * @param mtx[in]: pthread_mutex_t *
 * @return void
 */
TXATR void tsa_unlock( pthread_mutex_t * mtx  ) TSA_RE( *mtx );

/**
 * @fn tsa_try_unlock
 * @abstract tsa compatible wrapper for the pthread_mutex_unlock
 * @note try to unlock an exclusive lock
 * @param mtx[in]: pthread_mutex_t *
 * @return bool
 */
TXATR bool tsa_try_unlock( pthread_mutex_t * mtx  ) TSA_TRY_RE( *mtx );

/**
 * @fn tsa_rd_lock
 * @abstract tsa compatible wrapper for the pthread_rwlock_rdlock
 * @note acquire shared read lock on a read-write lock
 * @param mtx[in]: pthread_rwlock_t *
 * @return void
 */
TXATR void tsa_rd_lock( pthread_rwlock_t  * mtx  ) TSA_SH_AQ( *mtx );

/**
 * @fn tsa_try_rd_lock
 * @abstract tsa compatible wrapper for the pthread_rwlock_tryrdlock
 * @note acquire shared read lock on a read-write lock
 * @param mtx[in]: pthread_rwlock_t *
 * @return bool
 */
TXATR bool tsa_try_rd_lock( pthread_rwlock_t * mtx  ) TSA_TRY_SH_AQ( true, *mtx );

/**
 * @fn tsa_rd_unlock
 * @abstract tsa compatible wrapper for the pthread_rwlock_unlock
 * @note unlock shared read lock
 * @param mtx[in]: pthread_rwlock_t *
 * @return void
 */
TXATR void tsa_rd_unlock( pthread_rwlock_t * mtx  ) TSA_RE_ALL(*mtx);

/**
 * @fn tsa_wr_lock
 * @abstract tsa compatible wrapper for the pthread_rwlock_wrlock
 * @note acquire an exclusive write lock on a read-write lock
 * @param mtx[in]: pthread_mutex_t *
 * @return void
 */
TXATR void tsa_wr_lock( pthread_rwlock_t * mtx  ) TSA_AQ( *mtx );

/**
 * @fn tsa_try_wr_lock
 * @abstract tsa compatible wrapper for the pthread_rwlock_trywrlock
 * @note try to acquire an exclusive write lock on a read-write lock
 * @param mtx[in]: pthread_mutex_t *
 * @return bool
 */
TXATR bool tsa_try_wr_lock( pthread_rwlock_t * mtx  ) TSA_TRY_AQ( true, *mtx );

/**
 * @fn tsa_wr_unlock
 * @abstract tsa compatible wrapper for the pthread_rwlock_unlock
 * @note unlock an exclusive write lock
 * @param mtx[in]: pthread_mutex_t *
 * @return void
 */
TXATR void tsa_wr_unlock( pthread_rwlock_t * mtx  ) TSA_RE( *mtx );

#endif /* TTN_TSA */

/* vim: set ts=4 sw=4 et : */
