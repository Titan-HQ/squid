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

#include <assert.h>
#include "Redirection.h"
#include "edgelib.h"
#include "sqls.h"

tx_static_assert_type(  ( ( Redirections*){0} )->arr[0], 
                        Redirection,
                        "Unable to compile, the base type of the Redirections->arr differs"\
                        " from the expected (Redirection)\n"                                    );

static const uint_fast64_t RDS_LIMIT = (  sizeof( ( (Redirections*){0} )->arr )     /

                                          sizeof( ( (Redirections*){0} )->arr[0] )     );

static Redirections g_redirections = {};

static pthread_mutex_t g_rd_lock = PTHREAD_MUTEX_INITIALIZER;

//---------------------------------------------------------------------
// Redirections.
//---------------------------------------------------------------------

static void path_clean_( redirect_path_t * const restrict rdpath )
{
   if ( rdpath ) {

      tx_safe_free( rdpath->_path );

      zm( rdpath, sizeof( redirect_path_t ) );
   }
}

static void redirection_clear_( Redirection * const restrict rd )
{

   if ( rd ) {

      path_clean_( &rd->source );

      path_clean_( &rd->destination );
   }
}

static void redirections_clear_(void)
{

   Redirections* const rds = &g_redirections;

   if ( rds ) {

      const uint_fast64_t max = {   rds->length < RDS_LIMIT ?

                                    rds->length             :

                                    RDS_LIMIT                  };

      for ( uint_fast64_t i_ = 0; i_ < max ; ++i_ ) {

         redirection_clear_( &rds->arr[i_] );
      }

      rds->length = 0;
   }
}

static uint_fast64_t get_host_sz_from_url_(  const char* const restrict url,
                                             uint_fast64_t * const restrict  out_pos ) 
{

   if ( url ) {

      const uint_fast64_t o_l_ = strlen( url );

      if ( o_l_ ) {

         *out_pos = 0;

         const char * p_ = strnstr( url, "://", o_l_ );

         ptrdiff_t pdsz = 0;

         if ( p_ && ptr_diff (p_, url, &pdsz ) ) {

            pdsz += 3;
         }

         uint_fast64_t l_ = o_l_ - (uint_fast64_t)pdsz;

         if ( !l_ || l_ > o_l_ ) {

            l_ = o_l_;
         }

         if ( ! ( p_ = strnstr( url + pdsz, "/", l_ ) ) ) {

            *out_pos = (uint_fast64_t)pdsz;

            return l_;
         }

         *out_pos = (uint_fast64_t)pdsz;

         if ( ptr_diff( p_, ( url + (size_t)pdsz ), &pdsz ) ) {

            return (uint_fast64_t)pdsz;
         }
      }
   } /* main if */

   return 0;
}

static bool dup_path_(  redirect_path_t * const restrict rdpath,
                        const char * const restrict input         )
{

   if ( rdpath && input && *input ) {

      path_clean_( rdpath );

      uint_fast64_t pos = 0;

      const uint_fast64_t hlen = get_host_sz_from_url_( input ,&pos );

      if ( hlen && pos < hlen ) {

         uint_fast64_t len = hlen;

         redirect_path_t dup = { .cpath = str_dup_ex( input + pos, &len ),
                                 .csize = hlen                             };

         if ( dup.cpath && len == hlen ) {

            /* 16 bytes */
            tx_safe_memcpy( rdpath, &dup, sizeof(redirect_path_t) );

            return true;
         }

         path_clean_( &dup );
      }
   }

   return false;
}

/* find by src */
static Redirection * find_(   const char * const restrict host,
                              const uint_fast64_t hsize           )
{

   if ( host && *host && hsize ) {

      Redirections* const rds = &g_redirections;

      const uint_fast64_t max = {   rds->length < RDS_LIMIT ?

                                    rds->length             :

                                    RDS_LIMIT                  };

      for ( uint_fast64_t i_ = 0; i_ < max; ++i_ ) {

         Redirection * const rd = &rds->arr[i_];

         if (  (  hsize == rd->source.csize && rd->source.cpath )                &&

               (  rd->destination.csize && rd->destination.cpath )               &&

               ! strncasecmp( host, rd->source.cpath, rd->source.csize )         &&

               strncasecmp( host, rd->destination.cpath, rd->destination.csize )    ) {

            return rd;
         }
      }/* loop */
   }

   return NULL;
}

static bool load_(   const char* const restrict src,
                     const char* const restrict dst   )
{

   if (  ( src && dst && src != dst )        &&

         ( *src && *dst )                    && 

         /* slow */
         strncmp( src, dst, strlen( src ) )     ) {

      Redirection rd_new = {};

      if ( dup_path_( &rd_new.source, src ) ) {

         /* don't duplicate - slow */
         if (  ! find_( rd_new.source.cpath, rd_new.source.csize )   &&

               dup_path_( &rd_new.destination, dst )                    ) {

            Redirections* const rds = &g_redirections;

             /* 32 bytes */
            tx_safe_memcpy( &rds->arr[rds->length++] , &rd_new, sizeof( Redirection ) );

            return true;
         }

         redirection_clear_( &rd_new );
      }
   }

   return false;

}

/////////////////////////////////////////////////////////////////////////////////////////////////

bool redirections_get_redi_host( const char * const restrict host,
                                 const uint_fast64_t hsize,
                                 char * const restrict rd_host_out, 
                                 const uint_fast64_t rd_host_out_sz  )
{

   if ( host && *host && hsize && rd_host_out && rd_host_out_sz ) {

      bool found = false;

      /* move out side */
      tsa_lock(&g_rd_lock);

      const Redirection * const rd = find_( host, hsize );

      if ( rd ) {

         /* continue only if the rd_host_out can accommodate the destination (see strlcpy ) */
         if ( rd->destination.csize < ( rd_host_out_sz - 1 ) ){

            strlcpy( rd_host_out, rd->destination.cpath, rd_host_out_sz );

            found = true;
         } 
         else {

               //log the error ?
         }
      }

      tsa_unlock( &g_rd_lock);

      return found;
   }

   return false;
}

bool redirections_reload( PGconn* const restrict db )
{

   bool success = false;

   PGresult* const rset = pq_get_rset(db, TITAXLIB_QS_T_REDIRECTIONS);

   if ( rset ) {

      /* move out side */
      tsa_lock(&g_rd_lock);

      redirections_clear_();

      uint_fast64_t max = txpq_row_count( rset ); 

      if ( max > RDS_LIMIT ) {

         max = RDS_LIMIT;
      }

      for ( uint_fast64_t i_ = 0; i_ < max ; ++i_ ) {

         if ( load_( txpq_cv_str(rset, i_, 0),
                     txpq_cv_str(rset, i_, 1)   )  ) {


            continue;
         }

      } /* for */

      success = ( !max || g_redirections.length > 0);

      tsa_unlock(&g_rd_lock);

      txpq_reset( rset );
   } /* main if */

   return success;
}

/////////////////////////////////////////////////////////////////////////////////////////////////

#ifdef TTN_ATESTS

Redirections * redirections_instance(void)
{
   return &g_redirections;
}

void redirections_clear(void)
{

   redirections_clear_();
}

bool redirections_add( const char* const src, const char * const dst ) 
{

   return load_( src, dst );
}

Redirection * redirections_find( const char * const restrict host, const uint_fast64_t hsize )
{
   return find_(host, hsize);
}

#endif

