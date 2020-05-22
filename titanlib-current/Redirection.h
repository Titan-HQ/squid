/*
 * $Id$
 */
#ifndef TITAN_REDIRECTION_H
#define TITAN_REDIRECTION_H

#include "global.h"
#include "edgepq.h"

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------
// Define and global.
//---------------------------------------------------------------------
#define REDIRECTIONS_LEN 4096

typedef struct
{

   union /* anonymous union */
   {
      /* public */
      const char*       cpath;

      /* private used only by the path_clean */
      char*             _path;

   };

   const uint_fast64_t  csize;

} redirect_path_t;


typedef struct
{
   redirect_path_t      source;

   redirect_path_t      destination;

} Redirection;


typedef struct
{

   Redirection          arr[REDIRECTIONS_LEN];

   uint_fast64_t        length;

} Redirections;

//---------------------------------------------------------------------
// Function.
//---------------------------------------------------------------------
/**
 * redirections_get_redi_host
 * @param host       : request
 * @param hsize      : request size
 * @param redi_host  : redirection
 * @param rh_sz      : redi_host raw size
 */
bool redirections_get_redi_host( const char * const, const uint_fast64_t, char * const, const uint_fast64_t );
bool redirections_reload( PGconn* const );


#ifdef TTN_ATESTS

Redirections * redirections_instance(void);
void redirections_clear(void);
bool redirections_add( const char* const, const char * const );
Redirection * redirections_find( const char * const, const uint_fast64_t );

#endif

#ifdef __cplusplus
}
#endif

#endif /* TITAN_REDIRECTION_H */
