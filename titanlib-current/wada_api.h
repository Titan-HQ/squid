/* 
 * $Id$ 
 * Copyright (c) 2014, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 * The software contained herein is proprietary to and embodies the
 * confidential technology of Copperfasten Technologies, Teoranta.
 * Possession, use, duplication or dissemination of the software and
 * media is authorized only pursuant to a valid written license from
 * Copperfasten Technologies, Teoranta.
 */

#ifndef WADA_API_H
#define	WADA_API_H

/* DISABLED NOW / NOT USED  */

#include "global.h"

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef UPN_MAX_SZ
   #define UPN_MAX_SZ                  255
#endif

#ifndef WADA_DEFAULT_CACHE_FILE
   #define WADA_DEFAULT_CACHE_FILE     "wada_cache.wad"
#endif

#ifndef WADA_DEFAULT_USERID_FILE
   #define WADA_DEFAULT_USERID_FILE    "userid.wad"
#endif 

#ifdef TTN_ATESTS
   #define WADA_CSTR                   const char * 
#else    
   #define WADA_CSTR                   const char * const 
#endif 

/**
 * @abstract alias for: const char * restrict
 */
typedef const char * cstr_t; 
/**
 * @abstract alias for: const char * const restrict
 */
typedef const char * const cstrc_t; 
/**
 * @abstract alias for: cstrc_t
 */
typedef cstrc_t file_t;
/**
 * @abstract alias for: cstrc_t
 */
typedef cstrc_t strguid_t;
/**
 * @abstract alias for: cstrc_t
 */
typedef cstrc_t line_t;
/**
 * @abstract alias for: line_t
 */
typedef line_t lines_t;
/**
 * @abstract alias for: const size_t
 */
typedef const size_t csize_t;
/**
 * @abstract alias for: const bool
 */
typedef const bool cbool_t;
/**
 * @abstract alias for: const uint32_t
 */
typedef const uint32_t cuint32_t;


/**
 * @abstract alias of: const lp_cfg_t * const restrict
 */
//typedef const lp_cfg_t * const lp_cfg_arg_t;


/**
 * @abstract wada configuration 
 */
typedef struct
{
    /* file name to file with the users data */
    WADA_CSTR                           users_file;
    /* file name to file with the ips data */
    WADA_CSTR                           wada_cache_file;
    /* option keep existing entries (to ignore flush) */
    bool                          keep_existing_entries;

} wada_cfg_t;

/**
 * @abstract alias of: const wada_cfg_t * const 
 */
typedef const wada_cfg_t * const wada_cfg_arg_t;

/**
 * @abstract user details
 */
typedef struct
{
    /* wtc id */
    size_t                              wtcid;

} user_details_t;

/**
 * @abstract alias of: user_details_t * const restrict 
 */
typedef user_details_t * const  user_details_arg_t;

/**
 * @abstract wada api
 */
typedef struct
{
    /* reload data from files */
    bool                                (*reload_from_files)( void );
    /* reload data from given buffer */
    bool                                (*reload_from_http)( lines_t , csize_t );
    /* find user by ip */
    bool                                (*user_find_by_ip)( c_raw_ipaddr_t , user_details_arg_t );
    /* save current state to the file */
    bool                                (*save_to_file)( cbool_t );
    /* configure current instance */
    bool                                (*configure)( wada_cfg_arg_t );
    /* count wada locations */
    size_t                              (*count)( void );

#ifdef TTN_ATESTS
    bool                                (*reload_users_from_file_4test)( file_t );
    bool                                (*reload_users_from_buffer_4test)( lines_t , csize_t );
    bool                                (*reload_ips_from_file_4test)( file_t );
    bool                                (*save_to_file_4test)( file_t, cbool_t);
    size_t                              (*raw_count_4test)( void );
    void                                (*clear_config_4test )( void );
#endif

} wada_api_t;


extern wada_api_t * gtape_wada_api(void);


#ifdef TTN_ATESTS

typedef struct
{
    struct 
    {
        size_t      add;
        size_t      del;
        size_t      flush;
        size_t      internal_ctx;
        size_t      lines;

    } ips;

    struct 
    {
        size_t      lines;
        ssize_t     left;

    } read; 

    struct 
    {
        size_t      add;
        size_t      del;
        size_t      flush;
        size_t      internal_ctx;
        size_t      lines;

    } user;

    struct
    {
        size_t      lines;
        size_t      bytes;
        size_t      ctx;

    } save;

    size_t         line_proc;
    ssize_t        read_file;
    void           (*cls)(void);

} stats_4test_t;

extern stats_4test_t s4test;

#endif /* TTN_ATESTS */


#ifdef	__cplusplus
}
#endif

#endif	/* WADA_API_H */

/* vim: set ts=4 sw=4 et : */

