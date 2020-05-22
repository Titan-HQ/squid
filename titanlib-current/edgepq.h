/*
 * $Id$
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <libpq-fe.h>
#include "global.h"

/**
 * @abstract set of db wrappers that provide extra checks and validation
 * also all these methods are fully mocked during the autotest 
 * 
 */
#ifndef EDGEPQ_H
#define EDGEPQ_H

#ifndef DEF_DB_CON_TTL
   #define DEF_DB_CON_TTL 8
#endif

/**
 * @name pq_conn_close
 * @param db[in] pg connection 
 * @return t/f
 */
TXATR bool pq_conn_close(PGconn*const);
/**
 * @name pq_conn_isactive
 * @abstract passively tests if db connection is active 
 * @param db[in] pg connection 
 * @return t/f
 */
TXATR bool pq_conn_isactive(const PGconn* const);
/**
 * @name pq_conn
 * @abstract open new pg db connection 
 * @param cinfo[in] connection string
 * @return new connection or null on error
 */
TXATR PGconn* pq_conn(const char*const);
/**
 * @name pq_is_alive
 * @abstract actively tests the db connection 
 * @param db[in] pg connection 
 * @return t/f
 */
TXATR bool pq_is_alive(PGconn*const);
/**
 * @name pq_conn_reset
 * @abstract reset db connection 
 * @param db[in] pg connection 
 * @return t/f
 */
TXATR bool pq_conn_reset(PGconn*const);
/**
 * @name pq_get_rset
 * @abstract executes the sql query 
 * @param db[in]
 * @param query[in]
 * @return new record set or null on error
 */
TXATR PGresult* pq_get_rset(PGconn* const , const char* const );
/**
 * @name pq_get_rset_with_params
 * @abstract executes the sql query with the ability to pass parameters separately from the SQL
 * @param db[in]
 * @param query[in]
 * @param pcount[in]
 * @param params[in]
 * @return new record set or null on error 
 */
TXATR PGresult* pq_get_rset_with_params(PGconn* const, const char* const,const int,const char *const *);
/**
 * @name pq_get_rset_no_error
 * @abstract it is identical as pq_get_rset except there is no error checking
 * @param db[in]
 * @param query[in]
 * @return new record set or null
 */
TXATR PGresult* pq_get_rset_no_error(PGconn* const, const char* const);
/**
 * @name pq_do
 * @abstract executes sql statement
 * @param db[in]
 * @param statement[in]
 * @return t/f
 */
TXATR bool pq_do(PGconn* const , const char* const );
/**
 * @name pq_get_int
 * @abstract a wrapper, it runs a query and returns value as signed integer
 * @param db[in]
 * @param query[in]
 * @return value of the zero field form the zero row as signed integer
 */
TXATR int pq_get_int(PGconn* const , const char* const );
/**
 * @name pq_get_ulong
 * @abstract a wrapper, it runs a query and returns value as unsigned long 
 * @param db[in]
 * @param query[in]
 * @return value of the zero field form the zero row as unsigned long
 */
TXATR unsigned long pq_get_ulong(PGconn* const, const char* const);
/**
 * @name txpq_cv_str
 * @abstract get a value of the N-th field from the N-th row as cstring
 * @note all rows and fields starts from zero
 * @note it also tests a field for a null value if so then return NULL
 * @param rset[in] record set 
 * @param rno[in] record number
 * @param fno[in] field number
 * @return value as cstring or NULL (NULL value doesn't mean error)
 */
TXATR char * txpq_cv_str(const PGresult * const,const  size_t, const  size_t);
/**
 * @name txpq_cv_bool
 * @abstract get a value of the N-th field from the N-th row as bool
 * @note all rows and fields starts from zero
 * @note it also tests a field for a null value if so then return false
 * @param rset[in] record set 
 * @param rno[in] record number
 * @param fno[in] field number
 * @return value as bool 
 */
TXATR bool txpq_cv_bool(const PGresult * const,const size_t, const size_t);
/**
 * @name txpq_cv_int
 * @abstract get a value of the N-th field from the N-th row as int
 * @note all rows and fields starts from zero
 * @note it also tests a field for a null value if so then return zero
 * @param rset[in] record set 
 * @param rno[in] record number
 * @param fno[in] field number
 * @return value as int 
 */
TXATR int txpq_cv_int(const PGresult * const ,const size_t,const  size_t);
/**
 * @name txpq_cv_uint
 * @abstract get a value of the N-th field from the N-th row as unsigned int
 * @note all rows and fields starts from zero
 * @note it also tests a field for a null value if so then return zero
 * @param rset[in] record set 
 * @param rno[in] record number
 * @param fno[in] field number
 * @return value as unsigned int 
 */
TXATR unsigned int txpq_cv_uint(const PGresult * const,const size_t,const  size_t);
/**
 * @name txpq_cv_long
 * @abstract get a value of the N-th field from the N-th row as long
 * @note all rows and fields starts from zero
 * @note it also tests a field for a null value if so then return zero
 * @param rset[in] record set 
 * @param rno[in] record number
 * @param fno[in] field number
 * @return value as long
 */
TXATR long txpq_cv_long(const PGresult * const,const  size_t, const  size_t);
/**
 * @name txpq_cv_ulong
 * @abstract get a value of the N-th field from the N-th row as unsigned long
 * @note all rows and fields starts from zero
 * @note it also tests a field for a null value if so then return zero
 * @param rset[in] record set 
 * @param rno[in] record number
 * @param fno[in] field number
 * @return value as unsigned long
 */
TXATR unsigned long txpq_cv_ulong(const PGresult * const,const  size_t, const  size_t);
/**
 * @name txpq_cv_longlong
 * @abstract get a value of the N-th field from the N-th row as long long
 * @note all rows and fields starts from zero
 * @note it also tests a field for a null value if so then return zero
 * @param rset[in] record set 
 * @param rno[in] record number
 * @param fno[in] field number
 * @return value as long long
 */
TXATR long long  txpq_cv_longlong(const PGresult *const,const  size_t, const  size_t);
/**
 * @name txpq_row_count
 * @abstract get record count
 * @param rset[in]
 * @return count or 0 on error
 */
TXATR size_t txpq_row_count(PGresult *const);
/**
 * @name txpq_is_row_in_rset
 * @abstract checks if given recno is in the recordset 
 * @param rset[in]
 * @param recno[in]
 * @return true/false
 */
TXATR bool txpq_is_row_in_rset( PGresult *const, const size_t );
/**
 * @name txpq_reset
 * @abstract cleanup/release the record set allocated by any of the method from pq_get_rset* family
 * @param rset[in]
 */
TXATR void txpq_reset(PGresult *const);
/**
 * @name txpq_is_null
 * @abstract checks if given a field at recno is in null 
 * @param rset[in]
 * @param recno[in]
 * @param fno[in]
 * @return true/false
 */
TXATR bool txpq_is_null( const PGresult *const, const size_t, const  size_t );

typedef PGconn* (*db_connect_t)(void);

/**
 * @name check_raw_dbconn
 * @abstract It will try to establish a valid db connection or check validity of existing one 
 * - if db_conn is null then it will try to establish a new connection
 * - if db_conn is faulty then it will reset it or close and reconnect
 * - if within the given amount of tries a connection could not be successfully 
 * established it will return false and the value stored in the db_con should be discarded
 * @warning not thread-safe: 
 * - since the PGconn is not thread-safe itself
 * - the reconnect function pointer might point to the not thread-safe function 
 * @param db_conn[in|out]  connection handler
 * @param max_tries[in]    how many times to try 
 * @param reconnect[in]    a function pointer to a method that actually connects to the db
 * @return true or false
 */
TXATR bool check_raw_dbconn(PGconn**, const size_t, db_connect_t);

/**
 * @nme txpq_escape_literal
 * @abstract CAPI Escape literal 
 * @param conn[in]
 * @param in_str[in]
 * @param in_str_sz[in]
 * @return pointer to the newly allocated memory buffer with escaped string or null 
 * @note use txpq_free to release it
 */
TXATR char * txpq_escape_literal(   PGconn*, 
                                    const char *,
                                    const size_t   ); 

TXATR void txpq_free(char *);


/**
 * @name txpq_is_field_null
 * @abstract checks if given field is null 
 * @param rs[in] : record set
 * @param rn[in] : record number/index
 * @param fn[in] : field number/index
 * @return true/false
 */
TXATR bool txpq_is_field_null(   const PGresult * const ,
                                 const  size_t, 
                                 const  size_t              );

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */

TXATR unsigned int get_PGresult_active_instances(void);
#endif

/* vim: set ts=4 sw=4 et : */

