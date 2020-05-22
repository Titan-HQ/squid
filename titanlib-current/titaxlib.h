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
 * ABSTRACT
 */
#ifndef TITAXLIB_H
#define TITAXLIB_H
#include <sys/types.h>
#include <stdio.h>
#include <string.h>
#include <libpq-fe.h>

#include "global.h"
#include "TitaxUser.h"
#include "Group.h"

#ifdef TTN_ATESTS 

   #ifdef __cplusplus
   extern "C" {
   #endif

      typedef enum{
         udbtt_normal=0x00,
         udbtt_error_connect=0x01,
         udbtt_error_send=0x02,
         udbtt_error_recv=0x04,
      }t_udb_test_type;

      typedef struct{
         t_udb_test_type   type;
         char * buffer_with_reply;
       //  char * buffer_with_request;
      }t_udb_test_call;

      TXATR t_udb_test_call urldb_test_;

      #include "edgelib.h"
      /**
       * @name urldb_scan_data_4tests
       * @note see urldb_scan_data_
       * 
       */
      bool urldb_scan_data_4tests(char * const,const size_t, unsigned long long * const, unsigned long long * const);
      bool titax_data_update_4tests(PGconn* const,StringMap* const,const bool );
      bool is_policy_updated_4tests(StringMap* const, StringMap* const);
      bool is_updated_table_4tests(StringMap* const, StringMap* const,const char* const);
      bool get_update_times_4tests(PGconn* const, StringMap* const);
      bool titax_init_all_4tests(PGconn* const);
      void titax_cleanup_all_4test(void);
   #ifdef __cplusplus
   }
   #endif

#endif

//---------------------------------------------------------------------
// Function.
//---------------------------------------------------------------------
TXATR void titax_init_all(const bool);
TXATR void titax_init_all_icap(void);
/**
 * @name urldb_send_request
 * @abstract sends requests to the urlsvr, it is responsible for connection error handling 
 * @note this method is blocking 
 * @param call[in/out] ptr to arg structure
 * @return t/f
 */

TXATR t_urldb_rc urldb_send_request(urldb_call_t * const);
TXATR size_t get_titax_backoff_limit(void);
TXATR void set_titax_backoff_limit(const size_t);
TXATR int logger_open(void);
TXATR int logger_writen(const void* vptr,const  size_t n);
TXATR void logger_close(void);
TXATR void ttn_set_shutdown_now(void);
TXATR bool ttn_get_shutdown_now(void);
TXATR PGconn* db_config_connect(void);
TXATR PGconn* db_reporting_connect(void);
/**
 * @name titax_load_groups
 * @abstract re/load groups and policies 
 * @warning Not Thread-Safe
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE or pwrp_scoped_mx_t
 * @param dbconn 
 */
TSA_CAP_TR_RQ(sGroupMutex)
TXATR void titax_load_groups(PGconn* const);
TXATR void titax_load_user_dic(PGconn* const);
TXATR bool ttn_load_user( PGresult* const, const uint_fast64_t , TitaxUser * const );

#endif /* TITAXLIB_H */
