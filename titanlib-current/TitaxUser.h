/*
 * $Id$
 *
 * Copyright (c) 2005-2014, Copperfasten Technologies, Teoranta.  All rights
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
#ifndef TITAX_USER_H
#define TITAX_USER_H
#include <assert.h>
#include "global.h"
#include "edgelib.h"
#include "txip.h"

#ifdef __cplusplus
extern "C" {
#endif


//---------------------------------------------------------------------
// Define and global.
//---------------------------------------------------------------------
//inc the size of the MAX_TITAX_USER_NAME it was too short (63)
tx_static_assert_true(  MAX_TITAX_USER_NAME>=TITAX_ANON_DEFAULT_USER_NAME_SZ,
                        "Unable to compile MAX_TITAX_USER_NAME is too short"  );

typedef struct
{
   policy_id_t    ids[MAX_TITAX_GROUP_POLICY];

   size_t         length;

} ids_t;


typedef struct 
{
   ids_t groups;

   ids_t policies;

   bool  inherited;

} policies_t;


typedef struct TXUI
{
   char                 name[MAX_TITAX_USER_NAME + 1];
   char                 fullname[MAX_TITAX_USER_FULLNAME + 1];
   char                 md5val[MD5BASE64_MAX_SIZE];
   char                 lic_no[MAX_TITAX_USER_LIC_MAX+1];
   policies_t           policy_info;
   t_uuid               uuid;
   user_id_t            parent_id;
   user_id_t            id;
   size_t               TXTokens_Count; ///T/F and count of tokens per policy (because in  ISP version of DT admin=user=policy=group)   
   size_t               downloaded_byte;
   bool                 anonymous:1;
   bool                 default_user:1;
   bool                 invalid_user:1;
   bool                 parent_valid:1;
} TitaxUser;

typedef struct 
{
   enum
   {
      ult_plain=0x00,        //homogenous structure
      ult_multidomain=0x02,  //homogenous structure
      ult_hybrid=0x04,       //heterogeneous structure

   } type;

} userslist_t;

typedef struct{
   size_t                  reload_ctx;
   VoidMap*                md5val_map;
   VoidMap*                txtoken_map;
} TitaxUserDic;

typedef struct{
   user_id_t         user_id;
   size_t            str_sz;
   char              str[MAX_CK_STR_SZ+1];
   char              hash[MAX_CK_HASH_SZ+8];
} TitaxCKey;

typedef struct {
   char buf[16];
}t_int_id_buf;


#ifdef __cplusplus
}
#endif

extern const t_int_id_buf int_id_buf_clear;

//---------------------------------------------------------------------
// Functions.
//---------------------------------------------------------------------
TXATR bool titax_user_dic_free_instance(void);
TXATR TitaxCKey* titax_user_dic_add_token(const StringList * const);
TXATR bool titax_user_free(TitaxUser* const);
TXATR void titax_user_dic_sort(void);
TXATR TitaxCKey* TitaxCKey_new(const char*const , const char *const , size_t );
TXATR TitaxCKey* TitaxCKey_find_by_tokenval(const char*const );
TXATR bool TitaxCKey_free(TitaxCKey * const);
TXATR void token_map_add_elem(const char* const, TitaxCKey* const);
TXATR void token_map_clear(void);
TXATR bool titax_user_get_name_by_md5(const char*, char*, size_t);

#ifdef TTN_ATESTS
   TitaxUser* titax_user_dic_find_by_md5val_NL_4tests(const char* const);
#endif

#endif /* TITAX_USER_H */
