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
/*
- Author: jinyedge
- Comment:
   Library for multi-bytes keyword content filtering.
*/

#ifndef TITAN_MULKWMAP_H
#define TITAN_MULKWMAP_H

#include "edgelib.h"

#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------
// Define and global.
//---------------------------------------------------------------------
typedef struct{
   StringMap* map;
} MulKwMap;


#define BLOCKKEYWORD_MAX 512

//---------------------------------------------------------------------
// Function.
//---------------------------------------------------------------------
extern pthread_mutex_t g_mul_kw_lock;

MulKwMap* mul_kw_map_get_instance(void);
size_t mul_kw_map_size(void);
void mul_kw_map_add(char* const , const int);

TSA_CAP_TR_RQ(g_mul_kw_lock)
void mul_kw_map_clear(void);
void mul_kw_map_print_all(void);
size_t mul_kw_map_score_doc(const char* const, int* const, char * const,const size_t);

LI_TSA_AQ(g_mul_kw_lock)
void mul_kw_map_lock(void)
{
   tsa_lock(&g_mul_kw_lock);
}

LI_TSA_RE(g_mul_kw_lock)
void mul_kw_map_unlock(void)
{
   tsa_unlock(&g_mul_kw_lock);
}

#ifdef __cplusplus
};
#endif

#endif /* TITAN_MULKWMAP_H */
