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


#ifndef TITAN_CATEGORY_H
#define TITAN_CATEGORY_H

#include "global.h"


#ifdef __cplusplus
extern "C" {
#endif

//---------------------------------------------------------------------
// Define and global.
//---------------------------------------------------------------------

typedef struct{
   char name[MAX_CATEGORY_NAME_LEN + 1];
}CATEGORY;


/* Obtain a read lock whilst using this */
char* categoryGetName(const t_category);

/* Obtain a write lock whilst using these */
void categoryClear(const t_category);
bool categorySetName(const t_category, const char *const);

/* Obtains a read lock internally */

bool createCategoryString(const unsigned long long,char *const,const size_t);
CATEGORY * getCatTable(void);
CATEGORY * getcustomCatTable(void);

char* custom_categoryGetName(const t_category);
void custom_categoryClear(const t_category);
bool custom_categorySetName(const t_category, const char *const);
bool custom_createCategoryString(const unsigned long long,char *const,const size_t);

extern pthread_rwlock_t sCatLock;
extern pthread_rwlock_t custom_sCatLock;

LI_TSA_AQ(sCatLock)
void categoryLockWrite(void)
{
   tsa_wr_lock(&sCatLock);
}

LI_TSA_RE(sCatLock)
void categoryUnlock(void)
{
   tsa_wr_unlock(&sCatLock);
}

LI_TSA_AQ(custom_sCatLock)
void custom_categoryLockWrite(void)
{
   tsa_wr_lock(&custom_sCatLock);
}

LI_TSA_RE(custom_sCatLock)
void custom_categoryUnlock(void)
{
   tsa_wr_unlock(&custom_sCatLock);
}

#ifdef __cplusplus
}
#endif

#endif /* TITAN_CATEGORY_H */
