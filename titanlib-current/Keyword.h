/*
 * $Id$
 */
#ifndef TITAN_KEYWORD_H
#define TITAN_KEYWORD_H
#include "global.h"
//---------------------------------------------------------------------
// Define and global.
//---------------------------------------------------------------------

//---------------------------------------------------------------------
// Function.
//---------------------------------------------------------------------
/* Obtain a lock the keywords table preventing any readers
 * This MUST be called prior to rebuilding the table using keywordsDestroy() &
 * keywordAdd() to prevent scoreDocument() using a table that is not in a
 * usuable state and/or only contains a subset of the keywords.
 */

/* Destroy the keywords table */
TXATR void keywordsDestroy(void);

/* Add a word to the keywords table */
TXATR int keywordAdd(const char *const,const size_t);

/* Score a document against the keyword table
 * This function will block if a reader lock obtained in keywordsLock() is
 * currently active, until it is release by keywordsUnlock()
 */
TXATR ssize_t scoreDocument(const char* const, const size_t, int* const, char* const,const size_t);

extern pthread_rwlock_t keywordctreeLock;

LI_TSA_AQ(keywordctreeLock)
void KEYWORDSLOCK(void)
{
   tsa_wr_lock(&keywordctreeLock);
}

LI_TSA_RE(keywordctreeLock)
void KEYWORDSUNLOCK(void)
{
   tsa_wr_unlock(&keywordctreeLock);
}

#endif /* TITAN_KEYWORD_H */
