/*
 * $Id$
 */
#ifndef TITAN_EXTENSION_H
#define TITAN_EXTENSION_H

#ifdef __cplusplus
extern "C" {
#endif

#include <pthread.h>
#include <stdbool.h>
#include "global.h"

//---------------------------------------------------------------------
// Define and global.
//---------------------------------------------------------------------

typedef enum{
   ttn_ext_aud = 0x00,           //AUDIO_EXTENSIONS
   ttn_ext_vid = 0x01,           //VIDEO_EXTENSIONS
   ttn_ext_exe = 0x02,           //EXE_EXTENSIONS
   ttn_ext_img = 0x03,           //IMAGE_EXTENSIONS
   ttn_ext_txt = 0x04,           //TEXT_EXTENSIONS
   ttn_ext_arc = 0x05,           //ARCHIVE_EXTENSIONS
   ttn_ext_usr = 0x06,           //USER_EXTENSIONS
   ttn_ext_max = ttn_ext_usr+1,  //MAX_CATEGORIES
   ttn_ext_min = ttn_ext_aud,    //MIN_CATEGORIES
}t_ttn_ext_categories;


//---------------------------------------------------------------------
// Function.
//---------------------------------------------------------------------
extern pthread_rwlock_t sFileExtensionLock;

TSA_CAP_SH_TR_RQ(sFileExtensionLock)
const char * fileExtensionBlocked(const char*, const size_t,const t_ttn_ext_categories,const bool);

TSA_CAP_TR_RQ(sFileExtensionLock)
bool fileExtensionAdd(const t_ttn_ext_categories, const char* );

TSA_CAP_TR_RQ(sFileExtensionLock)
bool fileExtensionsLoad(const t_ttn_ext_categories, const char * const, const char * const);

TSA_CAP_SH_TR_RQ(sFileExtensionLock)
void fileExtensionPrintAll(void);

TSA_CAP_TR_RQ(sFileExtensionLock)
void fileExtensionsClear(const t_ttn_ext_categories);

LI_TSA_AQ(sFileExtensionLock)
void file_ext_wr_lock(void)
{
   tsa_wr_lock(&sFileExtensionLock);
}

LI_TSA_RE(sFileExtensionLock)
void file_ext_wr_unlock(void)
{
   tsa_wr_unlock(&sFileExtensionLock);
}

LI_TSA_SH_AQ(sFileExtensionLock)
void file_ext_rd_lock(void) 
{
   tsa_rd_lock(&sFileExtensionLock);
}

LI_TSA_SH_RE(sFileExtensionLock)
void file_ext_rd_unlock(void) 
{
   tsa_rd_unlock(&sFileExtensionLock);
}

#ifdef __cplusplus
}
#endif

#endif /* TITAN_EXTENSION_H */
