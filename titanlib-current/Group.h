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

#ifndef TITAN_GROUP_H
#define TITAN_GROUP_H

#include "global.h"

#ifdef __cplusplus
extern "C" {
#endif


#define MAX_GROUP_NAME        127
#define MAX_GROUP_DESCRIPTION 255
#define MAX_POLICY_NAME       255

// Define the SafeSearch engines bitmasks
#define SSE_ALL_ON   0xFFFFFFFF
#define SSE_GOOGLE   0x00000001
#define SSE_YAHOO    0x00000002
#define SSE_BING     0x00000004
#define SSE_YT       0x00000010

typedef enum
{
   SAFESEARCH_OFF = 0,
   SAFESEARCH_ON = 1,
   SAFESEARCH_CUSTOM = 2

} SAFESEARCH_SETTING;

typedef enum 
{
   IM_ALLOWED = 0,
   IM_BLOCKED = 1,
   IM_CUSTOM = 2

} IM_SETTING;

typedef enum
{
   P2P_ALLOWED = 0,
   P2P_BLOCKED = 1,
   P2P_BLOCKED_WITH_WHITELIST = 2

} P2P_SETTING;

typedef struct
{
   size_t         daysOfWeek; /* Day of week bitmask, Bit 0 (LSB) = Sunday */
   size_t         start;      /* Minutes since midnight */
   size_t         end;        /* Minutes since midnight */

} NONWORKING_PERIOD;

typedef struct
{
   size_t                  periodCount;
   NONWORKING_PERIOD *     periods;

} NONWORKING_HOURS;


//
// Extra flags added to
//

typedef struct
{
   size_t               pageThreshold;
   size_t               urlThreshold;
   size_t               mbThreshold;
   size_t               pagesizeThreshold;
   SAFESEARCH_SETTING   safeSearch;
   IM_SETTING           instantMessaging;
   P2P_SETTING          peerToPeer;
   bool                 filterEnabled:1;
   bool                 blockAll:1;
   bool                 onlyAllowSpecified:1;
   bool                 blockAudioFiles:1;
   bool                 blockVideoFiles:1;
   bool                 blockExeFiles:1;
   bool                 blockImageFiles:1;
   bool                 blockTextFiles:1;
   bool                 blockArchiveFiles:1;
   bool                 logOnlyGroupName:1;
   bool                 urlKeywordEnabled:1;
   bool                 blockUserDefinedFiles:1;
   bool                 textKeywordEnabled:1;
   bool                 blockIPAddressURLs:1;
   bool                 notifyKeywordMatching:1; // NO LONGER USED
   bool                 dontBlockOnKeywords:1;
   // Block pages which are in the 'Other' category (uncategorised)
   // When set to true, 'Other' sites will be blocked.
   bool                 blockOtherWorkingHours:1;
   bool                 blockOtherNonWorkingHours:1;
   bool                 blockOtherHTTPSWorkingHours:1;
   bool                 blockOtherHTTPSNonWorkingHours:1;
   bool                 blockHTTPSWorkingHours:1;
   bool                 blockHTTPSNonWorkingHours:1;
   bool                 inWorkingDay:1;
   bool                 sinBin:1;
   bool                 sizeKeywordEnabled:1;
   bool                 httpsBlocked:1; // obselete BUG 1857
   bool                 TXTokens_Show_Message:1;
   
} POLICY_FLAGS;

typedef struct
{
   unsigned long     SSE_OnOff;
   unsigned long     SSE_Moderate;

} SAFESEARCH_FLAGS;

typedef struct
{
   bool            ICQAOLBlocked:1;
   bool            MSNBlocked:1;
   bool            YahooBlocked:1;
   bool            GoogleTalkBlocked:1;

} IM_FLAGS;

typedef struct
{
   bool           allowWorking:1;
   bool           allowNonWorking:1;
   bool           notify:1;

} CATEGORYPERMS;

typedef t_category t_mask;

typedef struct 
{
   char                 name[MAX_POLICY_NAME];
   CATEGORYPERMS        categoryTable[MAX_CATEGORIES];
   CATEGORYPERMS        custom_categoryTable[MAX_CATEGORIES];
   POLICY_FLAGS         flags;
   SAFESEARCH_FLAGS     safeSearchFlags;
   policy_id_t          policyId;
   t_mask               workingHoursMask;
   t_mask               nonWorkingHoursMask;
   t_mask               currentCategoryMask;
   t_mask               notifyCategoryMask;
   t_mask               custom_workingHoursMask;
   t_mask               custom_nonWorkingHoursMask;
   t_mask               custom_currentCategoryMask;
   t_mask               custom_notifyCategoryMask;
   size_t               ldapServerID;
   size_t               notifyFlags;
   char*                emailNotify;
   IM_FLAGS             instantMessagingFlags;
   NONWORKING_HOURS     nonWorkingHours;

} POLICY;


typedef struct
{
   char                 name[MAX_GROUP_NAME+1];
   group_id_t           groupNumber;
   bool                 permanent:1;
   bool                 hide:1;
   bool                 createdByLdap:1;
   bool                 existOnLdap:1;

} GROUP;


typedef struct
{
   union
   {
      policy_id_t       ival;
      const char*       cptr;

   } svalue;

   GROUP*               in_groups;
   size_t               in_groups_count;
   GROUP *              out_group;
   size_t               out_group_idx;
   struct
   {
      bool             groupName:1;
      bool             groupNumber:1;
      bool             policyId:1;

   } stype;

   bool retry;

} t_search_val;

extern pthread_mutex_t  sGroupMutex;

size_t getGroupCount(void);

/**
 * @name getGroup
 * @abstract get group by id, if found then dst ptr will contain a copy of such group
 * @param groupNumber[in]
 * @param dst[out]
 * @return t/f
 */
bool getGroup(const int, GROUP *const );

/**
 * @name findGroupByName
 * @abstract find group by name, if found then dst ptr will contain a copy of such group
 * @param name[in]
 * @param dst[out]
 * @return t/f
 */
bool findGroupByName(const char *const, GROUP *const);

/**
 * @name find_group_by
 * @warning Not Thread-Safe
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 * @param sv[in|out]
 * @return t/f
 */
TSA_CAP_TR_RQ(sGroupMutex)
bool find_group_by(t_search_val * const);

/**
 * @name getPolicy_without_lock
 * @abstract find group by id, if found then out ptr will contain a pointer 
 * @warning Not Thread-Safe
 * @param groupNumber[in]
 * @param out[out] 
 * @return t/f
 */
TSA_CAP_TR_RQ(sGroupMutex)
bool getGroup_without_lock(const int, GROUP **);

/**
 * @name getPolicy_without_lock
 * @abstract find policy by id, if found then out ptr will contain a pointer
 * @warning Not Thread-Safe
 * @param policyId[in]
 * @param out[out] 
 * @return t/f
 */
TSA_CAP_TR_RQ(sGroupMutex)
bool getPolicy_without_lock(const int policyId, POLICY **out);


/**
 * @name getPolicy
 * @abstract get policy by id, if found then dst ptr will contain a COPY of such policy
 * @param policyId[in]
 * @param dst[out] 
 * @return t/f
 */
bool getPolicy(const int policy_id, POLICY *dst);

/**
 * @name checkAccessTimes
 * @warning not thread-safe, use TS_CHECKACCESSTIMES
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 * @abstract This function sets the appropriate Category mask according to
 * the time of day. i.e. working or non-working. The function asssumes
 * the non-working hours have been set correctly, the set function must
 * check that the start and stop periods are chronologically correct.
 */
TSA_CAP_TR_RQ(sGroupMutex)
void checkAccessTimes(void);

/**
 * @name replaceGroupPolicyTables
 * @warning Not Thread-Safe
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 * @abstract replace internal group and policy tables 
 * @param newGroupTable
 * @param newGroupCount
 * @param newPolicyTable
 * @param newPolicyCount
 */
TSA_CAP_TR_RQ(sGroupMutex)
void replaceGroupPolicyTables( GROUP * const, const size_t, POLICY * const, const size_t );

LI_TSA_AQ(sGroupMutex)
void LOCKGROUPTABLE(void)
{
   tsa_lock(&sGroupMutex);
}

LI_TSA_RE(sGroupMutex)
void UNLOCKGROUPTABLE(void)
{
   tsa_unlock(&sGroupMutex);
}

/**
 * @abstract thread-safe wrapper for checkAccessTimes
 */
TX_INLINE_LIB
void TS_CHECKACCESSTIMES(void) 
{
   LOCKGROUPTABLE();
   checkAccessTimes();
   UNLOCKGROUPTABLE();
}

#ifdef __cplusplus
}
#endif

#endif /* TITAN_GROUP_H */
