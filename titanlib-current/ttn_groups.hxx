/*
 * $Id$
 *
 */

#ifndef TTN_GROUPS_HXX
#define TTN_GROUPS_HXX

#include <libpq-fe.h>
#include "global.h"
#include "TitaxUser.h"
#include "Group.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @name getGroupIndex
 * @warning Not Thread-Safe, 
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 * @param group_id
 * @return index
 */   
TSA_CAP_TR_RQ(sGroupMutex)
long getGroupIndex(const group_id_t group_id);

/**
 * @name getPolicyIndex
 * @warning Not Thread-Safe, 
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 * @param policy_id
 * @return index
 */
TSA_CAP_TR_RQ(sGroupMutex)
long getPolicyIndex(const policy_id_t policy_id);

/**
 * @name clearGroupPolicyMaps
 * @warning Not Thread-Safe,
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 */
TSA_CAP_TR_RQ(sGroupMutex)
void clearGroupPolicyMaps(void);

/**
 * @name addGroupId
 * @warning Not Thread-Safe,
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 */
TSA_CAP_TR_RQ(sGroupMutex)
void addGroupId(const group_id_t group_id, const unsigned long index);

/**
 * @name addPolicyId
 * @warning Not Thread-Safe,
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 */
TSA_CAP_TR_RQ(sGroupMutex)
void addPolicyId(const policy_id_t policy_id, const  unsigned long index);

bool load_ids_for_policies_and_groups_for_user( PGresult * const, 
                                                const user_id_t, 
                                                TitaxUser * const );

#ifdef __cplusplus
};

/* CPP interface */

#include "ttn_global.hxx"
#include "ttn_tools.hxx"

namespace titan_v3
{
   namespace tools
   {

      extern globals::update_status_t load_ids_for_policies_and_groups( PGresult * const ) noexcept;

      #ifdef TTN_ATESTS
         extern app_mode_t app_mode_4tests_;
      #endif

      constexpr unassigned_t UNASSIGNED{0};
   }
}

#endif

#endif /* TTN_GROUPS_HXX */
