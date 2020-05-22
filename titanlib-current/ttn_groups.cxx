/*
 * $Id: ttn_groups.cxx 13867 2016-10-24 16:27:47Z jmanteiga $
 * Groups Hander
 */

#include "ttn_groups.hxx"
#include "edgepq.h"
#include "log.h"
#include "titaxlib.h"
#include "ttn_global.hxx"
#include "ttn_traits.hxx"
#include <iostream>
#include <mutex>
#include <set>
#include <unordered_map>
#include "TAPE.hxx"
#include "TitanUser.hxx"


using namespace titan_v3::globals;
/* groups_by_id & policies_by_id aren't protected by any lock */

TSA_GUARDED_BY(sGroupMutex)
static std::unordered_map<policy_id_t, unsigned long> policies_by_id{};

TSA_GUARDED_BY(sGroupMutex)
static std::unordered_map<group_id_t, unsigned long> groups_by_id{};

constexpr uint_fast64_t GROUP_POLICY_LIMIT = (  sizeof( std::declval<ids_t>().ids )   /

                                                sizeof( std::declval<ids_t>().ids[0] )   );

tx_static_assert_type(  decltype( std::declval<ids_t>().ids ),
                        policy_id_t,
                        "Unable to compile, the base type of the t_group_policy->ids "\
                        "differs from the expected (policy_id_t)\n"                       );


static PGconn* get_dbcon()
{
   static PGconn* dbconn{};
   return (check_raw_dbconn(&dbconn,16,&db_config_connect)?dbconn:nullptr);
}


long getGroupIndex(const group_id_t group_id)
{
   long ret_{ INVALID_ };
   auto group_index = groups_by_id.find(group_id);
   if (group_index != groups_by_id.end()) {
      ret_=static_cast<long>(group_index->second);
   } else {
      if (PGconn* const conn=get_dbcon()){

         titax_load_groups(conn);
         group_index = groups_by_id.find(group_id);
         if (group_index != groups_by_id.end()) {

            ret_=static_cast<long>(group_index->second);

         }
      }
   }
   return ret_;
}

long getPolicyIndex(const policy_id_t policy_id)
{
   long ret_{ INVALID_ };
   auto policy_index = policies_by_id.find(policy_id);
   if (policy_index != policies_by_id.end()) {
      ret_=static_cast<long>(policy_index->second);
   } else {
      if (PGconn* const conn=get_dbcon()){

         titax_load_groups(conn);
         policy_index = policies_by_id.find(policy_id);
         if (policy_index != policies_by_id.end()) {

            ret_=static_cast<long>(policy_index->second);
        }
     }
   }
   return ret_;

}

void clearGroupPolicyMaps()
{
   policies_by_id.clear();
   groups_by_id.clear();
}


void addGroupId(const policy_id_t group_id, const unsigned long index)
{
   groups_by_id[group_id] = index;
}


void addPolicyId(const policy_id_t policy_id, const unsigned long index)
{
   policies_by_id[policy_id] = index;
}

bool load_ids_for_policies_and_groups_for_user( PGresult * const __restrict rset,
                                                const user_id_t id, 
                                                TitaxUser* const __restrict user  )
{

   if ( rset && id && user ) { 

      auto status = titan_v3::tools::load_ids_for_policies_and_groups ( rset );

      if ( status.second ) {

         const auto & search = status.first.find(id);

         if ( search != status.first.end() ) {

            user->policy_info = std::move(search->second);

            return true;
         }
      }
   }

   return false;
}

struct dedup_t
{
   std::set<policy_id_t> policies;
   std::set<group_id_t> groups;
   bool inherited;
};

update_status_t titan_v3::tools::load_ids_for_policies_and_groups(PGresult * const __restrict rset ) noexcept
{
/* effective policy will always return gid and pid for the wtg */
   if ( rset  ) {

/* 
 user_id | group_id | policy_id | inherited 
---------+----------+-----------+-----------
*/

        std::map<user_id_t, dedup_t> uniq_pngs;

        const size_t row_ctx{ txpq_row_count( rset ) };

        for ( size_t i = 0; i < row_ctx; ++i ) {

            const user_id_t uid{ txpq_cv_ulong( rset, i, 0 ) };

            const policy_id_t pid{ txpq_cv_int( rset, i, 2 ) };

            if ( UNASSIGNED < uid && UNASSIGNED < pid ) {

                auto & uq = uniq_pngs[ uid ];

                uq.policies.insert( pid );

                const group_id_t gid{ txpq_cv_int( rset, i, 1 ) };

                if ( UNASSIGNED < gid ) {

                    uq.groups.insert( gid );
                }

                uq.inherited = txpq_cv_bool( rset, i, 3 );
            }
            else { 

                titax_log(  LOG_WARNING,
                            "%s:%d::invalid policy id or user id [%d,%zu]\n",
                            __FILE__,
                            __LINE__,
                            pid,
                            uid                                                 );
            }
        }

        users_policies_t results;

        // cpy 
        for ( const auto & uq : uniq_pngs ) {

            auto & r = results[ uq.first ];

            for ( const auto & id : uq.second.policies ) {

               if (  r.policies.length < GROUP_POLICY_LIMIT ) {

                  r.policies.ids[ r.policies.length++ ] = id ;

                  continue;
               }

               break;
            } 

            for ( const auto & id : uq.second.groups ) {

               if (  r.groups.length < GROUP_POLICY_LIMIT ) {

                  r.groups.ids[ r.groups.length++ ] = id ;

                  continue;
               }

               break;
            } 

            r.inherited = uq.second.inherited;

      }

      return update_status_t::success( results );
   }

   return update_status_t::failure();
}
