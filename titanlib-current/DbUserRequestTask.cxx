/*
 * $Id$
 */


#include "db_pg.hxx"
#include "DbUserRequestTask.hxx"
#include "TAPE.hxx"
#include "TitanScheduler.hxx"
#include "TitanUser.hxx"
#include "edgepq.h"
#include "log.h"
#include "sqls.h"
#include "ttn_errors.hxx"
#include "ttn_groups.hxx"
#include "ttn_app_modes.hxx"
#include "TAPE.hxx"
#include <iostream>
#include <libpq-fe.h>


using namespace titan_v3;
using namespace titan_v3::tools;

/* alias */
using RC=RequestContext::ResultCode;

TXATR bool ttn_load_user( PGresult* const,const size_t, TitaxUser * const );

static inline void cleanUser(TitaxUser& user) noexcept
{
    user = { .name = TITAX_ANON_DEFAULT_USER_NAME, .invalid_user = true, .anonymous = true };
}

inline
bool operator == (const user_id_t id, const TitaxUser & usr ) noexcept
{
    return ( id == usr.id );
}

template <const bool both>
static bool exec_policies_query(    PGconn* const __restrict db,
                                    const std::string & l_query,
                                    TitaxUser * const __restrict parent,
                                    TitaxUser * const __restrict child=nullptr   ) noexcept
{
    if (    db                                     &&

            parent                                 &&

            (  !both                               || 

               /* 
                * check if a parent is really a parent and 
                * a child is really a child of this parent 
                */
               (  child                            &&

                  !parent->parent_id               &&

                  parent->id == child->parent_id      )  )  ) {

        using namespace titan_v3::tools;

        const auto & q_str = std::string{ UserContext::policies_query + l_query };

        pgresult_uniq_t rset{pq_get_rset( db, q_str.c_str() )};

        if (rset){

            const auto & stat = load_ids_for_policies_and_groups( rset.get() ) ;

            if ( stat.second && stat.first.size() ) {

               using namespace titan_v3::tools::algorithms;

               if ( !both ) {

                  if ( stat.first.size()==1 ) {

                     // the map should have data only for the single user

                     const auto & top = stat.first.cbegin();

                     if ( 	top != stat.first.cend() ) {

                        auto is_in_stat = is_in( top->first, (*parent) );

                        if ( is_in_stat.second ) {

                           is_in_stat.first.policy_info = std::move(top->second);

                           return static_cast<bool>( is_in_stat.first.policy_info.policies.length);
                        }

                     }
                  }

                  // else error

                  return false;
               } 
               else {

                  // the map should have data only for 2 users
                  if ( stat.first.size() == 2 ) {

                     for ( auto & up : stat.first ) {

                        auto is_in_stat = is_in( up.first, *parent, *child );

                        if ( is_in_stat.second ) {

                           is_in_stat.first.policy_info = std::move(up.second);

                           continue;
                        }

                        //error
                        return false;
                     }

                     return ( parent->policy_info.policies.length && 

                              child->policy_info.policies.length     );
                  }
               }
            }
        }
    }

    return false;
}

template <const bool both>
static bool exec_users_bandwidth_query( PGconn* const __restrict db,
                                        const std::string & l_query,
                                        TitaxUser * const __restrict parent,
                                        TitaxUser * const __restrict child=nullptr  ) noexcept
{

    if ( db && parent ) {

        using namespace titan_v3::tools;

        const auto & q_str = std::string{ UserContext::users_bandwidth_query + l_query };

        pgresult_uniq_t rset{pq_get_rset( db, q_str.c_str() )};

        if ( rset ) {

            auto * rset_ = rset.get();
            const size_t num_users{ txpq_row_count(rset_) };

            for (size_t i = 0; i < num_users; ++i) {

                TitaxUser * const usr{  both ?
                                        (   parent->id != txpq_cv_ulong(rset_, i, 0) ?
                                            child :
                                            parent  ) :
                                        parent  };

                usr->downloaded_byte=static_cast<size_t>( txpq_cv_longlong(rset_, i, 1) );
            } 
            return true;
        }
    }

    return false;
}

static
RC readBothUsersData(   PGconn* const __restrict db,
                        TitaxUser & parent,
                        TitaxUser & child               ) noexcept
{

    parent.policy_info = {};

    child.policy_info = {};

    const auto & list_query = std::string{  "in ("                      +
                                             std::to_string(parent.id)  +
                                             ", "                       +
                                             std::to_string(child.id)   +
                                             ")"                           };

    if ( ! exec_policies_query<true>(   db,
                                        list_query,
                                        &parent,
                                        &child     )) {

            return RC::DbError;
    }

    parent.downloaded_byte = 0;

    child.downloaded_byte = 0;

    if ( app_mode_t::gateway != GTAPE.app_mode ) {

       return RC::Success;
    }

    return (    exec_users_bandwidth_query<true>(   db,
                                                    list_query,
                                                    &parent,
                                                    &child     )  ?

                RC::Success                                       :

                RC::DbError                                          );
}

static
RC readOneUserData( PGconn* const __restrict db,
                    TitaxUser& user               ) noexcept
{

    user.policy_info = {};

    const auto & id_query = std::string{ "=" + std::to_string(user.id) };

    if ( ! exec_policies_query<false>(  db,
                                        id_query,
                                        &user   ) ) {

            return RC::DbError;
    }

    user.downloaded_byte = 0;

    if ( app_mode_t::gateway != GTAPE.app_mode ) {

       return RC::Success;
    }

    return (    exec_users_bandwidth_query<false>(  db,
                                                    id_query,
                                                    &user      )  ?

                RC::Success                                       :

                RC::DbError                                          );

}

static
RC readParent(  PGconn* const __restrict db, 
                const size_t parent_id,
                TitaxUser& parent               ) noexcept
{

    using namespace titan_v3::tools;

    const auto & q_str =   UserContext::user_query                   +
                           std::string{   " where id="               +
                                          std::to_string(parent_id)     };

    pgresult_uniq_t rset{ pq_get_rset(  db, q_str.c_str()) };

    if (rset){

        if (txpq_row_count(rset.get())){

           //single record
           return ( ttn_load_user( rset.get(),0, &parent ) ?
                    RC::Success :
                    RC::DbError     );
        }

        return RC::UserNotFound;
    }

    return RC::DbError;

}

/* todo: use pg_db */
static
RC readChild(   PGconn* const __restrict  db, 
                TitaxUser & parent,
                TitaxUser & child,
                std::string  main_query         ) noexcept
{
    using namespace titan_v3::tools;

    pgresult_uniq_t rset{ pq_get_rset(  db,
                                        main_query.c_str()) };

    RC parent_result{ RC::UserNotFound };

    if (rset){

       if (    txpq_row_count( rset.get() ) &&
               //single record
               ttn_load_user( rset.get(), 0, &child )   ) {

                rset.reset();

                if ( child.parent_valid ) {

                    UsersCache::UserStatus parent_found{ users_cache->get_user_by_id(   child.parent_id,
                                                                                        parent           )};

                    if ( parent_found == UsersCache::UserNotLoaded ) {

                        //Parent not found in local cache. Read from DB.
                        parent_result = readParent( db,
                                                    child.parent_id,
                                                    parent  );

                        if ( parent_result == RC::Success &&
                             readBothUsersData(db,parent,child) != RC::DbError  ) {

                                users_cache->addUser(parent);
                                users_cache->addUser(child);
                                return RC::Success;

                        } 
                        else if ( parent_result == RC::UserNotFound ) {

                            return RC::UserNotFound;
                        }

                    }
                    else if ( parent_found == UsersCache::UserNotFound ) {

                        return RC::UserNotFound;
                    }
                    else if ( readOneUserData(db, child) != RC::DbError ) {

                        //Parent found in local cache
                        users_cache->addUser(child);
                        return RC::Success;
                    }

                }
                else if ( readOneUserData(db, child) != RC::DbError ) {

                    //Child has no parent
                    parent = child;
                    users_cache->addUser(child);
                    return RC::Success;
                }

        }
        else {
             //User not found
             return RC::UserNotFound;
        }

    }

    //This point is reached when there has been a DB error.
    cleanUser(child);

    if (parent_result == RC::Success) {

        cleanUser(parent);
    }

    return RC::DbError;
}

void UserFromIp::execute( SchedulerContext& sch_context ) noexcept
{

   if ( PGconn * const db=sch_context.getDbConnection() ) {
      using namespace titan_v3::locations;
      switch (loc_.type){

         case location_t::types::db:
         case location_t::types::session:{

            const auto & q =  UserContext::user_query                      +
                              std::string{   "where id="                   +
                                             std::to_string(loc_.user_id)     };

            if ((result = readChild(db,parent,child, q )) == ResultCode::UserNotFound) {
               users_cache->markIdAsNotFound(loc_.user_id);
            }

         }break;
         case location_t::types::wada:{

            std::string q{UserContext::user_query};
            q+=R"(where uuid_str=')";
            q+=std::string(loc_.uuid).c_str();
            q+=R"(')";

            result = readChild(db,parent, child, q);

            if (    ResultCode::Success!=result 
                    //|| !titan_v3::GTAPE.locations.find_and_update_wada_location(loc_,child.id)  disabled as redundant
                ){
               /* not implemented yet */
               //users_cache->markIpAsNotFound(ip);
            }

         }break;
         default:break;
      }
   } else 
      result=ResultCode::DbError;
}


void UserByName::execute( SchedulerContext& sch_context ) noexcept
{
    if ( PGconn * const db = sch_context.getDbConnection() ) {

        using namespace titan_v3::tools;

        /* a workaround */
        t_cbuffer_uniq escaped{ txpq_escape_literal(   db,
                                                       name.c_str(),
                                                       name.size()    ) };
        if ( escaped ) {

            if ( const size_t escaped_sz = strlen( escaped.get() ) ) {

                std::string query_buf = UserContext::user_query;

                query_buf += "where lower(name)=lower(";

                query_buf += std::string{ escaped.get(), escaped_sz };

                query_buf += ')';

                if ( ! domains.size() ) {

                    query_buf += " and COALESCE(domain,'')='' ";
                }
                else {

                    query_buf += " and domain in (";

                    if ( users_cache->getListType() == UsersListType::ult_hybrid ) {

                        query_buf += "'', ";
                    }

                    query_buf += domains;

                    query_buf += ')';
                }

                result = readChild( db, parent, child, query_buf );

                if ( result == ResultCode::UserNotFound ) {

                    users_cache->markNameAsNotFound( name );
                }

                return;
            }
        }
    }

    result = ResultCode::DbError;
}


void UserParent::execute( SchedulerContext & sch_context ) noexcept
{
   if ( PGconn * const db=sch_context.getDbConnection() ) {

      if ( ( result = readParent(db, parent_id,parent) ) == ResultCode::Success ) {

         if ( ( result = readOneUserData(db, child) ) == ResultCode::DbError ) {

            cleanUser(parent);
         }
         else {

            users_cache->addUser(parent);
         }
      }
   } 
   else 
      result=ResultCode::DbError;
}

void UserById::execute(SchedulerContext & sch_context) noexcept
{
   if ( PGconn * const db=sch_context.getDbConnection() ) {

      const auto & q =  UserContext::user_query                +
                        std::string{   "where id="             +
                                       std::to_string(user_id)    };

      if ( ( result = readChild(db, parent,child,q) ) == ResultCode::UserNotFound ) {

         users_cache->markIdAsNotFound(user_id);
      }
   } 
   else
      result=ResultCode::DbError;
}


////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros
 */
static int do_UserContext_tracing = 0;  /*Change to non zero to enable tracing*/
/* Connot use conextexpr or const above as -Wunreachable-code triggers */

titan_instance_tracker *get_titan_instance_tracker_UserContext()
{
   /* Create on first access, using double checked lock */
   static titan_instance_tracker * g_UserContext_tracker{};
   static std::mutex l_lock{};

   std::lock_guard<std::mutex> l_lg( l_lock );

   if ( !g_UserContext_tracker ) {

      g_UserContext_tracker = new titan_instance_tracker("UserContext");

   }

   return g_UserContext_tracker;
}
void print_tracked_UserContext( void *a_p, std::ostream & a_s)
{
    auto * p_item = static_cast< UserContext *>( a_p );
    p_item->dump_idetifying_info(a_s);
}
void Check_tracker_UserContext( std::ostream & a_os, uint32_t a_older_than_secs)
{
    if (do_UserContext_tracing != 0)
    {
        get_titan_instance_tracker_UserContext()->Check(a_os, a_older_than_secs, print_tracked_UserContext);
    }
    else
    {
        a_os << " UserContext instance tracing is not enabled (" << a_older_than_secs << ")\n";
    }
}
UserContext::UserContext() noexcept
{
    if (do_UserContext_tracing != 0) get_titan_instance_tracker_UserContext()->Add( this );
}
UserContext::~UserContext()
{
    if (do_UserContext_tracing != 0) get_titan_instance_tracker_UserContext()->Remove( this );
}


#ifdef TTN_ATESTS

bool exec_policies_query_4tests(   PGconn* const __restrict db,
                                          const std::string & l_query,
                                          TitaxUser * const __restrict parent,
                                          TitaxUser * const __restrict child     ) noexcept
{

   return exec_policies_query<false>(db,l_query,parent,child);
}


bool exec_policies_query_both_4tests(   PGconn* const __restrict db,
                                          const std::string & l_query,
                                          TitaxUser * const __restrict parent,
                                          TitaxUser * const __restrict child     ) noexcept
{

   return exec_policies_query<true>(db,l_query,parent,child);
}



#endif


