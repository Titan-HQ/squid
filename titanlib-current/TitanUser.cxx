/*
 * $Id$
 */

#include "TitanUser.hxx"
#include "edgepq.h"
#include "global.h"
#include "sqls.h"
#include "ttn_errors.hxx"
#include "ttn_tools.hxx"
#include "ttn_app_modes.hxx"
#include "TAPE.hxx"
#include "log.h"
#include <iostream>

//Receiver for reading users from database
Receiver       db_receiver{};
UsersCache*    users_cache{};

using namespace titan_v3;
using namespace titan_v3::tools;

void init_users_cache( const size_t size )
{
   if ( ( users_cache = new UsersCache{size} ) ) {
      return ;
   }

   throw titan_v3::tools::errors::nullptr_error();
}

void destroy_users_cache()
{
   if ( users_cache ) {
      delete users_cache;
   }
}

bool UsersCache::setListType(const uint32_t type) noexcept
{
   try{

      list_type = type;

      return true;

   } catch ( const std::exception & e ) {

      titax_log(  LOG_ERROR,
                  "%s:%d:%s\n",
                  __func__,
                  __LINE__,
                  e.what()       );
   }

   return false;
}

void UsersCache::deleteActions(TitaxUser& user) {

#ifndef __clang_analyzer__
    std::unique_lock<std::mutex> id_lock{   users_by_id_mtx,    std::defer_lock};
    std::unique_lock<std::mutex> name_lock{ users_by_name_mtx,  std::defer_lock};
    std::unique_lock<std::mutex> uuid_lock{ users_by_uuid_mtx,  std::defer_lock};

    std::lock(  id_lock,
                name_lock,
                uuid_lock   ); // can throw an exception
#endif

    users_by_id.erase(user.id);
    users_by_name.erase(user.name);
    users_by_uuid.erase(user.uuid);

}

bool UsersCache::load_default_info(TitaxUser& copy_buffer) {

#ifndef __clang_analyzer__
   std::unique_lock<std::mutex> default_lock(default_user_mtx);
#endif

   if (default_user_loaded) {

      get_user_by_id__( default_user,
                        copy_buffer );
      return true;
   }

   return false;
}

UsersCache::UserStatus UsersCache::get_user_by_id(  const user_id_t id,
                                                    TitaxUser& copy_buffer) {

    return get_user_by_id__(id,copy_buffer);
}

UsersCache::UserStatus UsersCache::get_user_by_location(    const titan_v3::locations::location_t & loc,
                                                            TitaxUser& copy_buffer) {

   if ( loc.user_id ) {

      return get_user_by_id__( loc.user_id, copy_buffer );
   }

   using namespace titan_v3::locations;

   switch ( loc.type ){

      case location_t::types::wada:{

         if ( loc.uuid ){

            const auto user_pos=lock_and_find_by_uuid(loc.uuid);

            if ( -1 < user_pos ){ 

               if (  copyElement(   static_cast<size_t>(user_pos),
                                    copy_buffer) && 

                     copy_buffer.uuid == static_cast<t_uuid>(loc.uuid) ){

                        return UserFound;
               }

               //User has been deleted after retrieving the index
               return UserNotLoaded;
            }

            const auto user_not_found = uuids_not_found.find(loc.uuid);
            if ( user_not_found != uuids_not_found.end() ) {

               if ( user_not_found->second < time(nullptr) ) {

                  uuids_not_found.erase(user_not_found);

                  return UserNotLoaded;
               }

               return UserNotFound;
            }

            return UserNotLoaded;
         }

         return UserNotFound;
      }

      default:{

         /* for now until the PE is ready to load locations on demand */ 
         return UserNotFound;
      }
   }
}

UsersCache::UserStatus UsersCache::find_user_by_name_utf8(  const std::string& name,
                                                            TitaxUser& copy_buffer   ){

   const auto user_pos = lock_and_find_by_name(name);

   if ( -1 < user_pos ){ 

      if (  copyElement(   static_cast<size_t>(user_pos),
                           copy_buffer) && 

            copy_buffer.name == name  ) {

                    return UserFound;
        }

        //User has been deleted after retrieving the index
        return UserNotLoaded;
    }

    const auto user_not_found = names_not_found.find(name);
    if ( user_not_found != names_not_found.end() ) {

       if ( user_not_found->second < time(nullptr) ) {

            names_not_found.erase(user_not_found);
            return UserNotLoaded;
        }

        return UserNotFound;
    }

    return UserNotLoaded;
}

void UsersCache::addUser(const TitaxUser& new_user) {

   { /* locking scope1 */
#ifndef __clang_analyzer__
      std::unique_lock<std::mutex> id_lock{ users_by_id_mtx };
#endif
      if (  users_by_id.count(new_user.id) || 
            users_being_added.count(new_user.id)   ) {

               return;
      }

      //Mark the user ad being added.
      users_being_added[new_user.id] = 0;
   }

   const auto user_index = addElement(  new_user,
                                        !new_user.parent_valid  );

   { /* locking scope2 */

#ifndef __clang_analyzer__
      std::unique_lock<std::mutex> id_lock{     users_by_id_mtx,   std::defer_lock};
      std::unique_lock<std::mutex> name_lock{   users_by_name_mtx, std::defer_lock};
      std::unique_lock<std::mutex> uuid_lock{   users_by_uuid_mtx, std::defer_lock};

      std::lock(    id_lock,
                    name_lock,
                    uuid_lock   ); // can throw an exception
#endif

      /* ignore the status, update is not allowed */
      (void)users_by_id.emplace(    new_user.id,
                                    user_index  );

      users_being_added.erase(new_user.id);
      ids_not_found.erase(new_user.id);
      
      /* ignore the status, update is not allowed */
      (void)users_by_name.emplace(  new_user.name,
                                    user_index  );

      /* ignore the status, update is not allowed */
      (void)users_by_uuid.emplace(  new_user.uuid,
                                    user_index  );

   }

   if (new_user.default_user) {

#ifndef __clang_analyzer__
      std::unique_lock<std::mutex> default_lock{ default_user_mtx };
#endif

      default_user = new_user.id;
      default_user_loaded = true;
   }
}

void UsersCache::updateBandwidth(   const user_id_t id,
                                    const size_t byte )
{

   if ( app_mode_t::gateway == GTAPE.app_mode ) {

      const auto user_pos = lock_and_find_by_id(id);

      if ( -1 < user_pos ){

         auto update_bw = [&](TitaxUser& user) {

            if ( id == user.id ) {

               user.downloaded_byte += byte;
            }
         };

         updateElement( static_cast<size_t>(user_pos), update_bw );
      }
   }
}

void UsersCache::updateTokensCount( const user_id_t id,
                                    const size_t tokens_count ) {

   const auto user_pos = lock_and_find_by_id(id);

   if ( -1< user_pos ){

      auto update_tk = [&](TitaxUser& user) {

         if ( id == user.id ) {

            user.TXTokens_Count = tokens_count;
         }
      };

      updateElement( static_cast<size_t>(user_pos), update_tk );
   }
}

void UsersCache::synchronize(PGconn* const __restrict db)
{
   if ( app_mode_t::gateway == GTAPE.app_mode ) {

      bool finish{};

      while ( db && !finish ) {

         size_t next{};
         std::vector<size_t> ids{};
         std::vector<size_t> bandwidths{};

         auto read_users = [&](TitaxUser& user) {

            if ( user.id && user.downloaded_byte ) {

               ids.emplace_back(user.id);

               bandwidths.emplace_back(user.downloaded_byte);
            }
         };

         finish = readUpdatedElements( read_users, 20, &next );

         if ( ids.size() ) {

            using namespace titan_v3::tools;

            const auto stat = sql::make_update_users_bw(   ids,
                                                           bandwidths );
            if ( stat.second ){

               if ( PGresult* const rset = pq_get_rset(  db,
                                                         stat.first.c_str() ) ) {

                     PQclear(rset);
               }
            }
         } /* if */
      } /* if */
   } /* while */
}

bool set_list_type( const uint32_t type )
{
   return ( users_cache ? users_cache->setListType(type) : false );
}

void add_user_to_cache( TitaxUser* const __restrict  user )
{
   if ( user && users_cache ) {

      users_cache->addUser(*user);
   }
}

void update_tokens_count(  const size_t user_id,
                           const size_t TXTokens_Count )
{

   if ( users_cache ) { 
      users_cache->updateTokensCount(  user_id,
                                       TXTokens_Count  );
   }
}

void clean_users()
{
   if ( users_cache ) {
      users_cache->cleanUsers();
   }
}

void reset_users_bw()
{
   if ( app_mode_t::gateway == GTAPE.app_mode ) {

      assert(users_cache);

      users_cache->resetUsersBandwidth();
   }
}

void user_cache_reserve(const size_t r_)
{
   if ( r_ && users_cache ) {

      users_cache->reserve_all(r_);
   }
}

void user_cache_rehash(const size_t r_)
{
   if ( r_ && users_cache ) {
      users_cache->rehash_all(r_);
   }
}

