/*
 * $Id$
 */

#ifndef TITANUSER_H_
#define TITANUSER_H_

#include <map>
#include <mutex>
#include <string>
#include <libpq-fe.h>

#include "time.h"

#include "TitanCache.hxx"
#include "TitaxUser.h"
#include "RequestTask.hxx"
#include "global.h"
#include "ttn_locations.hxx"
#include "ttn_tools.hxx"


namespace ttft=titan_v3::tools::functors::templates;

struct UsersListType : protected userslist_t
{
   using userslist_t::ult_plain;        //homogenous structure

   using userslist_t::ult_multidomain;  //homogenous structure

   using userslist_t::ult_hybrid;       //heterogeneous structure

   UsersListType() noexcept : userslist_t{ .type=userslist_t::ult_plain }
   {
   }

   constexpr UsersListType( const UsersListType & a ) noexcept : userslist_t{ .type=a.type }
   {
   }

   constexpr UsersListType( const userslist_t & a ) noexcept : userslist_t{ .type=a.type }
   {
   }

   template<typename T,typename std::enable_if<std::is_enum<T>::value>::type* = nullptr>
   constexpr UsersListType( const T & v ) noexcept : userslist_t{ .type=v }
   {
   }

   inline UsersListType & operator=( const UsersListType & a ) noexcept 
   {
      type = a.type;
      return *this;
   }

   inline UsersListType & operator=( const userslist_t & a ) noexcept 
   {  
      type = a.type;
      return *this;
   }

   template<typename T>
   inline typename std::enable_if< std::is_integral<T>::value, UsersListType&>::type 
   operator=( const T & v ) 
   {
      switch ( v ) {

         case ult_plain: type = ult_plain; break;

         case ult_multidomain: type = ult_multidomain; break;

         case ult_hybrid: type = ult_hybrid; break;

         default : 
            throw  titan_v3::tools::errors::assign_error("invalid enum");
         break;
      }

      return *this;
   }

   template<typename T>
   inline typename std::enable_if< std::is_enum<T>::value, bool>::type 
   operator==(const T & r) const noexcept
   {
      return type == r;
   }

   template<typename T>
   inline typename std::enable_if< std::is_enum<T>::value, bool>::type 
   operator!=(const T & r) const noexcept
   {
      return type != r;
   }

};

class UsersCache : protected TitanCache<TitaxUser> {
public:
   enum UserStatus {
      UserFound=0x00,
      UserNotLoaded,
      LoadUserNotFound, /* not found yet */
      UserNotFound, /* not found at all */

   };

protected:
   constexpr static time_t                                  USER_TTL{20};
   UsersListType                                            list_type{};
   mutable std::mutex                                       users_mtx{};

   mutable std::mutex                                       users_by_id_mtx{};
   std::unordered_map<size_t, size_t>                       users_by_id{};
   std::unordered_map<size_t, size_t>                       users_being_added{};
   std::unordered_map<size_t, time_t>                       ids_not_found{};
   using lock_and_find_by_id_fn= ttft::lock_and_find_fn<    decltype(users_by_id_mtx), 
                                                            decltype(users_by_id) >;
   lock_and_find_by_id_fn                                   lock_and_find_by_id{ users_by_id_mtx,
                                                                                 users_by_id };

   mutable std::mutex                                       users_by_name_mtx{};
   std::unordered_map<std::string, size_t>                  users_by_name{};
   std::unordered_map<std::string, time_t>                  names_not_found{};
   using lock_and_find_by_name_fn= ttft::lock_and_find_fn<  decltype(users_by_name_mtx), 
                                                            decltype(users_by_name) >;
   lock_and_find_by_name_fn                                 lock_and_find_by_name{  users_by_name_mtx,
                                                                                    users_by_name };


   mutable std::mutex                                       users_by_uuid_mtx{};
   std::unordered_map<t_uuid, size_t>                       users_by_uuid{};
   std::unordered_map<t_uuid, time_t>                       uuids_not_found{};
   using lock_and_find_by_uuid_fn= ttft::lock_and_find_fn<  decltype(users_by_uuid_mtx), 
                                                            decltype(users_by_uuid) >;
   lock_and_find_by_uuid_fn                                 lock_and_find_by_uuid{  users_by_uuid_mtx,
                                                                                    users_by_uuid };


   mutable std::mutex                                       default_user_mtx{};
   size_t                                                   default_user{};
   bool                                                     default_user_loaded{};

    /**
     * @fn get_user_by_id__ 
     * @abstract shared inlined code 
     */
    inline 
    UsersCache::UserStatus  get_user_by_id__(   const user_id_t id,
                                                TitaxUser& copy_buffer ) noexcept {

        const auto user_pos=lock_and_find_by_id(id);

        if ( -1 < user_pos ){

            if (   copyElement(  static_cast<size_t>(user_pos),
                                 copy_buffer) && 

                    copy_buffer.id == id ) {

                        return UserFound;
            }

            //User has been deleted after retrieving the index
            return UserNotLoaded;
        }

        const auto user_not_found = ids_not_found.find(id);
        if ( user_not_found != ids_not_found.end() ) {
            if ( user_not_found->second < time(nullptr) ) {
                ids_not_found.erase(user_not_found);
                return LoadUserNotFound;
            }
            return UserNotFound;
        }

        return UserNotLoaded;
    }


   void resetElement(TitaxUser& user) override {
      (void)zm(&user,sizeof(TitaxUser));
   }

   void deleteActions(TitaxUser& user) override ;

public:
   explicit UsersCache(const size_t size) noexcept : TitanCache<TitaxUser>(size) {

      if (size){
        if ( auto r_=static_cast<size_t>(size * 0.25) ){
            reserve_all(r_);
        }
      }
   }

   bool setListType(const uint32_t) noexcept;

   inline 
   const UsersListType & getListType() const noexcept {
        return list_type;
   }

   bool load_default_info(TitaxUser& copy_buffer);

   inline 
   bool isUserLoaded(const user_id_t id) const noexcept {

      return ( -1< lock_and_find_by_id(id) );

   }

   UserStatus get_user_by_id(const user_id_t id, TitaxUser& copy_buffer);
   /**
    * @fn get_user_by_location
    * @param loc[in] location_t (const ref)
    * @param user[in/out] TitaxUser (ref out)
    * @return UserStatus
    */
   UserStatus get_user_by_location(const titan_v3::locations::location_t &, TitaxUser&);

   UserStatus find_user_by_name_utf8(const std::string& name, TitaxUser& copy_buffer);

   void addUser(const TitaxUser& new_user);

   inline 
   void reserve_all( const size_t r_ ) noexcept {
      users_by_id.reserve(r_);
      users_being_added.reserve(r_);
      ids_not_found.reserve(r_);
      users_by_name.reserve(r_);
      names_not_found.reserve(r_);
      users_by_uuid.reserve(r_);
      uuids_not_found.reserve(r_);
   }

   inline 
   void rehash_all( const size_t r_ ) noexcept {
      users_by_id.rehash(r_);
      users_being_added.rehash(r_);
      ids_not_found.rehash(r_);
      users_by_name.rehash(r_);
      names_not_found.rehash(r_);
      users_by_uuid.rehash(r_);
      uuids_not_found.rehash(r_);
   }

   inline
   void removeUserById(const user_id_t id) noexcept {

      const auto user_pos=lock_and_find_by_id(id);

      if ( -1<user_pos )
         deleteElement( static_cast<size_t>(user_pos) );

   }

   template < typename U>
   inline void updateUsers( U && updates ) noexcept 
   {

      for ( auto && update : updates ) {

         const auto user_pos = lock_and_find_by_id(update.first);

         if ( -1 < user_pos ){

            auto update_policies = [&](TitaxUser& user) {

               if ( update.first == user.id ) {

                  user.policy_info = std::move(update.second);
               }
            };

            updateElement( static_cast<unsigned int>(user_pos), update_policies  );
         }

      }

   }


   inline
   void markIdAsNotFound(const user_id_t id) noexcept
   {
      std::lock_guard<std::mutex> id_lock{users_by_id_mtx};

      ids_not_found[id] = ( USER_TTL + time(nullptr) );
   }

   inline 
   void markNameAsNotFound(const std::string& name) noexcept 
   {
      std::lock_guard<std::mutex> name_lock(users_by_name_mtx);

      names_not_found[name] = ( USER_TTL + time(nullptr) );
   }

   void updateBandwidth(const user_id_t, const size_t);

   void updateTokensCount(const user_id_t, const size_t );

   void resetUsersBandwidth() noexcept  {

      auto reset_bw = [&](TitaxUser& user) {
         user.downloaded_byte = 0;
      };

      updateAllElements(reset_bw);
   }

   inline 
   void cleanUsers() noexcept {
        this->reloadCache();
   }

   void synchronize(PGconn* const db);
};

extern Receiver     db_receiver;
extern UsersCache*  users_cache;

/**
 * @fn init_users_cache
 * @param size[in]: size_t
 */
void init_users_cache(const size_t);

/**
 * @fn destroy_users_cache
 */
void destroy_users_cache();

/**
 * @fn set_list_type
 * @param type[in]: int
 */
extern "C" bool set_list_type(const uint32_t);

/**
 * @fn add_user_to_cache
 * @param user[in]: const ptr TitaxUser
 */
extern "C" void add_user_to_cache(TitaxUser* const);

/**
 * @fn update_tokens_count
 * @param user_id[in]: size_t
 * @param TXTokens_Count[in]: size_t
 */
extern "C" void update_tokens_count(const user_id_t , const size_t);

/**
 * @fn clean_users
 */
extern "C" void clean_users(void);

/**
 * @fn reset_users_bw
 */
extern "C" void reset_users_bw(void);
/**
 * @fn user_cache_reserve
 */
extern "C" void user_cache_reserve(const size_t);

/**
 * @fn user_cache_rehash
 */
extern "C" void user_cache_rehash(const size_t);

#endif /* TITANUSER_H_ */
