/*
 * $Id$
 */

#ifndef DBUSERREQUESTTASK_H_
#define DBUSERREQUESTTASK_H_

#include <string>

#include "edgepq.h"
#include "RequestTask.hxx"
#include "TitaxUser.h"
#include "ttn_locations.hxx"



class UserContext : public RequestContext {
public:
   static constexpr const char * const user_query=             "select id, name, fullname, domain, md5, "
                                                               "blockpage_tokens_count, parent_id, lic_no, "
                                                               "uuid_str, default_flag from v_users ";

   static constexpr const char * const policies_query=         "select user_id, group_id, policy_id, inherited from "
                                                               "effective_policies where user_id ";

   static constexpr const char * const users_bandwidth_query=  "select user_id, downloaded_byte from "
                                                               "usersbandwidth where user_id ";

protected:
   TitaxUser parent{};
   TitaxUser child{};
public:

   inline 
   void copy_data(TitaxUser& parent_buf, TitaxUser& child_buf)const{
      parent_buf = this->parent;
      child_buf =  this->child;
   }

   /**
    * Diagnostic Instrumentation 
    * TODO: consider use of macros 
    */
   UserContext() noexcept;
   virtual ~UserContext();

   inline
   void dump_idetifying_info( std::ostream & a_os)const{
      a_os << "parent.name [" << this->parent.name << "] child.name [" << this->child.name << ']'<<std::endl;
   }

 };

/**
 * @abstract task to fetch a parent from the db by name
 */
class UserFromIp : public UserContext {
   const titan_v3::locations::location_t loc_{};

public:
   explicit UserFromIp(const titan_v3::locations::location_t & _loc) noexcept : loc_{_loc} /*cpy*/ {}
   explicit UserFromIp(titan_v3::locations::location_t && _loc) noexcept : loc_{std::move(_loc)} /*move*/ {}

   void execute(SchedulerContext & sch_context) noexcept override;
};

/**
 * @abstract task to fetch a parent from the db by name
 */
class UserByName : public UserContext {
   std::string name{};
   std::string domains{};

   public:
   template <typename U>
   explicit constexpr UserByName(U && user_name) noexcept : name{std::forward<U>(user_name)} {}

   template <typename U, typename D>
   explicit constexpr UserByName(U&& user_name, D&& domain_list) noexcept : name{std::forward<U>(user_name)}, domains{std::forward<D>(domain_list)} {}

   void execute(SchedulerContext & sch_context) noexcept override;
};

/**
 * @abstract task to fetch a parent from the db by id
 */
class UserParent : public UserContext {
protected:
   const size_t parent_id{};

public:
   explicit UserParent(const size_t id) noexcept : parent_id{id} {}

   void execute(SchedulerContext & sch_context) noexcept override;
};

/**
 * @abstract task to fetch a user from the db by id
 */
class UserById : public UserParent {
   const size_t user_id{};

public:
   explicit UserById(   const size_t uid,
                        const size_t pid  ) noexcept :   UserParent{pid}, 
                                                         user_id{uid}{}

   void execute(SchedulerContext &sch_context) noexcept override;
};

#ifdef TTN_ATESTS

extern bool exec_policies_query_4tests(   PGconn* const,
                                          const std::string &,
                                          TitaxUser * const, 
                                          TitaxUser * const=nullptr  ) noexcept;

extern bool exec_policies_query_both_4tests( PGconn* const,
                                             const std::string &,
                                             TitaxUser * const, 
                                             TitaxUser * const    ) noexcept;
#endif

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation
 * TODO: consider use of macros
 */
 titan_instance_tracker *get_titan_instance_tracker_UserContext();
 void print_tracked_UserContext( void *a_p, std::ostream & a_s);
 void Check_tracker_UserContext( std::ostream & a_os, uint32_t a_older_than_secs);

#endif /* DBUSERREQUESTTASK_H_ */
