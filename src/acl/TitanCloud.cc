/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "HttpRequest.h"
#include "TAPE.hxx"
#include "TitanSchedulerAPI.hxx"
#include "TitanUser.hxx"
#include "acl/FilledChecklist.h"
#include "acl/TitanCloud.h"

using namespace titan_v3;

ACLTitanCloud::ACLTitanCloud(char const* type) :
   type_(type) {}

ACLTitanCloud::ACLTitanCloud (ACLTitanCloud const &old) : type_(old.type_)
{}

ACLTitanCloud &
ACLTitanCloud::operator= (ACLTitanCloud const &rhs)
{
    type_ = rhs.type_;
    return *this;
}

char const *
ACLTitanCloud::typeString() const
{
    return type_;
}

int
ACLTitanCloud::match(ACLChecklist *cl)
{
   ACLFilledChecklist *_fcl = Filled(cl);

   if (!_fcl || !_fcl->request) {
      //assert( false && "outch we shouldn't be here !!!");
      return 0;
   }

   HttpRequest& _ir = *_fcl->request;

   //Workaround to avoid that google domains are changed to forcesafesearch.google.com
   //This problem will be solved when redirection sets are implemented.
   if (strncasecmp(_ir.GetHost(), _ir.orig_host.c_str(), _ir.orig_host.size()) != 0) {
      _ir.set_host(_ir.orig_host);
   }

   //Cloud requests are not logged in the proxy.
   _ir.get_flags().ttn_has_been_logged = true;
   if (!_ir.ttag.user_found()) {

      const auto & cidr_stat = cidr::factory::make_cidr( _ir.get_client_addr() );

      if ( cidr_stat.second ) { 

         bool found = GTAPE.fetchIdentity(   _ir, 
                                             titan_v3::search_identity_by::ip,
                                             cidr_stat.first                     );

         if (!found && _ir.ttag.isScheduledContextSet()) {

            if (cl->goAsync(TitanCloudLookup::Instance())) {

               return -1;
            }
         }
      }
      else 
         return 0;
   }

   return 1;
}

TitanCloudLookup TitanCloudLookup::instance_;

TitanCloudLookup *
TitanCloudLookup::Instance()
{
    return &instance_;
}


void
TitanCloudLookup::checkForAsync(ACLChecklist *cl) const
{
   if (ACLFilledChecklist *checklist = Filled(cl)){
      if (checklist->request->ttag.isScheduledContextSet())
      {
         fetchUserFromDb( checklist->request->ttag.getScheduledContext(),
                          LookupDone,
                          checklist,
                          &db_receiver);
         return;
      };
      throw tools::errors::context_is_null();
   };
}


void
TitanCloudLookup::LookupDone( RequestTask & rq )
{
    void * data = rq.getCallback_data();
    if ( data )
    {
       auto ctx=rq.getRequestContext();
       if (ctx){
            ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));
            /* move ownership of the ctx */
            checklist->request->ttag.setScheduledContext(std::move(ctx));
            checklist->request->ttag.copy_scheduled_data();
            checklist->resumeNonBlockingCheck(TitanCloudLookup::Instance());
       };
    };
}

SBufList
ACLTitanCloud::dump() const
{
    SBufList sl;
    return sl;
}

bool
ACLTitanCloud::empty() const
{
    return false;
}

ACL *
ACLTitanCloud::clone() const
{
    return new ACLTitanCloud(*this);
}

