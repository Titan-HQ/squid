/*
 * DEBUG: section 28    Access Control
 * Based on ACLProxyAuth form the squid
 * $Id: AclTitanAuth.cc 10972 2015-01-12 09:57:29Z jmanteiga $
 */
#include "squid.h"
#include "auth/AclTitanAuth.h"
#include <algorithm>
#include <ctime>
#include <iostream>
#include <string>

#include <mutex>
#include <thread>

#include "HttpRequest.h"
#include "acl/FilledChecklist.h"
#include "acl/RegexData.h"
#include "acl/UserData.h"
#include "auth/Acl.h"
#include "auth/Gadgets.h"
#include "auth/User.h"
#include "auth/UserRequest.h"
#include "client_side.h"
#include "fde.h"
#include <cstdlib>

#include "TAPE.hxx"
#include "TitanSchedulerAPI.hxx"
#include "TitanUser.hxx"
#include "ttn_errors.hxx"


using namespace titan_v3;

ACLTitanAuth::~ACLTitanAuth()
{
    delete data;
}

ACLTitanAuth::ACLTitanAuth(ACLData<char const *> *newData, char const *theType) : data (newData), type_(theType),_fcl(nullptr) {}

ACLTitanAuth::ACLTitanAuth (ACLTitanAuth const &old) : data (old.data->clone()), type_(old.type_), _fcl(nullptr)
{}

ACLTitanAuth &
ACLTitanAuth::operator= (ACLTitanAuth const &rhs)
{
    data = rhs.data->clone();
    type_ = rhs.type_;
    return *this;
}

char const *
ACLTitanAuth::typeString() const
{
    return type_;
}

void
ACLTitanAuth::parse()
{
    data->parse();
}

static request_state check_authentication(IACLChecklist * const  alist){
   switch (AuthenticateAcl(static_cast<ACLChecklist*const>(alist))){
      case ACCESS_DENIED: return (request_state::deny);
      case ACCESS_ALLOWED: return (request_state::allow);
      case ACCESS_AUTH_REQUIRED: return (request_state::auth_req);
      default:return (request_state::dunno);
   };
}

int
ACLTitanAuth::match(ACLChecklist *checklist){

   if ((this->_fcl=Filled(checklist)) && this->_fcl->request){
      request_state state;
      IHRequest& _ir = *this->_fcl->request;
      _ir.ttag.clearScheduledContext();

      switch (_ir.processing_step) {
      case 0:
         state = GTAPE.matchACL(_ir, checklist, &check_authentication);
         break;
      case 1:
         state = GTAPE.matchACLCheckAuth(_ir, checklist, &check_authentication);
         break;
      case 2:
         //When this point is reached, previous state is always allow.
         state = GTAPE.matchACLCheckAnswer(_ir, checklist, request_state::allow);
         break;
      }

      if (state == request_state::read_sched) {
         if (checklist->goAsync(TitanDbLookup::Instance())) {
            return -1;
         }
         else {
            return 0;
         }
      }
      else {
         return (int) state;
      }
   }

   assert( false && "ACLTitanAuth::match::failed:@c1");   
}

SBufList
ACLTitanAuth::dump() const
{
    return data->dump();
}

bool
ACLTitanAuth::empty () const
{
    return data->empty();
}

bool
ACLTitanAuth::valid () const
{
    if (authenticateSchemeCount() == 0) {
        debugs(28, DBG_CRITICAL, "Can't use titan auth because no authentication schemes were compiled.");
        return false;
    }

    if (authenticateActiveSchemeCount() == 0) {
        debugs(28, DBG_CRITICAL, "Can't use titan auth because no authentication schemes are fully configured.");
        return false;
    }

    return true;
}

TitanAuthLookup TitanAuthLookup::instance_;

TitanAuthLookup *
TitanAuthLookup::Instance()
{
    return &instance_;
}

void
TitanAuthLookup::checkForAsync(ACLChecklist *cl) const
{
    ACLFilledChecklist *checklist = Filled(cl);

    debugs(28, 3, HERE << "checking password via authenticator");

    //This is an authentication request
    assert(checklist->auth_user_request != NULL);
    assert(checklist->auth_user_request->valid());
    checklist->auth_user_request->start(checklist->request, checklist->al, LookupDone, checklist);
}

void
TitanAuthLookup::LookupDone(void *data)
{
    ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));

    if (checklist->auth_user_request == NULL || !checklist->auth_user_request->valid() || checklist->conn() == NULL) {
        /* credentials could not be checked either way
         * restart the whole process */
        /* OR the connection was closed, there's no way to continue */
        checklist->auth_user_request = NULL;

        if (checklist->conn() != NULL) {
            checklist->conn()->setAuth(NULL, "titan_auth ACL failure");
        }
    }

    checklist->resumeNonBlockingCheck(TitanAuthLookup::Instance());
}


TitanDbLookup TitanDbLookup::instance_;

TitanDbLookup *
TitanDbLookup::Instance()
{
    return &instance_;
}

void
TitanDbLookup::checkForAsync(ACLChecklist *cl) const
{
   if (ACLFilledChecklist *checklist = Filled(cl)){
      if (checklist->request->ttag.isScheduledContextSet()){
         //This is a request to get a user from the database
         fetchUserFromDb(checklist->request->ttag.getScheduledContext(), LookupDone, checklist, &db_receiver);
         return;
      };
      throw tools::errors::context_is_null();
   };
}

void
TitanDbLookup::LookupDone( RequestTask& rq )
{
    void * data = rq.getCallback_data();
    if ( data )
    {
       auto ctx = rq.getRequestContext();
       if (ctx)
       {
            ACLFilledChecklist *checklist = Filled(static_cast<ACLChecklist*>(data));
            /* move ownership of the ctx */
            checklist->request->ttag.setScheduledContext(std::move(ctx));
            checklist->request->ttag.copy_scheduled_data();
            checklist->resumeNonBlockingCheck(TitanDbLookup::Instance());
       };
    };
}


ACL *
ACLTitanAuth::clone() const
{
    return new ACLTitanAuth(*this);
}

int
ACLTitanAuth::matchForCache(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    assert (checklist->auth_user_request != NULL);
    return data->match(checklist->auth_user_request->username());
}

/* aclMatchTitanAuth can return two exit codes:
 * 0 : Authorisation for this ACL failed. (Did not match)
 * 1 : Authorisation OK. (Matched)
 */
int
ACLTitanAuth::matchTitanAuth(ACLChecklist *cl)
{
    ACLFilledChecklist *checklist = Filled(cl);
    if (checklist->request->flags.sslBumped)
        return 1; // AuthenticateAcl() already handled this bumped request
    if (!authenticateUserAuthenticated(Filled(checklist)->auth_user_request)) {
        return 0;
    }
    /* check to see if we have matched the user-acl before */
    int result = cacheMatchAcl(&checklist->auth_user_request->user()->proxy_match_cache, checklist);
    checklist->auth_user_request = NULL;
    return result;
}



