/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AsyncCall.h"
#include "base/AsyncCall.h"
#include "base/AsyncCallQueue.h"
#include "cbdata.h"
#include "Debug.h"
#include <ostream>

InstanceIdDefinitions(AsyncCall, "call");

/* AsyncCall */

AsyncCall::AsyncCall(int aDebugSection, int aDebugLevel,
                     const char *aName): name(aName), debugSection(aDebugSection),
    debugLevel(aDebugLevel), theNext(0), isCanceled(NULL)
{
    debugs(debugSection, debugLevel, "The AsyncCall " << name << " constructed, this=" << this <<
           " [" << id << ']');
}

AsyncCall::~AsyncCall()
{
   //assert(!theNext); // AsyncCallQueue must clean
    //Titan start
   debugs(debugSection, debugLevel, HERE << dump());
   while (theNext!=NULL) {
      //cleanup the queue
      AsyncCall::Pointer call = theNext;
      theNext = call->Next();
      call->setNext(NULL);
      try{
          //!call->canceled() && call->cancel("AsyncCall::~AsyncCall");
          debugs(debugSection, DBG_CRITICAL, HERE << "::{theNext call is not empty}::" << call->dump());
          (void)(!call->canceled() && ScheduleCallHere(call));
      }catch(...){      /*std::abort is called if destructors throw*/
         call->cancel("AsyncCall::~AsyncCall::Exception");
      }
  };
  //Titan end
}

void
AsyncCall::make()
{
    debugs(debugSection, debugLevel, HERE << "make call " << name <<
           " [" << id << ']');
    if (canFire()) {
        fire();
        return;
    }

    if (!isCanceled) // we did not cancel() when returning false from canFire()
        isCanceled = "unknown reason";

    debugs(debugSection, debugLevel, HERE << "will not call " << name <<
           " [" << id << ']' << " because of " << isCanceled);
}

bool
AsyncCall::cancel(const char *reason)
{
    debugs(debugSection, debugLevel, HERE << "will not call " << name <<
           " [" << id << "] " << (isCanceled ? "also " : "") <<
           "because " << reason);

    isCanceled = reason;
    return false;
}

bool
AsyncCall::canFire()
{
    return !isCanceled;
}

/// \todo make this method const by providing a const getDialer()
void
AsyncCall::print(std::ostream &os)
{
    os << name;
    if (const CallDialer *dialer = getDialer())
        dialer->print(os);
    else
        os << "(?" << this << "?)";
}

std::string AsyncCall::dump(void){
   std::stringstream    _ss;
   _ss<<this;
   return _ss.str();
}

void
AsyncCall::dequeue(AsyncCall::Pointer &head, AsyncCall::Pointer &prev)
{
    if (prev != NULL)
        prev->setNext(Next());
    else
        head = Next();
    setNext(NULL);
}

bool
ScheduleCall(const char *fileName, int fileLine, AsyncCall::Pointer &call)
{
    debugs(call->debugSection, call->debugLevel, fileName << "(" << fileLine <<
           ") will call " << *call << " [" << call->id << ']' );
    AsyncCallQueue::Instance().schedule(call);
    return true;
}

