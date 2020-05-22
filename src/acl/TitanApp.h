/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLTitanApp_H
#define SQUID_ACLTitanApp_H
#include "acl/Checklist.h"
#include "acl/Ip.h"
#include "base/AsyncJob.h"
#include "ipcache.h"
#include "BodyPipe.h"
#include "client_side.h"
#include "CommCalls.h"
#include "TAPE.hxx"

typedef void (*TITAN_DONE_CB)(void*);

class TitanAppLookup : public ACLChecklist::AsyncState
{

public:
    static TitanAppLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static TitanAppLookup instance_;
    static void LookupDone(void *data);
};

struct TitanAppState {
   ACLFilledChecklist* checklist;
   TITAN_DONE_CB doneHandler;

   TitanAppState(TITAN_DONE_CB handler, ACLFilledChecklist* cl) :
      doneHandler(handler), checklist(cl) {}
};

class TitanAppHandler : public virtual AsyncJob
{
   titan_v3::IHRequest& _ir;
   BodyPipe::Pointer _bp;
   ConnStateData* _csd;
   bool write100Continue;

   CBDATA_CLASS2(TitanAppHandler);

public:
   typedef CbcPointer<TitanAppHandler> Pointer;

   TitanAppHandler(titan_v3::IHRequest& ir, BodyPipe::Pointer bp, ConnStateData* csd) :
      AsyncJob("TitanAppHandler"), _ir(ir), _bp(bp), _csd(csd), write100Continue(false) {}

   void noteMoreDataAvailable(const CommIoCbParams &io, TitanAppState*const state);

   void writeCompleted(const CommIoCbParams &io, TitanAppState* const state);

   void setWrite100Continue(void) { write100Continue = true; }

   bool getWrite100Continue(void)const { return write100Continue; }

   void doWrite100Continue(TitanAppState* const state);

   bool processReadData(void);

   void readMoreData(TitanAppState* const state);

   virtual bool doneAll() const { return false; }
};


class TitanAppDialer : public JobDialer<TitanAppHandler>, public CommDialerParamsT<CommIoCbParams>
{
   TitanAppState* _state;

protected:
    virtual void doDial() { ((&(*this->job))->*method)(this->params, _state); }

public:
   typedef void (TitanAppHandler::*Method)(const CommIoCbParams &io, TitanAppState* const state);

   Method method;

   TitanAppDialer(const CbcPointer<TitanAppHandler> &aJob, Method aMeth, TitanAppState* const state):
      JobDialer<TitanAppHandler>(aJob),
      CommDialerParamsT<CommIoCbParams>(aJob->toCbdata()),
      method(aMeth),
      _state(state) {
   }

   virtual bool canDial(AsyncCall &c) {
       return JobDialer<TitanAppHandler>::canDial(c) &&
              this->params.syncWithComm();
   }

   virtual void print(std::ostream &os) const {
       os << '(';
       this->params.print(os);
       os << ')';
   }
};


class ACLTitanApp : public ACL
{

public:
    MEMPROXY_CLASS(ACLTitanApp);

    ~ACLTitanApp() {};
    ACLTitanApp(char const *);
    ACLTitanApp (ACLTitanApp const &);
    ACLTitanApp &operator= (ACLTitanApp const &);

    virtual void parse() {}
    virtual char const *typeString() const;
    virtual int match(ACLChecklist *checklist);

    virtual SBufList dump() const;
    virtual bool empty () const;
    virtual ACL *clone()const;

private:
    static Prototype RegistryProtoype;
    static ACLTitanApp RegistryEntry_;

    char const *type_;
};

MEMPROXY_CLASS_INLINE(ACLTitanApp);

#endif /* SQUID_ACLTitanApp_H */

