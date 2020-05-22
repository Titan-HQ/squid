/*
 * Based on ACLProxyAuth form the squid
 * $Id: AclTitanAuth.h 10775 2014-11-27 11:35:58Z dawidw $
 */

#ifndef SQUID_ACLTITANAUTH_H
#define SQUID_ACLTITANAUTH_H

#if USE_AUTH

#include <iostream>
#include "HttpRequest.h"
#include "acl/Acl.h"
#include "acl/Data.h"
#include "acl/Checklist.h"
#include "RequestTask.hxx"
#include "TAPE.hxx"

//move squid independent code to the titan namespace and to the library
class TitanAuthLookup : public ACLChecklist::AsyncState
{

public:
    static TitanAuthLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static TitanAuthLookup instance_;
    static void LookupDone(void *data);
};

class TitanDbLookup : public ACLChecklist::AsyncState
{

public:
    static TitanDbLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static TitanDbLookup instance_;
    static void LookupDone( RequestTask & );
};


class ACLTitanAuth : public ACL
{

public:
    MEMPROXY_CLASS(ACLTitanAuth);

    ~ACLTitanAuth();
    ACLTitanAuth(ACLData<char const *> *, char const *);
    ACLTitanAuth (ACLTitanAuth const &);
    ACLTitanAuth &operator= (ACLTitanAuth const &);

    virtual char const *typeString() const;
    virtual void parse();
	 virtual bool isTitanAuth() const {return true;}
	 virtual bool isProxyAuth() const {return true;}
	
    virtual int match(ACLChecklist *checklist);
    virtual SBufList dump() const;
    virtual bool valid () const;
    virtual bool empty () const;
    virtual bool requiresRequest() const {return true;}

    virtual ACL *clone() const;
    virtual int matchForCache(ACLChecklist *checklist);

    ACLFilledChecklist * _fcl;
private:
    static Prototype UserRegistryProtoype;
    static ACLTitanAuth UserRegistryEntry_;
    static Prototype RegexRegistryProtoype;
    static ACLTitanAuth RegexRegistryEntry_;
    int matchTitanAuth(ACLChecklist *);
    ACLData<char const *> *data;
    char const *type_;
};

MEMPROXY_CLASS_INLINE(ACLTitanAuth);

#endif /* USE_AUTH */
#endif /* SQUID_ACLTITANAUTH_H */
