/*
 * Copyright (C) 1996-2015 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_ACLTitanCloud_H
#define SQUID_ACLTitanCloud_H
#include "acl/Checklist.h"

class TitanCloudLookup : public ACLChecklist::AsyncState
{

public:
    static TitanCloudLookup *Instance();
    virtual void checkForAsync(ACLChecklist *)const;

private:
    static TitanCloudLookup instance_;
    static void LookupDone( RequestTask & );
};

class ACLTitanCloud : public ACL
{

public:
    MEMPROXY_CLASS(ACLTitanCloud);

    ~ACLTitanCloud() {};
    ACLTitanCloud(char const *);
    ACLTitanCloud (ACLTitanCloud const &);
    ACLTitanCloud &operator= (ACLTitanCloud const &);

    virtual void parse() {}
    virtual char const *typeString() const;
    virtual int match(ACLChecklist *checklist);

    virtual SBufList dump() const;
    virtual bool empty () const;
    virtual ACL *clone()const;

private:
    static Prototype RegistryProtoype;
    static ACLTitanCloud RegistryEntry_;

    char const *type_;
};

MEMPROXY_CLASS_INLINE(ACLTitanCloud);

#endif /* SQUID_ACLTitanCloud_H */

