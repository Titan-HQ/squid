/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_AUTH_BASIC_USERREQUEST_H
#define _SQUID_SRC_AUTH_BASIC_USERREQUEST_H

#include "auth/UserRequest.h"
#include "MemPool.h"

class ConnStateData;
class HttpRequest;

namespace Auth
{

namespace Kshield
{

/* follows the http request around */

class UserRequest : public Auth::UserRequest
{
public:
    MEMPROXY_CLASS(Auth::Kshield::UserRequest);

    UserRequest() {}
    virtual ~UserRequest() { assert(LockCount()==0); }

    virtual int authenticated() const;
    virtual void authenticate(HttpRequest * request, ConnStateData *conn, http_hdr_type type);
    virtual Auth::Direction module_direction();
    virtual void startHelperLookup(HttpRequest * request, AccessLogEntry::Pointer &al, AUTHCB *, void *);
    virtual const char *credentialsStr();

    virtual char const *username() const;

private:
    static HLPCB HandleReply;
};

} // namespace Basic
} // namespace Auth

MEMPROXY_CLASS_INLINE(Auth::Kshield::UserRequest);

#endif /* _SQUID_SRC_AUTH_BASIC_USERREQUEST_H */

