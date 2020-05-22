/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_AUTH_BASIC_USER_H
#define _SQUID_AUTH_BASIC_USER_H

#include "auth/User.h"
#include "auth/UserRequest.h"

namespace Auth
{

class Config;
class QueueNode;

namespace Kshield
{

/** User credentials for the Basic authentication protocol */
class User : public Auth::User
{
public:
    MEMPROXY_CLASS(Auth::Kshield::User);

    User(Auth::Config *, const char *requestRealm);
    ~User();
    bool authenticated() const;
    bool valid() const;

    virtual int32_t ttl() const;

    char *user;

    QueueNode *queue;
};

MEMPROXY_CLASS_INLINE(Auth::Kshield::User);

} // namespace Basic
} // namespace Auth

#endif /* _SQUID_AUTH_BASIC_USER_H */

