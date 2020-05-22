/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "auth/kshield/Config.h"
#include "auth/kshield/User.h"
#include "Debug.h"
#include "SquidConfig.h"
#include "SquidTime.h"

Auth::Kshield::User::User(Auth::Config *aConfig, const char *aRequestRealm) :
    Auth::User(aConfig, aRequestRealm),
    user(NULL),
    queue(NULL)
{}

Auth::Kshield::User::~User()
{
    safe_free(user);
}

int32_t
Auth::Kshield::User::ttl() const
{
    if (credentials() != Auth::Ok && credentials() != Auth::Pending)
        return -1; // TTL is obsolete NOW.

    int32_t basic_ttl = expiretime - squid_curtime + static_cast<Auth::Kshield::Config*>(config)->credentialsTTL;
    int32_t global_ttl = static_cast<int32_t>(expiretime - squid_curtime + ::Config.authenticateTTL);

    return min(basic_ttl, global_ttl);
}

bool
Auth::Kshield::User::authenticated() const
{
    if ((credentials() == Auth::Ok) && (expiretime + static_cast<Auth::Kshield::Config*>(config)->credentialsTTL > squid_curtime))
        return true;

    debugs(29, 4, "User not authenticated or credentials need rechecking.");

    return false;
}

bool
Auth::Kshield::User::valid() const
{
    if (username() == NULL)
        return false;
    return true;
}

