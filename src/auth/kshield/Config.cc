/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 29    Authenticator */

/* The functions in this file handle authentication.
 * They DO NOT perform access control or auditing.
 * See acl.c for access control and client_side.c for auditing */

#include "squid.h"
#include "auth/kshield/Config.h"
#include "auth/kshield/Scheme.h"
#include "auth/kshield/User.h"
#include "auth/kshield/UserRequest.h"
#include "auth/Gadgets.h"
#include "auth/State.h"
#include "cache_cf.h"
#include "charset.h"
#include "helper.h"
#include "HttpHeaderTools.h"
#include "HttpReply.h"
#include "mgr/Registration.h"
#include "rfc1738.h"
#include "SquidTime.h"
#include "Store.h"
#include "uudecode.h"
#include "wordlist.h"

/* Basic Scheme */
static AUTHSSTATS authenticateKshieldStats;

helper *kshield_authenticators = NULL;

static int kshield_initialised = 0;

/*
 *
 * Public Functions
 *
 */

/* internal functions */

bool
Auth::Kshield::Config::active() const
{
    return kshield_initialised == 1;
}

bool
Auth::Kshield::Config::configured() const
{
    if ((authenticateProgram != NULL) && (authenticateChildren.n_max != 0)) {
        debugs(29, 9, HERE << "returning configured");
        return true;
    }

    debugs(29, 9, HERE << "returning unconfigured");
    return false;
}

const char *
Auth::Kshield::Config::type() const
{
    return Auth::Kshield::Scheme::GetInstance()->type();
}

void
Auth::Kshield::Config::fixHeader(Auth::UserRequest::Pointer auth_user_request, HttpReply *rep, http_hdr_type hdrType, HttpRequest * request)
{
   //Do nothing as no authentication message is sent to the client.
}

void
Auth::Kshield::Config::rotateHelpers()
{
    /* schedule closure of existing helpers */
    if (kshield_authenticators) {
        helperShutdown(kshield_authenticators);
    }

    /* NP: dynamic helper restart will ensure they start up again as needed. */
}

/** shutdown the auth helpers and free any allocated configuration details */
void
Auth::Kshield::Config::done()
{
    Auth::Config::done();

    kshield_initialised = 0;

    if (kshield_authenticators) {
        helperShutdown(kshield_authenticators);
    }

    delete kshield_authenticators;
    kshield_authenticators = NULL;

    if (authenticateProgram)
        wordlistDestroy(&authenticateProgram);
}

bool
Auth::Kshield::Config::dump(StoreEntry * entry, const char *name, Auth::Config * scheme) const
{
    if (!Auth::Config::dump(entry, name, scheme))
        return false; // not configured

    storeAppendPrintf(entry, "%s basic credentialsttl %d seconds\n", name, (int) credentialsTTL);
    return true;
}

Auth::Kshield::Config::Config() :
    credentialsTTL( 2*60*60 )
{
    static const SBuf defaultRealm("Squid proxy-caching web server");
    realm = defaultRealm;
}

void
Auth::Kshield::Config::parse(Auth::Config * scheme, int n_configured, char *param_str)
{
    if (strcmp(param_str, "credentialsttl") == 0) {
        parse_time_t(&credentialsTTL);
    } else
        Auth::Config::parse(scheme, n_configured, param_str);
}

static void
authenticateKshieldStats(StoreEntry * sentry)
{
    helperStats(sentry, kshield_authenticators, "Kshield Authenticator Statistics");
}


/**
 * KShield does not receive any [Proxy-]Auth string. It just returns a new auth_user_request.
 */
Auth::UserRequest::Pointer
Auth::Kshield::Config::decode(char const *proxy_auth, const char *aRequestRealm)
{
   Auth::UserRequest::Pointer auth_user_request = new Auth::Kshield::UserRequest();
   Auth::User::Pointer auth_user;

   if ((auth_user = findUserInCache(proxy_auth, Auth::AUTH_KSHIELD)) == NULL) {
       Auth::Kshield::User *new_user = new Auth::Kshield::User(Auth::Config::Find("kshield"), aRequestRealm);
       new_user->auth_type = Auth::AUTH_KSHIELD;
       new_user->username(proxy_auth);
       new_user->expiretime = current_time.tv_sec;
       new_user->addToNameCache();
       auth_user_request->user(new_user);
   } else {
       /* replace the current cached password with the new one */
       if (auth_user->credentials() == Auth::Failed) {
          auth_user->credentials(Auth::Unchecked);
       }
       auth_user_request->user(auth_user);
   }

   /* all we have to do is identify that it's NTLM - the helper does the rest */
   debugs(29, 9, HERE << "decode: Kshield authentication");
   return auth_user_request;
}

/** Initialize helpers and the like for this auth scheme. Called AFTER parsing the
 * config file */
void
Auth::Kshield::Config::init(Auth::Config * schemeCfg)
{
    if (authenticateProgram) {
       kshield_initialised = 1;

        if (kshield_authenticators == NULL)
           kshield_authenticators = new helper("kshield_authenticator");

        kshield_authenticators->cmdline = authenticateProgram;

        kshield_authenticators->childs.updateLimits(authenticateChildren);

        kshield_authenticators->ipc_type = IPC_STREAM;

        helperOpenServers(kshield_authenticators);
    }
}

void
Auth::Kshield::Config::registerWithCacheManager(void)
{
    Mgr::RegisterAction("kshield_authenticator",
                        "Kshield User Authenticator Stats",
                        authenticateKshieldStats, 0, 1);
}

