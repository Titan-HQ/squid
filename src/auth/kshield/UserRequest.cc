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
#include "auth/kshield/UserRequest.h"
#include "auth/QueueNode.h"
#include "auth/State.h"
#include "charset.h"
#include "Debug.h"
#include "format/Format.h"
#include "helper.h"
#include "helper/Reply.h"
#include "HttpMsg.h"
#include "HttpRequest.h"
#include "MemBuf.h"
#include "rfc1738.h"
#include "SquidTime.h"

#if !defined(HELPER_INPUT_BUFFER)
#define HELPER_INPUT_BUFFER  8192
#endif

int
Auth::Kshield::UserRequest::authenticated() const
{
    Auth::Kshield::User const *kshield_auth = dynamic_cast<Auth::Kshield::User const *>(user().getRaw());

    if (kshield_auth && kshield_auth->authenticated())
        return 1;

    return 0;
}

const char *
Auth::Kshield::UserRequest::credentialsStr()
{
    Auth::Kshield::User const *kshield_auth = dynamic_cast<Auth::Kshield::User const *>(user().getRaw());
    if (kshield_auth)
        return kshield_auth->username();
    return NULL;
}

/* log a basic user in
 */
void
Auth::Kshield::UserRequest::authenticate(HttpRequest * request, ConnStateData * conn, http_hdr_type type)
{
    assert(user() != NULL);

    /* if the password is not ok, do an identity */
    if (!user() || user()->credentials() != Auth::Ok)
        return;

    /* are we about to recheck the credentials externally? */
    if ((user()->expiretime + static_cast<Auth::Kshield::Config*>(Auth::Config::Find("kshield"))->credentialsTTL) <= squid_curtime) {
        debugs(29, 4, HERE << "credentials expired - rechecking");
        return;
    }

    /* we have been through the external helper, and the credentials haven't expired */
    debugs(29, 9, HERE << "user '" << user()->username() << "' authenticated");

    /* Decode now takes care of finding the AuthUser struct in the cache */
    /* after external auth occurs anyway */
    user()->expiretime = current_time.tv_sec;

    return;
}

Auth::Direction
Auth::Kshield::UserRequest::module_direction()
{
    /* null auth_user is checked for by Auth::UserRequest::direction() */
    if (user()->auth_type != Auth::AUTH_KSHIELD)
        return Auth::CRED_ERROR;

    switch (user()->credentials()) {
    case Auth::Ok:
        if (user()->expiretime + static_cast<Auth::Kshield::Config*>(Auth::Config::Find("kshield"))->credentialsTTL <= squid_curtime)
            return Auth::CRED_LOOKUP;
        return Auth::CRED_VALID;

    case Auth::Unchecked:
    case Auth::Pending:
       return Auth::CRED_LOOKUP;

    case Auth::Failed:
    default:
        return Auth::CRED_ERROR;
    }
}

/* send the initial data to a basic authenticator module */
void
Auth::Kshield::UserRequest::startHelperLookup(HttpRequest *request, AccessLogEntry::Pointer &al, AUTHCB * handler, void *data)
{
    Auth::Kshield::User *kshield_auth = dynamic_cast<Auth::Kshield::User *>(user().getRaw());
    if (static_cast<Auth::Kshield::Config*>(Auth::Config::Find("kshield"))->authenticateProgram == NULL) {
        debugs(29, DBG_CRITICAL, "ERROR: No Kshield authentication program configured.");
        handler(data);
        return;
    }


    /* check to see if the auth_user already has a request outstanding */
    if (user()->credentials() == Auth::Pending) {
        /* there is a request with the same credentials already being verified */

        Auth::QueueNode *node = new Auth::QueueNode(this, handler, data);

        /* queue this validation request to be informed of the pending lookup results */
        node->next = kshield_auth->queue;
        kshield_auth->queue = node;
        return;
    }
    // otherwise submit this request to the auth helper(s) for validation

    /* mark this user as having verification in progress */
    user()->credentials(Auth::Pending);
    char buf[HELPER_INPUT_BUFFER];

    snprintf(buf, sizeof(buf), "%s\n", request->client_addr.toStr(buf,HELPER_INPUT_BUFFER));

    helperSubmit(kshield_authenticators, buf, Auth::Kshield::UserRequest::HandleReply,
                    new Auth::StateData(this, handler, data));
}

void
Auth::Kshield::UserRequest::HandleReply(void *data, const Helper::Reply &reply)
{
    Auth::StateData *r = static_cast<Auth::StateData *>(data);
    void *cbdata;
    debugs(29, 5, HERE << "reply=" << reply);

    assert(r->auth_user_request != NULL);
    assert(r->auth_user_request->user()->auth_type == Auth::AUTH_KSHIELD);

    // add new helper kv-pair notes to the credentials object
    // so that any transaction using those credentials can access them
    r->auth_user_request->user()->notes.appendNewOnly(&reply.notes);

    /* this is okay since we only play with the Auth::Kshield::User child fields below
     * and dont pass the pointer itself anywhere */
    Auth::Kshield::User *kshield_auth = dynamic_cast<Auth::Kshield::User *>(r->auth_user_request->user().getRaw());

    assert(kshield_auth != NULL);

    if (reply.result == Helper::Okay) {
        kshield_auth->credentials(Auth::Ok);
        const char *userLabel = reply.notes.findFirst("user");
        if (userLabel) {
           kshield_auth->user = xstrdup(userLabel);
           r->auth_user_request->denyMessage("Login successful");
        } else {
           kshield_auth->credentials(Auth::Failed);
           r->auth_user_request->denyMessage("KSHIELD Authentication helper returned no username");
           debugs(29, DBG_CRITICAL, "ERROR: KSHIELD Authentication helper returned no username. Result: " << reply);
        }
    }
    else {
        kshield_auth->credentials(Auth::Failed);

        if (reply.other().hasContent())
            r->auth_user_request->setDenyMessage(reply.other().content());
    }
    kshield_auth->expiretime = squid_curtime;

    if (cbdataReferenceValidDone(r->data, &cbdata))
        r->handler(cbdata);

    cbdataReferenceDone(r->data);

    while (kshield_auth->queue) {
        if (cbdataReferenceValidDone(kshield_auth->queue->data, &cbdata))
           kshield_auth->queue->handler(cbdata);

        Auth::QueueNode *tmpnode = kshield_auth->queue->next;
        kshield_auth->queue->next = NULL;
        delete kshield_auth->queue;

        kshield_auth->queue = tmpnode;
    }

    delete r;
}


char const *
Auth::Kshield::UserRequest::username() const
{
    if (user() != NULL) {
        const Auth::Kshield::User *kshield_auth = dynamic_cast<const Auth::Kshield::User *>(user().getRaw());
        return kshield_auth->user;
    }
    else
        return NULL;
}
