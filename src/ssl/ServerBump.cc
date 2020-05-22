/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 33    Client-side Routines */

#include "squid.h"

#include "client_side.h"
#include "FwdState.h"
#include "globals.h"
#include "ssl/ServerBump.h"
#include "Store.h"
#include "StoreClient.h"
#include "URL.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, ServerBump);

//temporary change to add more traceability
static uint64_t _ctx=0;

Ssl::ServerBump::ServerBump(HttpRequest *fakeRequest, StoreEntry *e, Ssl::BumpMode md):
   request(fakeRequest),
   _entry(*({
      StoreEntry * __entry=e;
      if (!__entry){
         const char *uri = urlCanonical(fakeRequest);
         __entry = storeCreateEntry(uri, uri, fakeRequest->flags, fakeRequest->method);
      } else __entry->lock("Ssl::ServerBump");
      __entry;
   })),
   step(bumpStep1),
   _id(++_ctx)
{

    debugs(33, 4, HERE << "will peek at " << request->GetHost() << ':' << request->port);
    act.step1 = md;
    act.step2 = act.step3 = Ssl::bumpNone;
    // We do not need to be a client because the error contents will be used
    // later, but an entry without any client will trim all its contents away.

    sc = storeClientListAdd(&_entry, this);
}

Ssl::ServerBump::~ServerBump()
{
   debugs(33, 4, HERE << "destroying " << _entry);
   storeUnregister(sc, &_entry, this);
   _entry.unlock("Ssl::ServerBump");
}

void
Ssl::ServerBump::attachServerSSL(SSL *ssl)
{
    if (serverSSL.get())
        return;

    serverSSL.resetAndLock(ssl);
}

const Ssl::CertErrors *
Ssl::ServerBump::sslErrors() const
{
    if (!serverSSL.get())
        return NULL;

    const Ssl::CertErrors *errs = static_cast<const Ssl::CertErrors*>(SSL_get_ex_data(serverSSL.get(), ssl_ex_index_ssl_errors));
    return errs;
}

