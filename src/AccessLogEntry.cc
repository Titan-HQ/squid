/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "SquidConfig.h"

#if USE_OPENSSL
#include "ssl/support.h"

constexpr int do_AccessLogEntry_tracing = 0;  /*Change to non zero to enable tracing*/

/* Even though AccessLOgEntry is RefCountable it is not showing in the mem:mgr report*/
static titan_instance_tracker *get_instance_tracker_AccessLogEntry()
{
    /* Create on first access, using double checked lock */
    static titan_instance_tracker *g_AccessLogEntry_tracker = nullptr;
    static std::mutex l_lock;
    if (g_AccessLogEntry_tracker == nullptr)
    {
	std::lock_guard<std::mutex> l_lg( l_lock );
	if( g_AccessLogEntry_tracker == nullptr)
	    g_AccessLogEntry_tracker = new titan_instance_tracker("AccessLogEntry");
    }
    return(g_AccessLogEntry_tracker); 
}

AccessLogEntry::AccessLogEntry() : url(NULL), tcpClient(), reply(NULL), request(NULL),
            adapted_request(NULL)
{
    if (do_AccessLogEntry_tracing != 0) get_instance_tracker_AccessLogEntry()->Add( this );
}
void Check_tracker_AccessLogEntry( std::ostream & a_os, uint32_t a_older_than_secs)
{
    if (do_AccessLogEntry_tracing != 0)
    {
        /* You can pass a function here for printing details of the instance */
        get_instance_tracker_AccessLogEntry()->Check(a_os, a_older_than_secs, nullptr);
    }
    else
    {
        a_os << " AccessLogEntry tracing is not enabled\n";
    }
}

AccessLogEntry::SslDetails::SslDetails(): user(NULL), bumpMode(::Ssl::bumpEnd)
{
}
#endif /* USE_OPENSSL */

void
AccessLogEntry::getLogClientIp(char *buf, size_t bufsz) const
{
    Ip::Address log_ip;

#if FOLLOW_X_FORWARDED_FOR
    if (Config.onoff.log_uses_indirect_client && request)
        log_ip = request->indirect_client_addr;
    else
#endif
        if (tcpClient != NULL)
            log_ip = tcpClient->remote;
        else
            log_ip = cache.caddr;
    
    // internally generated requests (and some ICAP) lack client IP
    if (log_ip.isNoAddr()) {
        strncpy(buf, "-", bufsz);
        return;
    }
    
    // Apply so-called 'privacy masking' to IPv4 clients
    // - localhost IP is always shown in full
    // - IPv4 clients masked with client_netmask
    // - IPv6 clients use 'privacy addressing' instead.

    if (!log_ip.isLocalhost() && log_ip.isIPv4())
        log_ip.applyMask(Config.Addrs.client_netmask);

    log_ip.toStr(buf, bufsz);
}

AccessLogEntry::~AccessLogEntry()
{
    if (do_AccessLogEntry_tracing != 0) get_instance_tracker_AccessLogEntry()->Remove( this );
    
    safe_free(headers.request);

#if USE_ADAPTATION
    safe_free(adapt.last_meta);
#endif

    safe_free(headers.reply);

    safe_free(headers.adapted_request);
    HTTPMSGUNLOCK(adapted_request);

    HTTPMSGUNLOCK(reply);
    HTTPMSGUNLOCK(request);
#if ICAP_CLIENT
    HTTPMSGUNLOCK(icap.reply);
    HTTPMSGUNLOCK(icap.request);
#endif
}

