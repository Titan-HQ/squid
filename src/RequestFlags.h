/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv3+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 73    HTTP Request */

#ifndef SQUID_REQUESTFLAGS_H_
#define SQUID_REQUESTFLAGS_H_

/** request-related flags
 *
 * The bit-field contains both flags marking a request's current state,
 * and flags requesting some processing to be done at a later stage.
 * TODO: better distinguish the two cases.
 */
#include "TAPE.hxx"

class RequestFlags:public titan_v3::IHRequestFlags
{
public:
    RequestFlags():IHRequestFlags(){
    }

    /** true if the response to this request may not be READ from cache */
    using titan_v3::IHRequestFlags::noCache;
    /** request is if-modified-since */
    using titan_v3::IHRequestFlags::ims;
    /** request is authenticated */
    using titan_v3::IHRequestFlags::auth;
    /** he response to the request may be stored in the cache */
    using titan_v3::IHRequestFlags::cachable;
    /** the request can be forwarded through the hierarchy */
    using titan_v3::IHRequestFlags::hierarchical;
    /** a loop was detected on this request */
    using titan_v3::IHRequestFlags::loopDetected;
    /** the connection can be kept alive */
    using titan_v3::IHRequestFlags::proxyKeepalive;
    /* this should be killed, also in httpstateflags */
    using titan_v3::IHRequestFlags::proxying;
    /** content has expired, need to refresh it */
    using titan_v3::IHRequestFlags::refresh;
    /** request was redirected by redirectors */
    using titan_v3::IHRequestFlags::redirected;
    /** the requested object needs to be validated. See client_side_reply.cc
     * for further information.
     */
    using titan_v3::IHRequestFlags::needValidation;
    /** whether we should fail if validation fails */
    using titan_v3::IHRequestFlags::failOnValidationError;
    /** reply is stale if it is a hit */
    using titan_v3::IHRequestFlags::staleIfHit;
    /** request to override no-cache directives
     *
     * always use noCacheHack() for reading.
     * \note only meaningful if USE_HTTP_VIOLATIONS is defined at build time
     */
    using titan_v3::IHRequestFlags::nocacheHack;
    /** this request is accelerated (reverse-proxy) */
    using titan_v3::IHRequestFlags::accelerated;
    /** if set, ignore Cache-Control headers */
    using titan_v3::IHRequestFlags::ignoreCc;
    /** set for intercepted requests */
    using titan_v3::IHRequestFlags::intercepted;
    /** set if the Host: header passed verification */
    using titan_v3::IHRequestFlags::hostVerified;
    /// Set for requests handled by a "tproxy" port.
    using titan_v3::IHRequestFlags::interceptTproxy;
    /// The client IP address should be spoofed when connecting to the web server.
    /// This applies to TPROXY traffic that has not had spoofing disabled through
    /// the spoof_client_ip squid.conf ACL.
    using titan_v3::IHRequestFlags::spoofClientIp;
    /** set if the request is internal (\see ClientHttpRequest::flags.internal)*/
    using titan_v3::IHRequestFlags::internal;
    /** set for internally-generated requests */
    //XXX this is set in in clientBeginRequest, but never tested.
    using titan_v3::IHRequestFlags::internalClient;
    /** if set, request to try very hard to keep the connection alive */
    using titan_v3::IHRequestFlags::mustKeepalive;
    /** set if the rquest wants connection oriented auth */
    using titan_v3::IHRequestFlags::connectionAuth;
    /** set if connection oriented auth can not be supported */
    using titan_v3::IHRequestFlags::connectionAuthDisabled;
    /** Request wants connection oriented auth */
    // XXX This is set in clientCheckPinning but never tested
    using titan_v3::IHRequestFlags::connectionProxyAuth;
    /** set if the request was sent on a pinned connection */
    using titan_v3::IHRequestFlags::pinned;
    /** Authentication was already sent upstream (e.g. due tcp-level auth) */
    using titan_v3::IHRequestFlags::authSent;
    /** Deny direct forwarding unless overriden by always_direct
     * Used in accelerator mode */
    using titan_v3::IHRequestFlags::noDirect;
    /** Reply with chunked transfer encoding */
    using titan_v3::IHRequestFlags::chunkedReply;
    /** set if stream error has occured */
    using titan_v3::IHRequestFlags::streamError;
    /** internal ssl-bump request to get server cert */
    using titan_v3::IHRequestFlags::sslPeek;
    /** set if X-Forwarded-For checking is complete
     *
     * do not read directly; use doneFollowXff for reading
     */
    using titan_v3::IHRequestFlags::done_follow_x_forwarded_for;
    /** set for ssl-bumped requests */
    using titan_v3::IHRequestFlags::sslBumped;
    /// carries a representation of an FTP command [received on ftp_port]
    using titan_v3::IHRequestFlags::ftpNative;
    using titan_v3::IHRequestFlags::destinationIpLookedUp;
    /** request to reset the TCP stream */
    using titan_v3::IHRequestFlags::resetTcp;
    /** set if the request is ranged */
    using titan_v3::IHRequestFlags::isRanged;



    /** clone the flags, resetting to default those which are not safe in
     *  a related (e.g. ICAP-adapted) request.
     */
    RequestFlags cloneAdaptationImmune() const;

    // if FOLLOW_X_FORWARDED_FOR is not set, we always return "done".
    bool doneFollowXff() const {
        return done_follow_x_forwarded_for || !FOLLOW_X_FORWARDED_FOR;
    }

    // if USE_HTTP_VIOLATIONS is not set, never allow this
    bool noCacheHack() const {
        return USE_HTTP_VIOLATIONS && nocacheHack;
    }
};

#endif /* SQUID_REQUESTFLAGS_H_ */

