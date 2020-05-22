/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_HTTP_STATUSCODE_H
#define _SQUID_SRC_HTTP_STATUSCODE_H
#include "TAPE.h"
namespace Http
{

/**
 * These basic HTTP reply status codes are defined by RFC 2616 unless otherwise stated.
 * The IANA registry for HTTP status codes can be found at:
 * http://www.iana.org/assignments/http-status-codes/http-status-codes.xhtml
 */
typedef t_status_codes StatusCode;
using ::scNone;
using ::scContinue;
using ::scSwitchingProtocols;
using ::scProcessing;      // RFC2518 section 10.1
using ::scEarlyHints;      /**< draft-kazuho-early-hints-status-code */
using ::scOkay;
using ::scCreated;
using ::scAccepted;
using ::scNonAuthoritativeInformation;
using ::scNoContent;
using ::scResetContent;
using ::scPartialContent;
using ::scMultiStatus;     ///< RFC2518 section 10.2 / RFC4918
using ::scAlreadyReported; //< RFC5842
using ::scImUsed;          //< RFC3229
using ::scMultipleChoices;
using ::scMovedPermanently;
using ::scFound;
using ::scSeeOther;
using ::scNotModified;
using ::scUseProxy;
using ::scTemporaryRedirect;
using ::scPermanentRedirect; //< RFC7238
using ::scBadRequest;
using ::scUnauthorized;
using ::scPaymentRequired;
using ::scForbidden;
using ::scNotFound;
using ::scMethodNotAllowed;
using ::scNotAcceptable;
using ::scProxyAuthenticationRequired;
using ::scRequestTimeout;
using ::scConflict;
using ::scGone;
using ::scLengthRequired;
using ::scPreconditionFailed;
using ::scPayloadTooLarge;
using ::scUriTooLong;
using ::scUnsupportedMediaType;
using ::scRequestedRangeNotSatisfied;
using ::scExpectationFailed;
using ::scMisdirectedRequest;
using ::scUnprocessableEntity;    //< RFC2518 section 10.3 / RFC4918
using ::scLocked;                 //< RFC2518 section 10.4 / RFC4918
using ::scFailedDependency;       //< RFC2518 section 10.5 / RFC4918
using ::scUpgradeRequired;
using ::scPreconditionRequired;   //< RFC6585
using ::scTooManyRequests;        //< RFC6585
using ::scRequestHeaderFieldsTooLarge; //< RFC6585
using ::scUnavailableForLegalReasons; /**< RFC7725 */
using ::scInternalServerError;
using ::scNotImplemented;
using ::scBadGateway;
using ::scServiceUnavailable;
using ::scGatewayTimeout;
using ::scHttpVersionNotSupported;
using ::scVariantAlsoNegotiates;  //< RFC2295
using ::scInsufficientStorage;    //< RFC2518 section 10.6 / RFC4918
using ::scLoopDetected;           //< RFC5842
using ::scNotExtended;            //< RFC2774
using ::scNetworkAuthenticationRequired; //< RFC6585
using ::scInvalidHeader;          //< Squid header parsing error
using ::scHeaderTooLarge;          // Header too large to process

const char *StatusCodeString(const Http::StatusCode status);

} // namespace Http

#endif /* _SQUID_SRC_HTTP_STATUSCODE_H */

