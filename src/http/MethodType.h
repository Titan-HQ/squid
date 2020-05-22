/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_SRC_HTTP_METHODTYPE_H
#define SQUID_SRC_HTTP_METHODTYPE_H

#include "SBuf.h"
#include "TAPE.h"
namespace Http
{

/*
 * The IANA registry for HTTP status codes can be found at:
 * http://www.iana.org/assignments/http-methods/http-methods.xhtml
 */
//WARNING : if changing list of known methods, please update manually the MethodType.cc file   
typedef t_method_type MethodType;    
using ::METHOD_NONE;
using ::METHOD_GET;
using ::METHOD_POST;
using ::METHOD_PUT;
using ::METHOD_HEAD;
using ::METHOD_CONNECT;
using ::METHOD_TRACE;
using ::METHOD_OPTIONS;
using ::METHOD_DELETE;
using ::METHOD_CHECKOUT;
using ::METHOD_CHECKIN;
using ::METHOD_UNCHECKOUT;
using ::METHOD_MKWORKSPACE;
using ::METHOD_VERSION_CONTROL;
using ::METHOD_REPORT;
using ::METHOD_UPDATE;
using ::METHOD_LABEL;
using ::METHOD_MERGE;
using ::METHOD_BASELINE_CONTROL;
using ::METHOD_MKACTIVITY;
using ::METHOD_PROPFIND;
using ::METHOD_PROPPATCH;
using ::METHOD_MKCOL;
using ::METHOD_COPY;
using ::METHOD_MOVE;
using ::METHOD_LOCK;
using ::METHOD_UNLOCK;
using ::METHOD_SEARCH;
using ::METHOD_PRI;
using ::METHOD_PURGE;
using ::METHOD_OTHER;
using ::METHOD_ENUM_END;


extern const SBuf MethodType_sb[];

inline const SBuf &
MethodStr(const MethodType m)
{
    return MethodType_sb[m];
}

}; // namespace Http

#endif /* SQUID_SRC_HTTP_METHODTYPE_H */

