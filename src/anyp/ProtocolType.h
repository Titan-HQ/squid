/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_SRC_ANYP_PROTOCOLTYPE_H
#define _SQUID_SRC_ANYP_PROTOCOLTYPE_H

#include <ostream>
#include "TAPE.h"

namespace AnyP
{

/**
 * List of all protocols known and supported.
 * This is a combined list. It is used as type-codes where needed and
 * the AnyP::ProtocolType_Str array of strings may be used for display
 */
   
//WARNING : if changing list of known protocols, please update manually the ProtocolType.cc file
typedef t_proto_types ProtocolType;
using ::PROTO_NONE;
using ::PROTO_HTTP;
using ::PROTO_FTP;
using ::PROTO_HTTPS;
using ::PROTO_COAP;
using ::PROTO_COAPS;
using ::PROTO_GOPHER;
using ::PROTO_WAIS;
using ::PROTO_CACHE_OBJECT;
using ::PROTO_ICP;
   #if USE_HTCP
      using ::PROTO_HTCP,
   #endif
using ::PROTO_URN;
using ::PROTO_WHOIS;
   //PROTO_INTERNAL,
using ::PROTO_ICY;
using ::PROTO_DNS;
using ::PROTO_UNKNOWN;
using ::PROTO_MAX;

extern const char *ProtocolType_str[];

/** Display the registered Protocol Type (in upper case).
 *  If the protocol is not a registered AnyP::ProtocolType nothing will be displayed.
 * The caller is responsible for any alternative text.
 */
inline std::ostream &
operator <<(std::ostream &os, ProtocolType const &p)
{
    if (PROTO_NONE <= p && p < PROTO_MAX)
        os << ProtocolType_str[p];
    else
        os << static_cast<int>(p);
    return os;
}

} // namespace AnyP

#endif /* _SQUID_SRC_ANYP_PROTOCOLTYPE_H */

