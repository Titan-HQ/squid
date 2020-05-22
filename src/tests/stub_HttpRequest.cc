/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#include "squid.h"
#include "AccessLogEntry.h"
#include "HttpRequest.h"

#define STUB_API "HttpRequest.cc"
#include "tests/STUB.h"

uint64_t _httpctx_c = 0;
uint64_t _httpctx_d = 0;
t_HttpRmap _RQmap;

HttpRequest::HttpRequest() : HttpMsg(hoRequest) STUB
    HttpRequest::HttpRequest(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aUrlpath) : HttpMsg(hoRequest) STUB
    HttpRequest::~HttpRequest() STUB
    void HttpRequest::packFirstLineInto(Packer * p, bool full_uri) const STUB
    bool HttpRequest::sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, Http::StatusCode *error) STUB_RETVAL(false)
    void HttpRequest::hdrCacheInit() STUB
    void HttpRequest::reset() STUB
    bool HttpRequest::expectingBody(const HttpRequestMethod& unused, int64_t&) const STUB_RETVAL(false)
    void HttpRequest::initHTTP(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *aUrlpath) STUB
    bool HttpRequest::parseFirstLine(const char *start, const char *end) STUB_RETVAL(false)
    HttpRequest * HttpRequest::clone() const STUB_RETVAL(NULL)
    bool HttpRequest::inheritProperties(const HttpMsg *aMsg) STUB_RETVAL(false)
    int64_t HttpRequest::getRangeOffsetLimit() STUB_RETVAL(0)
    const char *HttpRequest::storeId() STUB_RETVAL(".")
    std::string HttpRequest::get_path(void) STUB_RETVAL("")
    std::string HttpRequest::get_canonical(void) STUB_RETVAL("")
    bool HttpRequest::set_client_addr(const uint32_t) STUB_RETVAL(false)
    std::string HttpRequest::headers_get(const t_http_hdr_types) STUB_RETVAL("")
    std::string HttpRequest::headers_getex(const t_http_hdr_types) STUB_RETVAL("")
    uint32_t HttpRequest::get_client_addr(void) STUB_RETVAL(0)
    bool HttpRequest::is_target_server(void) STUB_RETVAL(false)
    std::string HttpRequest::get_sni(void) STUB_RETVAL("")
    bool HttpRequest::can_report_errors(void) STUB_RETVAL(false)
    int get_authenticateUserAuthenticated(void) STUB_RETVAL(0)

