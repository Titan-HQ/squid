/* Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 73    HTTP Request */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/AclSizeLimit.h"
#include "acl/FilledChecklist.h"
#include "client_side.h"
#include "DnsLookupDetails.h"
#include "err_detail_type.h"
#include "globals.h"
#include "gopher.h"
#include "http.h"
#include "HttpHdrCc.h"
#include "HttpHeaderRange.h"
#include "HttpRequest.h"
#include "log/Config.h"
#include "MemBuf.h"
#include "SquidConfig.h"
#include "Store.h"
#include "URL.h"
#include "ssl/ServerBump.h"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/icap_log.h"
#endif

#include "ssl/ServerBump.h"
#include "TAPE.hxx"
using namespace titan_v3;

//temporary change to add more traceability
uint64_t _httpctx_c{};    /* Count of constructions */
uint64_t _httpctx_d{};    /* Count of destructions */
uint64_t _httpctx_k{};    /* Count of clone*/
t_HttpRmap _RQmap;

constexpr int do_httprequest_tracing = 0;  /*Change to non zero to enable tracing*/

static titan_instance_tracker *get_instance_tracker_HttpRequest()
{
    /* Create on first access, using double checked lock */
    static titan_instance_tracker *g_HttpRequest_tracker = nullptr;
    static std::mutex l_lock;
    if (g_HttpRequest_tracker == nullptr)
    {
	std::lock_guard<std::mutex> l_lg( l_lock );
	if( g_HttpRequest_tracker == nullptr)
	    g_HttpRequest_tracker = new titan_instance_tracker("HttpRequest");
    }
    return(g_HttpRequest_tracker); 
}
void print_tracked_HttpRequest( void *a_p, std::ostream & a_s)
{
    if (do_httprequest_tracing != 0)
    {
        HttpRequest * p_item = static_cast< HttpRequest *>( a_p );
        a_s << " _id=" << p_item->_id;
        //a_s << " orig_host=" << p_item->orig_host;
        a_s << " canonical=" << p_item->canonical;
        //a_s << " sni=" << p_item->get_sni();
        a_s << " flags=" << p_item->flags;
    }
}
void Check_tracker_HttpRequest( std::ostream & a_os, uint32_t a_older_than_secs)
{
    if (do_httprequest_tracing != 0)
    {
        /* You can pass a function here for printing details of the instance */
        get_instance_tracker_HttpRequest()->Check(a_os, a_older_than_secs, print_tracked_HttpRequest);
    }
    else
    {
        a_os << " HttpRequest instance tracing is not enabled\n";
    }
}

HttpRequest::HttpRequest() :
    HttpMsg(hoRequest)
{
    if (do_httprequest_tracing != 0) get_instance_tracker_HttpRequest()->Add( this );
   _id=_httpctx_c++; 
   debugs(83,5, HERE << " (HttpRequest()) constructed: this " << (void *)this << " id=" << _id);
   
   init();
}

HttpRequest::HttpRequest(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *const aUrlpath) :
    HttpMsg(hoRequest)
{
    if (do_httprequest_tracing != 0) get_instance_tracker_HttpRequest()->Add( this );
   _id=_httpctx_c++;
   debugs(83,5, HERE << " (HttpRequest(args)) constructed, this=" << (void *)this  << " id=" << _id);

   init();
   initHTTP(aMethod, aProtocol, aUrlpath);
}

HttpRequest::~HttpRequest()
{
    if (do_httprequest_tracing != 0) get_instance_tracker_HttpRequest()->Remove( this );
   _destruct=_httpctx_d++; 
   
    clean();
    
    debugs(83,5, HERE << " (HttpRequest) destructed, this=" << (void *)this << " id=" << _id);
}

void HttpRequest::lock(const char * const a_place ,const uint32_t a_no) const
{
    HttpMsg::lock( a_place, a_no);
    debugs(83,3, "HttpRequest::lock() : _id=" << _id << " this=" << (void *)this << " from " << a_place << " line " << a_no );
}
uint32_t HttpRequest::unlock(const char * const a_place,const uint32_t a_no) const
{
    uint32_t l_rv = HttpMsg::unlock( a_place, a_no);
    debugs(83,3, "HttpRequest::unlock() : _id=" << _id << " this=" << (void *)this << " remaining lc=" << l_rv << " from " << a_place << " line " << a_no );
    return( l_rv );
}

void
HttpRequest::initHTTP(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *const aUrlpath)
{
    method = aMethod;
    url.setScheme(aProtocol);
    urlpath = aUrlpath;
}

void
HttpRequest::init()
{
    method = Http::METHOD_NONE;
    url.clear();
    urlpath = NULL;
    login[0] = '\0';
    host[0] = '\0';
#if USE_AUTH
    auth_user_request = NULL;
#endif
    port = 0;
    canonical = NULL;
    memset(&flags, '\0', sizeof(flags));
    range = NULL;
    ims = -1;
    imslen = 0;
    lastmod = -1;
    client_addr.setEmpty();
    my_addr.setEmpty();
    body_pipe = NULL;
    // hier
    dnsWait = -1;
    errType = ERR_NONE;
    errDetail = ERR_DETAIL_NONE;
    peer_login = NULL;      // not allocated/deallocated by this class
    peer_domain = NULL;     // not allocated/deallocated by this class
    peer_host = NULL;
    vary_headers = SBuf();
    myportname = null_string;
    tag = null_string;
#if USE_AUTH
    extacl_user = null_string;
    extacl_passwd = null_string;
#endif
    extacl_log = null_string;
    extacl_message = null_string;
    pstate = psReadyToParseStartLine;
#if FOLLOW_X_FORWARDED_FOR
    indirect_client_addr.setEmpty();
#endif /* FOLLOW_X_FORWARDED_FOR */
#if USE_ADAPTATION
    adaptHistory_ = NULL;
#endif
#if ICAP_CLIENT
    icapHistory_ = NULL;
#endif
    rangeOffsetLimit = -2; //a value of -2 means not checked yet

}

void
HttpRequest::clean()
{
    // we used to assert that the pipe is NULL, but now the request only
    // points to a pipe that is owned and initiated by another object.
    body_pipe = NULL;
#if USE_AUTH
    auth_user_request = NULL;
#endif
    safe_free(canonical);
    canonical_sz=0;
    vary_headers.clear();
    url.clear();
    urlpath.clean();

    header.clean();

    if (cache_control) {
        delete cache_control;
        cache_control = NULL;
    }

    if (range) {
        delete range;
        range = NULL;
    }

    myportname.clean();

    notes = NULL;

    tag.clean();
#if USE_AUTH
    extacl_user.clean();
    extacl_passwd.clean();
#endif
    extacl_log.clean();

    extacl_message.clean();

    etag.clean();

#if USE_ADAPTATION
    adaptHistory_ = NULL;
#endif
#if ICAP_CLIENT
    icapHistory_ = NULL;
#endif
    // Titax.
    safe_free(loggable_username);
    loggable_username = nullptr;
    safe_free(groups);
    groups = nullptr;
    group_count = 0;
}

void
HttpRequest::reset()
{
    clean();
    init();
}

HttpRequest *
HttpRequest::clone() const
{
    _httpctx_k++;
    HttpRequest *copy = new HttpRequest(method, url.getScheme(), urlpath.termedBuf());
    // TODO: move common cloning clone to Msg::copyTo() or copy ctor
    copy->header.append(&header);
    copy->hdrCacheInit();
    copy->hdr_sz = hdr_sz;
    copy->http_ver = http_ver;
    copy->pstate = pstate; // TODO: should we assert a specific state here?
    copy->body_pipe = body_pipe;

    strncpy(copy->login, login, sizeof(login)); // MAX_LOGIN_SZ
    strncpy(copy->host, host, sizeof(host)); // SQUIDHOSTNAMELEN
    copy->host_addr = host_addr;

    copy->port = port;
    // urlPath handled in ctor
    copy->canonical = canonical ? xstrdup(canonical) : NULL;

    // range handled in hdrCacheInit()
    copy->ims = ims;
    copy->imslen = imslen;
    copy->hier = hier; // Is it safe to copy? Should we?

    copy->errType = errType;

    // XXX: what to do with copy->peer_login?

    copy->lastmod = lastmod;
    copy->etag = etag;
    copy->vary_headers = vary_headers;
    // XXX: what to do with copy->peer_domain?

    copy->tag = tag;
    copy->extacl_log = extacl_log;
    copy->extacl_message = extacl_message;

    const bool inheritWorked = copy->inheritProperties(this);
    assert(inheritWorked);

//TODO: TEST ME :)
    copy->ttag=ttag;
    return copy;
}

bool
HttpRequest::inheritProperties(const HttpMsg *aMsg)
{
    const HttpRequest* aReq = dynamic_cast<const HttpRequest*>(aMsg);
    if (!aReq)
        return false;

    client_addr = aReq->client_addr;
#if FOLLOW_X_FORWARDED_FOR
    indirect_client_addr = aReq->indirect_client_addr;
#endif
    my_addr = aReq->my_addr;

    dnsWait = aReq->dnsWait;

#if USE_ADAPTATION
    adaptHistory_ = aReq->adaptHistory();
#endif
#if ICAP_CLIENT
    icapHistory_ = aReq->icapHistory();
#endif

    // This may be too conservative for the 204 No Content case
    // may eventually need cloneNullAdaptationImmune() for that.
    flags = aReq->flags.cloneAdaptationImmune();

    errType = aReq->errType;
    errDetail = aReq->errDetail;
#if USE_AUTH
    auth_user_request = aReq->auth_user_request;
    extacl_user = aReq->extacl_user;
    extacl_passwd = aReq->extacl_passwd;
#endif

    myportname = aReq->myportname;

    // main property is which connection the request was received on (if any)
    clientConnectionManager = aReq->clientConnectionManager;

    notes = aReq->notes;
    return true;
}

/**
 * Checks the first line of an HTTP request is valid
 * currently just checks the request method is present.
 *
 * NP: Other errors are left for detection later in the parse.
 */
bool
HttpRequest::sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, Http::StatusCode *error)
{
    // content is long enough to possibly hold a reply
    // 2 being magic size of a 1-byte request method plus space delimiter
    if ( buf->contentSize() < 2 ) {
        // this is ony a real error if the headers apparently complete.
        if (hdr_len > 0) {
            debugs(58, 3, HERE << "Too large request header (" << hdr_len << " bytes)");
            *error = Http::scInvalidHeader;
        }
        return false;
    }

    /* See if the request buffer starts with a known HTTP request method. */
    if (HttpRequestMethod(buf->content(),NULL) == Http::METHOD_NONE) {
        debugs(73, 3, "HttpRequest::sanityCheckStartLine: did not find HTTP request method");
        *error = Http::scInvalidHeader;
        return false;
    }

    return true;
}

bool
HttpRequest::parseFirstLine(const char *start, const char *end)
{
    const char *t = start + strcspn(start, w_space);
    method = HttpRequestMethod(start, t);

    if (method == Http::METHOD_NONE)
        return false;

    start = t + strspn(t, w_space);

    const char *ver = findTrailingHTTPVersion(start, end);

    if (ver) {
        end = ver - 1;

        while (xisspace(*end)) // find prev non-space
            --end;

        ++end;                 // back to space

        if (2 != sscanf(ver + 5, "%d.%d", &http_ver.major, &http_ver.minor)) {
            debugs(73, DBG_IMPORTANT, "parseRequestLine: Invalid HTTP identifier.");
            return false;
        }
    } else {
        http_ver.major = 0;
        http_ver.minor = 9;
    }

    if (end < start)   // missing URI
        return false;

    char save = *end;

    * (char *) end = '\0';     // temp terminate URI, XXX dangerous?

    HttpRequest *tmp = urlParse(method, (char *) start, this);

    * (char *) end = save;

    if (NULL == tmp)
        return false;

    return true;
}

int
HttpRequest::parseHeader(const char *parse_start, int len)
{
    const char *blk_start, *blk_end;

    if (!httpMsgIsolateHeaders(&parse_start, len, &blk_start, &blk_end))
        return 0;

    int result = header.parse(blk_start, blk_end);

    if (result)
        hdrCacheInit();

    return result;
}

/* swaps out request using httpRequestPack */
void
HttpRequest::swapOut(StoreEntry * e)
{
    Packer p;
    assert(e);
    packerToStoreInit(&p, e);
    pack(&p);
    packerClean(&p);
}

/* packs request-line and headers, appends <crlf> terminator */
void
HttpRequest::pack(Packer * p)
{
    assert(p);
    /* pack request-line */
    packerPrintf(p, SQUIDSBUFPH " " SQUIDSTRINGPH " HTTP/%d.%d\r\n",
                 SQUIDSBUFPRINT(method.image()), SQUIDSTRINGPRINT(urlpath),
                 http_ver.major, http_ver.minor);
    /* headers */
    header.packInto(p);
    /* trailer */
    packerAppend(p, "\r\n", 2);
}

/*
 * A wrapper for debugObj()
 */
void
httpRequestPack(void *obj, Packer *p)
{
    HttpRequest *request = static_cast<HttpRequest*>(obj);
    request->pack(p);
}

/* returns the length of request line + headers + crlf */
int
HttpRequest::prefixLen()
{
    return method.image().length() + 1 +
           urlpath.size() + 1 +
           4 + 1 + 3 + 2 +
           header.len + 2;
}

/* sync this routine when you update HttpRequest struct */
void
HttpRequest::hdrCacheInit()
{
    HttpMsg::hdrCacheInit();

    assert(!range);
    range = header.getRange();
}

#if ICAP_CLIENT
Adaptation::Icap::History::Pointer
HttpRequest::icapHistory() const
{
    if (!icapHistory_) {
        if (Log::TheConfig.hasIcapToken || IcapLogfileStatus == LOG_ENABLE) {
            icapHistory_ = new Adaptation::Icap::History();
            debugs(93,4, HERE << "made " << icapHistory_ << " for " << this);
        }
    }

    return icapHistory_;
}
#endif

#if USE_ADAPTATION
Adaptation::History::Pointer
HttpRequest::adaptHistory(bool createIfNone) const
{
    if (!adaptHistory_ && createIfNone) {
        adaptHistory_ = new Adaptation::History();
        debugs(93,4, HERE << "made " << adaptHistory_ << " for " << this);
    }

    return adaptHistory_;
}

Adaptation::History::Pointer
HttpRequest::adaptLogHistory() const
{
    return HttpRequest::adaptHistory(Log::TheConfig.hasAdaptToken);
}

void
HttpRequest::adaptHistoryImport(const HttpRequest &them)
{
    if (!adaptHistory_) {
        adaptHistory_ = them.adaptHistory_; // may be nil
    } else {
        // check that histories did not diverge
        Must(!them.adaptHistory_ || them.adaptHistory_ == adaptHistory_);
    }
}

#endif

bool
HttpRequest::multipartRangeRequest() const
{
    return (range && range->specs.size() > 1);
}

bool
HttpRequest::bodyNibbled() const
{
    return body_pipe != NULL && body_pipe->consumedSize() > 0;
}

void
HttpRequest::detailError(err_type aType, int aDetail)
{
    if (errType || errDetail)
        debugs(11, 5, HERE << "old error details: " << errType << '/' << errDetail);
    debugs(11, 5, HERE << "current error details: " << aType << '/' << aDetail);
    // checking type and detail separately may cause inconsistency, but
    // may result in more details available if they only become available later
    if (!errType)
        errType = aType;
    if (!errDetail)
        errDetail = aDetail;
}

void
HttpRequest::clearError()
{
    debugs(11, 7, HERE << "old error details: " << errType << '/' << errDetail);
    errType = ERR_NONE;
    errDetail = ERR_DETAIL_NONE;
}

const char *HttpRequest::packableURI(bool full_uri) const
{
    if (full_uri)
        return urlCanonical((HttpRequest*)this);

    if (urlpath.size())
        return urlpath.termedBuf();

    return "/";
}

void HttpRequest::packFirstLineInto(Packer * p, bool full_uri) const
{
    // form HTTP request-line
    packerPrintf(p, SQUIDSBUFPH " %s HTTP/%d.%d\r\n",
                 SQUIDSBUFPRINT(method.image()),
                 packableURI(full_uri),
                 http_ver.major, http_ver.minor);
}

/*
 * Indicate whether or not we would expect an entity-body
 * along with this request
 */
bool
HttpRequest::expectingBody(const HttpRequestMethod& unused, int64_t& theSize) const
{
    bool expectBody = false;

    /*
     * Note: Checks for message validity is in clientIsContentLengthValid().
     * this just checks if a entity-body is expected based on HTTP message syntax
     */
    if (header.chunked()) {
        expectBody = true;
        theSize = -1;
    } else if (content_length >= 0) {
        expectBody = true;
        theSize = content_length;
    } else {
        expectBody = false;
        // theSize undefined
    }

    return expectBody;
}

/*
 * Create a Request from a URL and METHOD.
 *
 * If the METHOD is CONNECT, then a host:port pair is looked for instead of a URL.
 * If the request cannot be created cleanly, NULL is returned
 */
HttpRequest *
HttpRequest::CreateFromUrlAndMethod(char * url, const HttpRequestMethod& method)
{
    return urlParse(method, url, NULL);
}

/*
 * Create a Request from a URL.
 *
 * If the request cannot be created cleanly, NULL is returned
 */
HttpRequest *
HttpRequest::CreateFromUrl(char * url)
{
    return urlParse(Http::METHOD_GET, url, NULL);
}

/**
 * Are responses to this request possible cacheable ?
 * If false then no matter what the response must not be cached.
 */
bool
HttpRequest::maybeCacheable()
{
    // Intercepted request with Host: header which cannot be trusted.
    // Because it failed verification, or someone bypassed the security tests
    // we cannot cache the reponse for sharing between clients.
    // TODO: update cache to store for particular clients only (going to same Host: and destination IP)
    if (!flags.hostVerified && (flags.intercepted || flags.interceptTproxy))
        return false;

    switch (url.getScheme()) {
    case AnyP::PROTO_HTTP:
    case AnyP::PROTO_HTTPS:
        if (!method.respMaybeCacheable())
            return false;

	// RFC 7234 section 5.2.1.5:
	// "cache MUST NOT store any part of either this request or any response to it"
	// NP: refresh_pattern ignore-no-store only applies to response messages
	//     this test is handling request message CC header.
	if (!flags.ignoreCc && cache_control && cache_control->noStore())
	    return false;
        break;

    case AnyP::PROTO_GOPHER:
        if (!gopherCachable(this))
            return false;
        break;

    case AnyP::PROTO_CACHE_OBJECT:
        return false;

    //case AnyP::PROTO_FTP:
    default:
        break;
    }

    return true;
}

bool
HttpRequest::conditional() const
{
    return flags.ims ||
           header.has(HDR_IF_MATCH) ||
           header.has(HDR_IF_NONE_MATCH);
}

void
HttpRequest::recordLookup(const DnsLookupDetails &dns)
{
    if (dns.wait >= 0) { // known delay
        if (dnsWait >= 0) // have recorded DNS wait before
            dnsWait += dns.wait;
        else
            dnsWait = dns.wait;
    }
}

int64_t
HttpRequest::getRangeOffsetLimit()
{
    /* -2 is the starting value of rangeOffsetLimit.
     * If it is -2, that means we haven't checked it yet.
     *  Otherwise, return the current value */
    if (rangeOffsetLimit != -2)
        return rangeOffsetLimit;

    rangeOffsetLimit = 0; // default value for rangeOffsetLimit

    ACLFilledChecklist ch(NULL, this, NULL);
    ch.src_addr = client_addr;
    ch.my_addr =  my_addr;

    for (AclSizeLimit *l = Config.rangeOffsetLimit; l; l = l -> next) {
        /* if there is no ACL list or if the ACLs listed match use this limit value */
        if (!l->aclList || ch.fastCheck(l->aclList) == ACCESS_ALLOWED) {
            debugs(58, 4, HERE << "rangeOffsetLimit=" << rangeOffsetLimit);
            rangeOffsetLimit = l->size; // may be -1
            break;
        }
    }

    return rangeOffsetLimit;
}

void
HttpRequest::ignoreRange(const char *reason)
{
    if (range) {
        debugs(73, 3, static_cast<void*>(range) << " for " << reason);
        delete range;
        range = NULL;
    }
    // Some callers also reset isRanged but it may not be safe for all callers:
    // isRanged is used to determine whether a weak ETag comparison is allowed,
    // and that check should not ignore the Range header if it was present.
    // TODO: Some callers also delete HDR_RANGE, HDR_REQUEST_RANGE. Should we?
}

bool
HttpRequest::canHandle1xx() const
{
    // old clients do not support 1xx unless they sent Expect: 100-continue
    // (we reject all other HDR_EXPECT values so just check for HDR_EXPECT)
    if (http_ver <= Http::ProtocolVersion(1,0) && !header.has(HDR_EXPECT))
        return false;

    // others must support 1xx control messages
    return true;
}

ConnStateData * const  HttpRequest::pinnedConnection()
{
   if (ConnStateData * const _csd=static_cast<ConnStateData * const>(this->clientConnectionManager.valid())){
      return (_csd->pinning.pinned?_csd:NULL);
   };
   return NULL;
}

const char *
HttpRequest::storeId()
{
    if (store_id.size() != 0) {
        debugs(73, 3, "sent back store_id:" << store_id);

        return store_id.termedBuf();
    }
    debugs(73, 3, "sent back canonicalUrl:" << urlCanonical(this) );

    return urlCanonical(this);
}

////////////////////////////////////////////////////////////////////////////////
bool HttpRequest::set_client_addr(const titan_v3::raw_ipaddr_t & _ip)
{
    if ( _ip ) {
        this->cli_ip_ = _ip;
        this->cli_ip_man_set_ = true;
    }
    else {
        raw_ipaddr_t l_rip{};
        this->cli_ip_ = l_rip;
        this->cli_ip_man_set_ = false;
    }
    return (this->cli_ip_man_set_);
}

titan_v3::raw_ipaddr_t HttpRequest::get_indirect_client_addr(void)
{
   return raw_ip_from_Address(this->indirect_client_addr);
}

titan_v3::raw_ipaddr_t HttpRequest::get_client_addr(void)
{
   if (!this->cli_ip_man_set_)
   {
       titan_v3::raw_ipaddr_t l_rv{};
       Ip::Address * r_addr = & this->client_addr;
       if (this->client_addr.isAnyAddr())       /* == 0 */
       {
           if (ConnStateData * const _csd=static_cast<ConnStateData * const>(this->clientConnectionManager.valid()))
           {
               r_addr = & _csd->log_addr;
           }
           else
               return l_rv; /*default*/
       }

       l_rv = raw_ip_from_Address( *r_addr );
       return l_rv;
   }

   return this->cli_ip_;
}

std::string  HttpRequest::get_canonical(void) 
{
   return urlCanonicalStr(this);
}

bool HttpRequest::is_target_server(void) const
{
    if ( ConnStateData * const _csd = 
                    static_cast<ConnStateData * const>( this->clientConnectionManager.valid() ) ) {

        return is_target_server(_csd->clientConnection);
    }

    return false;
}

bool HttpRequest::is_target_server(const Comm::ConnectionPointer & _ccptr)
{
   if (_ccptr!=NULL){
      static Ip::Address _int_ip;
      _int_ip=(   _ccptr->local.isIPv4() ? 
                   GTAPE.ttncfg.ip_4_str.c_str() :
                   GTAPE.ttncfg.ip_6_str.c_str() );

      static Ip::Address _cnames_ip;
      const std::string & _cnames=GTAPE.ttncfg.cnames_str;
      _cnames_ip=(_cnames.size()?_cnames.c_str():"");
      return (((_ccptr->flags & COMM_INTERCEPTION) != 0) && ( _ccptr->local==_int_ip || _ccptr->local==_cnames_ip));
   }
   return false;
}


std::string HttpRequest::get_sni(void) const
{
   if (ConnStateData * const _csd=static_cast<ConnStateData * const>(this->clientConnectionManager.valid())){
      if (Ssl::ServerBump * const sslb=_csd->serverBump()){
         if (const size_t s_=sslb->clientSni.length()){
            if (const char * const c_=sslb->clientSni.c_str()){
               if (*c_) return std::string {c_,s_};
            }
         }
      }
   }
   return std::string {};
}

bool HttpRequest::can_report_errors(void) const
{
   //(this->flags.intercepted || this->flags.interceptTproxy)
   if (ConnStateData * const _csd=static_cast<ConnStateData * const>(this->clientConnectionManager.valid())){
      if (method != Http::METHOD_CONNECT){
         return true;
      } else 
         return ((_csd->sslBumpMode==Ssl::bumpBump  || _csd->sslBumpMode==Ssl::bumpEnd));
   }

   return false;
}

void HttpRequest::set_host(const std::string & src) 
{
    host_addr.setEmpty();
    safe_free(canonical); // force its re-build
    canonical = nullptr;
    host[0]=0;

    if ( src.size() ) {

        host_addr = src.c_str(); 

        if ( host_addr.isAnyAddr() ) {

            xstrncpy(host, src.c_str(), SQUIDHOSTNAMELEN);
            flags.ttn_is_host_numeric = false;
            debugs(23, 3, HERE << "Host is given: " << host_addr);
        } 
        else {

            host_addr.toHostStr(host, SQUIDHOSTNAMELEN);
            flags.ttn_is_host_numeric = true;
            debugs(23, 3, HERE << "IP is given: " << host_addr);
        }

        if ( !flags.ttn_has_been_processed ) {

            flags.ttn_is_local_request = GTAPE.ttncfg.is_request_local(host);
            debugs(23, 3, HERE << "is host local : " << flags.ttn_is_local_request);
        }

        return;
    }

    debugs(28, 0, HERE << "set_host failed");
    exit(-1);
}


