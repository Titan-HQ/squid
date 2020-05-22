/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPREQUEST_H
#define SQUID_HTTPREQUEST_H

#include "base/CbcPointer.h"
#include "Debug.h"
#include "err_type.h"
#include "HierarchyLogEntry.h"
#include "HttpMsg.h"
#include "HttpRequestMethod.h"
#include "Notes.h"
#include "RequestFlags.h"
#include "URL.h"
#include "ttn_cidr_types.hxx"

#if USE_AUTH
#include "auth/UserRequest.h"
#endif
#if USE_ADAPTATION
#include "adaptation/History.h"
#endif
#if ICAP_CLIENT
#include "adaptation/icap/History.h"
#endif
#if USE_SQUID_EUI
#include "eui/Eui48.h"
#include "eui/Eui64.h"
#endif

#include "TAPE.hxx"

class ConnStateData;

/*  Http Request */
void httpRequestPack(void *obj, Packer *p);

class HttpHdrRange;
class DnsLookupDetails;

class HttpRequest: public HttpMsg, public titan_v3::IHRequest
{

public:
    uint64_t _destruct{};
    typedef RefCount<HttpRequest> Pointer;

    MEMPROXY_CLASS(HttpRequest);
    HttpRequest();
    HttpRequest(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char *const aUrlpath);
    ~HttpRequest();

    void lock(const char * const a_place,const uint32_t a_no) const final ;
    uint32_t unlock(const char * const a_place,const uint32_t a_no) const final ;

    void reset() final;

    void initHTTP(const HttpRequestMethod& aMethod, AnyP::ProtocolType aProtocol, const char * const aUrlpath);

    HttpRequest *clone() const final;

    /// Whether response to this request is potentially cachable
    /// \retval false  Not cacheable.
    /// \retval true   Possibly cacheable. Response factors will determine.
    bool maybeCacheable();

    bool conditional() const; ///< has at least one recognized If-* header

    /// whether the client is likely to be able to handle a 1xx reply
    bool canHandle1xx() const;

    /* Now that we care what host contains it is better off being protected. */
    /* HACK: These two methods are only inline to get around Makefile dependancies */
    /*      caused by HttpRequest being used in places it really shouldn't.        */
    /*      ideally they would be methods of URL instead. */
    inline void SetHost(const char *src) 
    {
       set_host(src);
    }

    std::string orig_host{}; //titanlib

    inline const char* GetHost(void) const noexcept 
    { 
       return host; 
    }

    inline int GetHostIsNumeric(void) const noexcept
    { 
       return flags.ttn_is_host_numeric; 
    }


#if USE_ADAPTATION
    /// Returns possibly nil history, creating it if adapt. logging is enabled
    Adaptation::History::Pointer adaptLogHistory() const;
    /// Returns possibly nil history, creating it if requested
    Adaptation::History::Pointer adaptHistory(bool createIfNone = false) const;
    /// Makes their history ours, throwing on conflicts
    void adaptHistoryImport(const HttpRequest &them);
#endif
#if ICAP_CLIENT
    /// Returns possibly nil history, creating it if icap logging is enabled
    Adaptation::Icap::History::Pointer icapHistory() const;
#endif

    void recordLookup(const DnsLookupDetails &detail);

    /// sets error detail if no earlier detail was available
    void detailError(err_type aType, int aDetail);
    /// clear error details, useful for retries/repeats
    void clearError();

protected:
    void clean();

    void init();

public:
    HttpRequestMethod method;

    // TODO expand to include all URI parts
    URL url; ///< the request URI (scheme only)

    char login[MAX_LOGIN_SZ]={};

private:
    char host[SQUIDHOSTNAMELEN]={};

#if USE_ADAPTATION
    mutable Adaptation::History::Pointer adaptHistory_; ///< per-HTTP transaction info
#endif
#if ICAP_CLIENT
    mutable Adaptation::Icap::History::Pointer icapHistory_; ///< per-HTTP transaction info
#endif

public:
    Ip::Address host_addr;
#if USE_AUTH
    Auth::UserRequest::Pointer auth_user_request;
#endif
    unsigned short port{};

    String urlpath;

    char *canonical{};
    size_t canonical_sz{}; //tx

    /**
     * If defined, store_id_program mapped the request URL to this ID.
     * Store uses this ID (and not the URL) to find and store entries,
     * avoiding caching duplicate entries when different URLs point to
     * "essentially the same" cachable resource.
     */
    String store_id;

    RequestFlags flags{};

    HttpHdrRange *range{};

    time_t ims{};

    int imslen{};

    Ip::Address client_addr;

#if FOLLOW_X_FORWARDED_FOR
    Ip::Address indirect_client_addr;
#endif /* FOLLOW_X_FORWARDED_FOR */

    Ip::Address my_addr;

    HierarchyLogEntry hier;

    int dnsWait{}; ///< sum of DNS lookup delays in milliseconds, for %dt

    err_type errType{};
    int errDetail{}; ///< errType-specific detail about the transaction error

    char *peer_login{};       /* Configured peer login:password */

    char *peer_host{};           /* Selected peer host*/

    time_t lastmod{};     /* Used on refreshes */

    /// The variant second-stage cache key. Generated from Vary header pattern for this request.
    SBuf vary_headers{};

    char *peer_domain{};      /* Configured peer forceddomain */

    String myportname; // Internal tag name= value from port this requests arrived in.

    NotePairs::Pointer notes; ///< annotations added by the note directive and helpers

    String tag;         /* Internal tag for this request */

    String extacl_user;     /* User name returned by extacl lookup */

    String extacl_passwd;   /* Password returned by extacl lookup */

    String extacl_log;      /* String to be used for access.log purposes */

    String extacl_message;  /* String to be used for error page purposes */

#if FOLLOW_X_FORWARDED_FOR
    String x_forwarded_for_iterator; /* XXX a list of IP addresses */
#endif /* FOLLOW_X_FORWARDED_FOR */

    /// A strong etag of the cached entry. Used for refreshing that entry.
    String etag;
//-----------------
    // Titax.
    char* loggable_username{};    /* username that can be used in logging - may have been anonimized */
    int* groups{};                /* malloc'd list of groups, allocated by send free'd when the header is created */
    int group_count{};            /* the number of groups in groups */
    bool has_been_logged{};

//-----------
public:
    bool multipartRangeRequest() const;

    bool parseFirstLine(const char *start, const char *end) final; 

    int parseHeader(const char *parse_start, int len);

    virtual bool expectingBody(const HttpRequestMethod& unused, int64_t&) const final;

    bool bodyNibbled() const; // the request has a [partially] consumed body

    int prefixLen();

    void swapOut(StoreEntry * e);

    void pack(Packer * p);

    static void httpRequestPack(void *obj, Packer *p);

    static HttpRequest * CreateFromUrlAndMethod(char * url, const HttpRequestMethod& method);

    static HttpRequest * CreateFromUrl(char * url);

    ConnStateData *const pinnedConnection();

    /**
     * Returns the current StoreID for the request as a nul-terminated char*.
     * Always returns the current id for the request
     * (either the request canonical url or modified ID by the helper).
     * Does not return NULL.
     */
    const char *storeId();

    /**
     * The client connection manager, if known;
     * Used for any response actions needed directly to the client.
     * ie 1xx forwarding or connection pinning state changes
     */
    CbcPointer<ConnStateData> clientConnectionManager;

    /// forgets about the cached Range header (for a reason)
    void ignoreRange(const char *reason);
    int64_t getRangeOffsetLimit(); /* the result of this function gets cached in rangeOffsetLimit */

private:
    const char *packableURI(bool full_uri) const;

    mutable int64_t rangeOffsetLimit;  /* caches the result of getRangeOffsetLimit */

protected:
    void packFirstLineInto(Packer * p, bool full_uri) const final;

    bool sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, Http::StatusCode *error) final;

    void hdrCacheInit() final;

    bool inheritProperties(const HttpMsg *aMsg) final;

///////////////////////////////////////////////////////////////////////////////
//	IHRequest
///////////////////////////////////////////////////////////////////////////////
public:

    std::string headers_get_all(std::string sep_={}) final
    {
        std::string r_{};
        r_.reserve(1024);

        for ( const auto * e_ : this->header.entries ) {

            if ( e_ ){

                const char * const cn_=e_->name.termedBuf();
                const char * const cv_=e_->value.termedBuf();
                if ( cn_ && cn_ ){

                    r_+=sep_;
                    r_+=cn_;
                    r_+={':'};
                    r_+=cv_;
                    r_+={'\n'};

                }
            }
        }

        return r_;
    }

   void set_host(const std::string &) final;

    void set_path(const std::string & s_) final 
    {
      safe_free(canonical); // force its re-build
      canonical = nullptr;
      urlpath.clean();
      if (s_.size()) urlpath=s_.c_str();
    }

    void headers_put(const t_http_hdr_types i_, const std::string & s_) final
    {
        this->header.putStr(i_,s_.c_str());
    }

    std::string get_host(void) const noexcept final 
    {
        if ( const char *const _c=this->GetHost() ) {

            return std::string{_c};
        }

        return std::string{};
    }

    bool is_host_numeric(void) const noexcept final
    {
        return flags.ttn_is_host_numeric;
    }

    std::string get_path(void) const final
    {
        if ( const size_t s_=this->urlpath.size() ) {

            if ( const char * const c_=this->urlpath.termedBuf() ) {

                if ( *c_ ) {

                    return std::string{ c_, s_ };
                }
            }
        }

        return std::string {};
    }

    titan_v3::raw_ipaddr_t get_client_addr(void) final;

    bool set_client_addr(const titan_v3::raw_ipaddr_t &) final;

    titan_v3::raw_ipaddr_t get_indirect_client_addr(void) final;

    std::string get_x_forwarded_for_iterator(void) const final
    {
        if ( const size_t s_=this->x_forwarded_for_iterator.size() ) {

            if ( const char * const c_=this->x_forwarded_for_iterator.termedBuf() ) {

                if( *c_ ) {

                    return std::string { c_, s_ };
                }
            }
        }

        return std::string {};
    }

    std::string  get_extacl_user(void) const final
    {
        if ( const size_t s_=this->extacl_user.size() ) {

            if ( const char * const c_=this->extacl_user.termedBuf() ) {

                if ( *c_ ) {

                    return std::string { c_, s_ };
                }
            }
        }

        return std::string {};
    }

    std::string  get_extacl_passwd(void) const final
    {
        if ( const size_t s_=this->extacl_passwd.size() ) {

            if ( const  char * const c_=this->extacl_passwd.termedBuf() ) {

                if(*c_) {

                    return std::string { c_, s_ };
                }
            }
        }

        return std::string {};
    }

    std::string  get_extacl_log(void) const final
    {
        if ( const size_t s_=this->extacl_log.size() ) {

            if ( const  char * const c_=this->extacl_log.termedBuf() ) {

                if( *c_ ) {

                    return std::string { c_, s_ };
                }
            }
        }
        return std::string {};
    }

    std::string  get_extacl_message(void) const final
    {
        if ( const size_t s_=this->extacl_message.size() ) {

            if ( const char * const c_=this->extacl_message.termedBuf() ) {

                if(*c_) {

                    return std::string { c_, s_ };
                }
            }
        }

        return std::string {};
    }

    int  headers_has(const t_http_hdr_types _i) const final
    {
        return (this->header.has((http_hdr_type)_i));
    }

    std::string headers_get(const t_http_hdr_types _i) final
    {
        if ( const String * const str_ =this->header.getStrEx((http_hdr_type)_i) ) {

            if ( const size_t s_=str_->size() ) {

                if ( const char * const c_=str_->termedBuf() ) {

                    if( *c_ ) {

                        return std::string{ c_, s_ };
                    }
                }
            }
        }

        return std::string {};
    }

    std::string headers_getex(const t_http_hdr_types _i)
    {
        if ( const String * const pstr=this->header.getStrEx((http_hdr_type)_i) ) {

            if (const size_t s_=pstr->size()){

                if (const char * const c_=pstr->termedBuf()){

                    if (*c_) {

                        return std::string{ c_, s_ };
                    }
                }
            }
        }

        return std::string {};
    }

    int headers_del(const t_http_hdr_types _i) final
    {
        return (this->header.delById(_i));
    }

    void  headers_clear(void) final
    {
        this->header.clean();
    }

    int get_authenticateUserAuthenticated(void) const final
    {
        return authenticateUserAuthenticated(this->auth_user_request);
    }

    std::string get_auth_user_request_username(void) const final
    {
        if ( const  char * const _c=this->auth_user_request->username() ) {

            if(*_c) {

                return std::string {_c};
            }
        }
        return std::string {};
    }

    std::string get_canonical(void) final;

    t_proto_types get_protocol(void) const final
    {
        return (this->url.getScheme());
    }

    bool set_protocol(t_proto_types _p) final
    {
        this->url.setScheme(_p);
        return true;
    }

    unsigned short get_port(void) const noexcept final 
    {
        return this->port;
    }

    void set_port(const size_t _p) noexcept final 
    {
        this->port=(unsigned short) _p;
    }

    titan_v3::IHRequestFlags & get_flags(void) noexcept final
    {
        return this->flags;
    }

    titan_v3::IBodyPipe * get_bodypipe(void) const final
    {
        return ((titan_v3::IBodyPipe *const)this->body_pipe.getRaw());
    }

    t_method_type get_method(void) const noexcept final 
    {
        return this->method.id();
    }

    bool set_method(const t_method_type _m) noexcept final 
    {
        this->method=static_cast<Http::MethodType>(_m);
        return (this->method.id()==_m);
    }

    int64_t get_content_length(void) const noexcept final 
    {
        return this->content_length;
    }

    bool is_target_server(void) const final;
    static bool is_target_server(const Comm::ConnectionPointer &);
    std::string get_sni(void) const final;
    bool can_report_errors(void) const final;
   
};

//temporary change to add more traceability
extern t_HttpRmap _RQmap;


MEMPROXY_CLASS_INLINE(HttpRequest);

#endif /* SQUID_HTTPREQUEST_H */

