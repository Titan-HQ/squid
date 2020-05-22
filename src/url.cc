/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 23    URL Parsing */

#include "squid.h"
#include "globals.h"
#include "HttpRequest.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidString.h"
#include "URL.h"

// Titax.
#include "edgelib.h"
#include "Redirection.h"

static HttpRequest *const urlParseFinish(const HttpRequestMethod& method,
                                   const AnyP::ProtocolType protocol,
                                   const char *const urlpath,
                                   const char *const host,
                                   std::string orig_host,
                                   const char *const login,
                                   const int port,
                                   HttpRequest *const request);
static HttpRequest *const urnParse(const HttpRequestMethod& method, char *const urn, HttpRequest *const request);
static const char valid_hostname_chars_u[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-._"
    "[:]"
    ;
static const char valid_hostname_chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789-."
    "[:]"
    ;

void
urlInitialize(void)
{
    debugs(23, 5, "urlInitialize: Initializing...");
    /* this ensures that the number of protocol strings is the same as
     * the enum slots allocated because the last enum is always 'MAX'.
     */
    assert(strcmp(AnyP::ProtocolType_str[AnyP::PROTO_MAX], "MAX") == 0);
    /*
     * These test that our matchDomainName() function works the
     * way we expect it to.
     */
    assert(0 == matchDomainName("foo.com", "foo.com"));
    assert(0 == matchDomainName(".foo.com", "foo.com"));
    assert(0 == matchDomainName("foo.com", ".foo.com"));
    assert(0 == matchDomainName(".foo.com", ".foo.com"));
    assert(0 == matchDomainName("x.foo.com", ".foo.com"));
    assert(0 == matchDomainName("y.x.foo.com", ".foo.com"));
    assert(0 != matchDomainName("x.foo.com", "foo.com"));
    assert(0 != matchDomainName("foo.com", "x.foo.com"));
    assert(0 != matchDomainName("bar.com", "foo.com"));
    assert(0 != matchDomainName(".bar.com", "foo.com"));
    assert(0 != matchDomainName(".bar.com", ".foo.com"));
    assert(0 != matchDomainName("bar.com", ".foo.com"));
    assert(0 < matchDomainName("zzz.com", "foo.com"));
    assert(0 > matchDomainName("aaa.com", "foo.com"));
    assert(0 == matchDomainName("FOO.com", "foo.COM"));
    assert(0 < matchDomainName("bfoo.com", "afoo.com"));
    assert(0 > matchDomainName("afoo.com", "bfoo.com"));
    assert(0 < matchDomainName("x-foo.com", ".foo.com"));

    assert(0 == matchDomainName(".foo.com", ".foo.com", mdnRejectSubsubDomains));
    assert(0 == matchDomainName("x.foo.com", ".foo.com", mdnRejectSubsubDomains));
    assert(0 != matchDomainName("y.x.foo.com", ".foo.com", mdnRejectSubsubDomains));
    assert(0 != matchDomainName(".x.foo.com", ".foo.com", mdnRejectSubsubDomains));

    assert(0 == matchDomainName("*.foo.com", "x.foo.com", mdnHonorWildcards));
    assert(0 == matchDomainName("*.foo.com", ".x.foo.com", mdnHonorWildcards));
    assert(0 == matchDomainName("*.foo.com", ".foo.com", mdnHonorWildcards));
    assert(0 != matchDomainName("*.foo.com", "foo.com", mdnHonorWildcards));
    /* more cases? */
}

/**
 * urlParseProtocol() takes begin (b) and end (e) pointers, but for
 * backwards compatibility, e defaults to NULL, in which case we
 * assume b is NULL-terminated.
 */
AnyP::ProtocolType
urlParseProtocol(const char *const b, const char *const e)
{
    /*
     * if e is NULL, b must be NULL terminated and we
     * make e point to the first whitespace character
     * after b.
     */
   const char * _e=NULL;
   const int len=(!e?((_e = (b + strcspn(b, ":")))-b):(e - b));
   if (len){
      /* test common stuff first */
      if (strncasecmp(b, "http", len) == 0)
         return AnyP::PROTO_HTTP;

      if (strncasecmp(b, "ftp", len) == 0)
         return AnyP::PROTO_FTP;

      if (strncasecmp(b, "https", len) == 0)
         return AnyP::PROTO_HTTPS;

      if (strncasecmp(b, "file", len) == 0)
         return AnyP::PROTO_FTP;

      if (strncasecmp(b, "coap", len) == 0)
         return AnyP::PROTO_COAP;

      if (strncasecmp(b, "coaps", len) == 0)
         return AnyP::PROTO_COAPS;

      if (strncasecmp(b, "gopher", len) == 0)
         return AnyP::PROTO_GOPHER;

      if (strncasecmp(b, "wais", len) == 0)
         return AnyP::PROTO_WAIS;

      if (strncasecmp(b, "cache_object", len) == 0)
         return AnyP::PROTO_CACHE_OBJECT;

      if (strncasecmp(b, "urn", len) == 0)
         return AnyP::PROTO_URN;

      if (strncasecmp(b, "whois", len) == 0)
         return AnyP::PROTO_WHOIS;
   };
   return AnyP::PROTO_NONE;
}

int
urlDefaultPort(const AnyP::ProtocolType p)
{
    switch (p) {

    case AnyP::PROTO_HTTP:
        return 80;

    case AnyP::PROTO_HTTPS:
        return 443;

    case AnyP::PROTO_FTP:
        return 21;

    case AnyP::PROTO_COAP:
    case AnyP::PROTO_COAPS:
        // coaps:// default is TBA as of draft-ietf-core-coap-08.
        // Assuming IANA policy of allocating same port for base and TLS protocol versions will occur.
        return 5683;

    case AnyP::PROTO_GOPHER:
        return 70;

    case AnyP::PROTO_WAIS:
        return 210;

    case AnyP::PROTO_CACHE_OBJECT:
        return CACHE_HTTP_PORT;

    case AnyP::PROTO_WHOIS:
        return 43;

    default:
        return 0;
    }
}

/*
 * Parse a URI/URL.
 *
 * If the 'request' arg is non-NULL, put parsed values there instead
 * of allocating a new HttpRequest.
 *
 * This abuses HttpRequest as a way of representing the parsed url
 * and its components.
 * method is used to switch parsers and to init the HttpRequest.
 * If method is Http::METHOD_CONNECT, then rather than a URL a hostname:port is
 * looked for.
 * The url is non const so that if its too long we can NULL-terminate it in place.
 */

/*
 * This routine parses a URL. Its assumed that the URL is complete -
 * ie, the end of the string is the end of the URL. Don't pass a partial
 * URL here as this routine doesn't have any way of knowing whether
 * its partial or not (ie, it handles the case of no trailing slash as
 * being "end of host with implied path of /".
 */
HttpRequest * const
urlParse(const HttpRequestMethod& method, char *const url, HttpRequest *const request)
{
   if (!url || !*url ){
      return NULL;
   };
    LOCAL_ARRAY(char, proto, MAX_URL);
    LOCAL_ARRAY(char, login, MAX_URL);
    LOCAL_ARRAY(char, host, MAX_URL);
    LOCAL_ARRAY(char, urlpath, MAX_URL);
    proto[0] = host[0] = urlpath[0] = login[0] = '\0';


    size_t l_{};

    if ((l_ = strlen(url)) + Config.appendDomainLen > (MAX_URL - 1)) {
        /* terminate so it doesn't overflow other buffers */
        *(url + (MAX_URL >> 1)) = '\0';
        debugs(23, DBG_IMPORTANT, "urlParse: URL too large (" << l_ << " bytes)");
        return nullptr;
    };
    
    int port{};
    AnyP::ProtocolType protocol = AnyP::PROTO_NONE;
    
    if (method == Http::METHOD_CONNECT) {
        port = CONNECT_PORT;

        if (sscanf(url, "[%[^]]]:%d", host, &port) < 1)
            if (sscanf(url, "%[^:]:%d", host, &port) < 1)
                return nullptr;

    } else if ((method == Http::METHOD_OPTIONS || method == Http::METHOD_TRACE) && strcmp(url, "*") == 0) {
        return urlParseFinish(method, AnyP::PROTO_HTTP, url, host, std::string{}, login, urlDefaultPort(AnyP::PROTO_HTTP), request);
    } else if (!strncmp(url, "urn:", 4)) {
        return urnParse(method, url, request);
    } else {
        /* Parse the URL: */
        const char * src = url;
        char * dst=nullptr;
        size_t i_ = 0;
        /* Find first : - everything before is protocol */
        for (dst = proto; i_ < l_ && *src != ':'; ++i_, ++src, ++dst) {
            *dst = *src;
        }
        if (i_ >= l_)
            return nullptr;
        *dst = '\0';

        /* Then its :// */
        if ((i_+3) > l_ || *src != ':' || *(src + 1) != '/' || *(src + 2) != '/')
            return nullptr;
        i_ += 3;
        src += 3;

        /* Then everything until first /; thats host (and port; which we'll look for here later) */
        // bug 1881: If we don't get a "/" then we imply it was there
        // bug 3074: We could just be given a "?" or "#". These also imply "/"
        // bug 3233: whitespace is also a hostname delimiter.
        for (dst = host; i_ < l_ && *src != '/' && *src != '?' && *src != '#' && *src != '\0' && !xisspace(*src); ++i_, ++src, ++dst) {
            *dst = *src;
        }

        /*
         * We can't check for "i >= l" here because we could be at the end of the line
         * and have a perfectly valid URL w/ no trailing '/'. In this case we assume we've
         * been -given- a valid URL and the path is just '/'.
         */
        if (i_ > l_)
            return nullptr;
        *dst = '\0';

        // bug 3074: received 'path' starting with '?', '#', or '\0' implies '/'
        if (*src == '?' || *src == '#' || *src == '\0') {
            urlpath[0] = '/';
            dst = &urlpath[1];
        } else {
            dst = urlpath;
        }
        /* Then everything from / (inclusive) until \r\n or \0 - thats urlpath */
        for (; i_ < l_ && *src != '\r' && *src != '\n' && *src != '\0'; ++i_, ++src, ++dst) {
            *dst = *src;
        }

        /* We -could- be at the end of the buffer here */
        if (i_ > l_)
            return nullptr;
        /* If the URL path is empty we set it to be "/" */
        if (dst == urlpath) {
            *dst = '/';
            ++dst;
        }
        *dst = '\0';

        protocol = urlParseProtocol(proto);
        port = urlDefaultPort(protocol);

        /* Is there any login information? (we should eventually parse it above) */
        char * t_ = strrchr(host, '@');
        if (t_ != nullptr) {
            strncpy((char *) login, (char *) host, sizeof(login)-1);
            login[sizeof(login)-1] = '\0';
            t_ = strrchr(login, '@');
            *t_ = 0;
            strncpy((char *) host, t_ + 1, sizeof(host)-1);
            host[sizeof(host)-1] = '\0';
            // Bug 4498: URL-unescape the login info after extraction
            rfc1738_unescape(login);
        }

        /* Is there any host information? (we should eventually parse it above) */
        if (*host == '[') {
            /* strip any IPA brackets. valid under IPv6. */
            dst = host;
            /* only for IPv6 sadly, pre-IPv6/URL code can't handle the clean result properly anyway. */
            src = host;
            ++src;
            l_ = strlen(host);
            i_ = 1;
            for (; i_ < l_ && *src != ']' && *src != '\0'; ++i_, ++src, ++dst) {
                *dst = *src;
            }

            /* we moved in-place, so truncate the actual hostname found */
            *dst = '\0';
            ++dst;

            /* skip ahead to either start of port, or original EOS */
            while (*dst != '\0' && *dst != ':')
                ++dst;
            t_ = dst;
        } else {
            t_ = strrchr(host, ':');

            if (t_ != strchr(host,':') ) {
                /* RFC 2732 states IPv6 "SHOULD" be bracketed. allowing for times when its not. */
                /* RFC 3986 'update' simply modifies this to an "is" with no emphasis at all! */
                /* therefore we MUST accept the case where they are not bracketed at all. */
                t_ = nullptr;
            }
        }

        // Bug 3183 sanity check: If scheme is present, host must be too.
        if (protocol != AnyP::PROTO_NONE && host[0] == '\0') {
            debugs(23, DBG_IMPORTANT, "SECURITY ALERT: Missing hostname in URL '" << url << "'. see access.log for details.");
            return nullptr;
        };

        if (t_ && *t_ == ':') {
            *t_ = '\0';
            ++t_;
            port = atoi(t_);
        };
    };

    for (char * t_ = host; *t_; ++t_)
        *t_ = xtolower(*t_);

    if (stringHasWhitespace(host)) {
        if (URI_WHITESPACE_STRIP == Config.uri_whitespace) {
            char * t_=host;
            char * q_=t_;
            while (*t_) {
                if (!xisspace(*t_)) {
                    *q_ = *t_;
                    ++q_;
                }
                ++t_;
            }
            *q_ = '\0';
        }
    }

    debugs(23, 3, "urlParse: Split URL '" << url << "' into proto='" << proto << "', host='" << host << "', port='" << port << "', path='" << urlpath << "'");

    if (Config.onoff.check_hostnames && strspn(host, Config.onoff.allow_underscore ? valid_hostname_chars_u : valid_hostname_chars) != strlen(host)) {
        debugs(23, DBG_IMPORTANT, "urlParse: Illegal character in hostname '" << host << "'");
        return nullptr;
    }

    // Titax
    // titanlib
    const std::string orig_host = host;
    // write host if redirection 
    redirections_get_redi_host( orig_host.c_str(), orig_host.size(), host, sizeof( host ) );

    if ( !host[0] ) {

      strlcpy( host, orig_host.c_str(), sizeof( host ) );
    }

    /* For IPV6 addresses also check for a colon */
    if (Config.appendDomain && !strchr(host, '.') && !strchr(host, ':'))
        strncat(host, Config.appendDomain, SQUIDHOSTNAMELEN - strlen(host) - 1);

    /* remove trailing dots from hostnames */
    while ((l_ = strlen(host)) > 0 && host[--l_] == '.')
        host[l_] = '\0';

    /* reject duplicate or leading dots */
    if (strstr(host, "..") || *host == '.') {
        debugs(23, DBG_IMPORTANT, "urlParse: Illegal hostname '" << host << "'");
        return nullptr;
    }

    if (port < 1 || port > 65535) {
        debugs(23, 3, "urlParse: Invalid port '" << port << "'");
        return nullptr;
    }

#if HARDCODE_DENY_PORTS
    /* These ports are filtered in the default squid.conf, but
     * maybe someone wants them hardcoded... */
    if (port == 7 || port == 9 || port == 19) {
        debugs(23, DBG_CRITICAL, "urlParse: Deny access to port " << port);
        return NULL;
    }
#endif

    if (stringHasWhitespace(urlpath)) {
        debugs(23, 2, "urlParse: URI has whitespace: {" << url << "}");

      char * t_=nullptr;
        switch (Config.uri_whitespace) {

        case URI_WHITESPACE_DENY:
             return nullptr;

        case URI_WHITESPACE_ALLOW:
            break;

         case URI_WHITESPACE_ENCODE:{
             t_ = rfc1738_escape_unescaped(urlpath);
             xstrncpy(urlpath, t_, MAX_URL);
         }break;

        case URI_WHITESPACE_CHOP:
            *(urlpath + strcspn(urlpath, w_space)) = '\0';
            break;

        case URI_WHITESPACE_STRIP:
         default:{
             char * q_=t_=urlpath;

             while (*t_) {
                 if (!xisspace(*t_)) {
                     *q_ = *t_;
                     ++q_;
                 };
                 ++t_;
             };
             *q_ = '\0';
          }break;
    };
   };

    return urlParseFinish(method, protocol, urlpath, host, orig_host, login, port, request);
}

/**
 * Update request with parsed URI data.  If the request arg is
 * non-NULL, put parsed values there instead of allocating a new
 * HttpRequest.
 */
HttpRequest * const
urlParseFinish(const HttpRequestMethod& method,
               const AnyP::ProtocolType protocol,
               const char *const urlpath,
               const char *const host,
               std::string orig_host,
               const char *const login,
               const int port,
               HttpRequest * const request){
   if (HttpRequest * const _retreq=(request?request:new HttpRequest(method, protocol, urlpath))){
      if (_retreq==request){
         _retreq->initHTTP(method, protocol, urlpath);
         safe_free(_retreq->canonical);
      };
      _retreq->SetHost(host);
      strlcpy(_retreq->login, login, sizeof(_retreq->login));
      _retreq->orig_host=std::move(orig_host);  // Titax.
      _retreq->port = (unsigned short) port;
      return _retreq;
   };
   assert(0 && "urlParseFinish");
   return nullptr;

}

static HttpRequest * const
urnParse(const HttpRequestMethod& method, char *const urn, HttpRequest *const request)
{
    debugs(50, 5, "urnParse: " << urn);
    if (request) {
        request->initHTTP(method, AnyP::PROTO_URN, urn + 4);
        safe_free(request->canonical);
        return request;
    }
    return (new HttpRequest(method, AnyP::PROTO_URN, urn + 4));
}

const char * const urlCanonicalEx(HttpRequest *const request, size_t *const  outlen){
    LOCAL_ARRAY(char, portbuf, 32);
    LOCAL_ARRAY(char, urlbuf, MAX_URL);


//possible it is a bug - begin
   if (request->canonical){
      if (*request->canonical){
         if (!request->canonical_sz){
            request->canonical_sz=strlen(request->canonical);
         };
         (*outlen)=request->canonical_sz;
         return request->canonical;
      } else {
        safe_free(request->canonical);
      };
   };
//possible it is a bug - end

    if (request->url.getScheme() == AnyP::PROTO_URN) {
        request->canonical_sz=snprintf(urlbuf, MAX_URL, "urn:" SQUIDSTRINGPH,
                 SQUIDSTRINGPRINT(request->urlpath));
    } else {
        switch (request->method.id()) {

        case Http::METHOD_CONNECT:
            request->canonical_sz=snprintf(urlbuf, MAX_URL, "%s:%d", request->GetHost(), request->port);
            break;

        default: {
            portbuf[0] = '\0';

            if (request->port != urlDefaultPort(request->url.getScheme()))
                snprintf(portbuf, 32, ":%d", request->port);

            request->canonical_sz = snprintf(urlbuf, MAX_URL, "%s://%s%s%s%s" SQUIDSTRINGPH,
                     request->url.getScheme().c_str(),
                     request->login,
                     *request->login ? "@" : null_string,
                     request->GetHost(),
                     portbuf,
                     SQUIDSTRINGPRINT(request->urlpath));
        }
        }
    }

    (*outlen)=request->canonical_sz;

    return ((request->canonical = xstrdupex(urlbuf,request->canonical_sz)));
}


std::string urlCanonicalStr(HttpRequest *const r_){   
   size_t l_{};
   if (const char * const s_=urlCanonicalEx(r_,&l_)){
      return (l_?std::string{s_,l_}:std::string{s_,(r_->canonical_sz=strlen(s_))});
   };
   return std::string{};
}

const char * const
urlCanonical(HttpRequest * const request)
{
    size_t l=0;
    return (urlCanonicalEx(request,&l));
}


/** \todo AYJ: Performance: This is an *almost* duplicate of urlCanonical. But elides the query-string.
 *        After copying it on in the first place! Would be less code to merge the two with a flag parameter.
 *        and never copy the query-string part in the first place
 */
bool
urlCanonicalClean(const HttpRequest *const request, char * const _out, const uint32_t _osz)
{
   if (request && _out && _osz ){
       //LOCAL_ARRAY(char, portbuf, 32);
       //LOCAL_ARRAY(char, loginbuf, MAX_LOGIN_SZ + 1);

       if (request->url.getScheme() == AnyP::PROTO_URN) {
          (void)snprintf(_out, _osz, "urn:" SQUIDSTRINGPH,
                    SQUIDSTRINGPRINT(request->urlpath));
       } else {

           switch (request->method.id()) {

           case Http::METHOD_CONNECT:
              (void)snprintf(_out, _osz, "%s:%d", request->GetHost(), request->port);
               break;

           default: {
              char portbuf[32];
              char loginbuf[MAX_LOGIN_SZ + 1];
              char *t;
              portbuf[0] = '\0';

               if (request->port != urlDefaultPort(request->url.getScheme()))
                  (void)snprintf(portbuf, 32, ":%d", request->port);

               loginbuf[0] = '\0';

               if ((int) strlen(request->login) > 0) {
                  (void)strcpy(loginbuf, request->login);

                   if ((t = strchr(loginbuf, ':')))
                       *t = '\0';

                   (void)strcat(loginbuf, "@");
               }

               (void)snprintf(_out, _osz, "%s://%s%s%s" SQUIDSTRINGPH,
                        request->url.getScheme().c_str(),
                        loginbuf,
                        request->GetHost(),
                        portbuf,
                        SQUIDSTRINGPRINT(request->urlpath));

               // strip arguments AFTER a question-mark
               if (Config.onoff.strip_query_terms)
                   if ((t = strchr(_out, '?')))
                       *(++t) = '\0';
              }break;
           };
       };

       if (stringHasCntl(_out))
          (void)xstrncpy(_out, rfc1738_escape_unescaped(_out), _osz);
       return true;
   };
   return false;
}

/**
 * Yet another alternative to urlCanonical.
 * This one adds the https:// parts to Http::METHOD_CONNECT URL
 * for use in error page outputs.
 * Luckily we can leverage the others instead of duplicating.
 */
bool
urlCanonicalFakeHttps(const HttpRequest *const request,char *const _out, const uint32_t _osz)
{
   if (request && _out && _osz){
      if (request->method == Http::METHOD_CONNECT && request->port == 443) {
         // method CONNECT and port HTTPS
          (void)snprintf(_out, _osz, "https://%s/*", request->GetHost());
          return true;
      };
      // else do the normal complete canonical thing.
      return (urlCanonicalClean(request,_out,_osz));
   };
   return false;
}

/*
 * Test if a URL is relative.
 *
 * RFC 2396, Section 5 (Page 17) implies that in a relative URL, a '/' will
 * appear before a ':'.
 */
bool
urlIsRelative(const char *const url)
{


    if (url == NULL) {
        return (false);
    }
    if (*url == '\0') {
        return (false);
    }

    const char *p;
    for (p = url; *p != '\0' && *p != ':' && *p != '/'; ++p);

    if (*p == ':') {
        return (false);
    }
    return (true);
}

/*
 * Convert a relative URL to an absolute URL using the context of a given
 * request.
 *
 * It is assumed that you have already ensured that the URL is relative.
 *
 * If NULL is returned it is an indication that the method in use in the
 * request does not distinguish between relative and absolute and you should
 * use the url unchanged.
 *
 * If non-NULL is returned, it is up to the caller to free the resulting
 * memory using safe_free().
 */
char * const
urlMakeAbsolute(const HttpRequest * const req, const char *const relUrl)
{

    if (req->method.id() == Http::METHOD_CONNECT) {
        return (NULL);
    }

    char *const urlbuf = (char *const)xmalloc(MAX_URL * sizeof(char));

    if (req->url.getScheme() == AnyP::PROTO_URN) {
        (void)snprintf(urlbuf, MAX_URL, "urn:" SQUIDSTRINGPH,
                 SQUIDSTRINGPRINT(req->urlpath));
        return (urlbuf);
    }

    size_t urllen;

    if (req->port != urlDefaultPort(req->url.getScheme())) {
        urllen = snprintf(urlbuf, MAX_URL, "%s://%s%s%s:%d",
                          req->url.getScheme().c_str(),
                          req->login,
                          *req->login ? "@" : null_string,
                          req->GetHost(),
                          req->port
                         );
    } else {
        urllen = snprintf(urlbuf, MAX_URL, "%s://%s%s%s",
                          req->url.getScheme().c_str(),
                          req->login,
                          *req->login ? "@" : null_string,
                          req->GetHost()
                         );
    }

    if (relUrl[0] == '/') {
       (void)strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
    } else {
        const char *path = req->urlpath.termedBuf();
        const char *last_slash = strrchr(path, '/');

        if (last_slash == NULL) {
            urlbuf[urllen] = '/';
            ++urllen;
            (void)strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
        } else {
            ++last_slash;
            size_t pathlen = last_slash - path;
            if (pathlen > MAX_URL - urllen - 1) {
                pathlen = MAX_URL - urllen - 1;
            }
            (void)strncpy(&urlbuf[urllen], path, pathlen);
            urllen += pathlen;
            if (urllen + 1 < MAX_URL) {
               (void)strncpy(&urlbuf[urllen], relUrl, MAX_URL - urllen - 1);
            }
        }
    }

    return (urlbuf);
}

int
matchDomainName(const char *const  _h, const char *const d, uint flags)
{
   const char * h=(const char *const)_h;
   const bool hostIncludesSubdomains = (*h == '.');

   while ('.' == *h) ++h;

    int hl = strlen(h);
    if (hl == 0) return -1;

    int dl = strlen(d);

    /*
     * Start at the ends of the two strings and work towards the
     * beginning.
     */
    while (xtolower(h[--hl]) == xtolower(d[--dl])) {
        if (hl == 0 && dl == 0) {
            /*
             * We made it all the way to the beginning of both
             * strings without finding any difference.
             */
            return 0;
        }

        if (0 == hl) {
            /*
             * The host string is shorter than the domain string.
             * There is only one case when this can be a match.
             * If the domain is just one character longer, and if
             * that character is a leading '.' then we call it a
             * match.
             */

            if (1 == dl && '.' == d[0])
                return 0;
            else
                return -1;
        }

        if (0 == dl)
	{
            /*
             * The domain string is shorter than the host string.
             * This is a match only if the first domain character
             * is a leading '.'.
             */
            if ('.' == d[0])
	    {
                if (flags & mdnRejectSubsubDomains)
		{
                    // Check for sub-sub domain and reject
                    while(--hl >= 0 && h[hl] != '.');
                    if (hl < 0) {
                        // No sub-sub domain found, but reject if there is a
                        // leading dot in given host string (which is removed
                        // before the check is started).
                        return hostIncludesSubdomains ? 1 : 0;
                    } else
                        return 1; // sub-sub domain, reject
                } else
                    return 0;
            } else
                return 1;
        }
    }

    /*
     * We found different characters in the same position (from the end).
     */

    // If the h has a form of "*.foo.com" and d has a form of "x.foo.com"
    // then the h[hl] points to '*', h[hl+1] to '.' and d[dl] to 'x'
    // The following checks are safe, the "h[hl + 1]" in the worst case is '\0'.
    if ((flags & mdnHonorWildcards) && h[hl] == '*' && h[hl + 1] == '.')
        return 0;

    /*
     * If one of those character is '.' then its special.  In order
     * for splay tree sorting to work properly, "x-foo.com" must
     * be greater than ".foo.com" even though '-' is less than '.'.
     */
    if ('.' == d[dl])
        return 1;

    if ('.' == h[hl])
        return -1;

    return (xtolower(h[hl]) - xtolower(d[dl]));
}

/*
 * return true if we can serve requests for this method.
 */
int
urlCheckRequest(const HttpRequest * const r)
{
    int rc = 0;
    /* protocol "independent" methods
     *
     * actually these methods are specific to HTTP:
     * they are methods we recieve on our HTTP port,
     * and if we had a FTP listener would not be relevant
     * there.
     *
     * So, we should delegate them to HTTP. The problem is that we
     * do not have a default protocol from the client side of HTTP.
     */

    if (r->method == Http::METHOD_CONNECT)
        return 1;

    // we support OPTIONS and TRACE directed at us (with a 501 reply, for now)
    // we also support forwarding OPTIONS and TRACE, except for the *-URI ones
    if (r->method == Http::METHOD_OPTIONS || r->method == Http::METHOD_TRACE)
        return (r->header.getInt64(HDR_MAX_FORWARDS) == 0 || r->urlpath != "*");

    if (r->method == Http::METHOD_PURGE)
        return 1;

    /* does method match the protocol? */
    switch (r->url.getScheme()) {

    case AnyP::PROTO_URN:

    case AnyP::PROTO_HTTP:

    case AnyP::PROTO_CACHE_OBJECT:
        rc = 1;
        break;

    case AnyP::PROTO_FTP:

        if (r->method == Http::METHOD_PUT)
            rc = 1;

    case AnyP::PROTO_GOPHER:

    case AnyP::PROTO_WAIS:

    case AnyP::PROTO_WHOIS:
        if (r->method == Http::METHOD_GET)
            rc = 1;
        else if (r->method == Http::METHOD_HEAD)
            rc = 1;

        break;

    case AnyP::PROTO_HTTPS:
#if USE_OPENSSL

        rc = 1;

        break;

#else
        /*
        * Squid can't originate an SSL connection, so it should
        * never receive an "https:" URL.  It should always be
        * CONNECT instead.
        */
        rc = 0;

#endif

    default:
        break;
    }

    return rc;
}

/*
 * Quick-n-dirty host extraction from a URL.  Steps:
 *      Look for a colon
 *      Skip any '/' after the colon
 *      Copy the next SQUID_MAXHOSTNAMELEN bytes to host[]
 *      Look for an ending '/' or ':' and terminate
 *      Look for login info preceeded by '@'
 */

class URLHostName
{

public:
    char *const  extract(char const *const url);

private:
    static char Host [SQUIDHOSTNAMELEN];
    void init(char const *const);
    void findHostStart();
    void trimTrailingChars();
    void trimAuth();
    char const *hostStart;
    char const *url;
};

char * const
urlHostname(const char *const url)
{
    return URLHostName().extract(url);
}

char URLHostName::Host[SQUIDHOSTNAMELEN];

void
URLHostName::init(char const *const aUrl)
{
    Host[0] = '\0';
    url = aUrl;
}

void
URLHostName::findHostStart()
{
    if (NULL == (hostStart = strchr(url, ':')))
        return;

    ++hostStart;

    while (*hostStart != '\0' && *hostStart == '/')
        ++hostStart;

    if (*hostStart == ']')
        ++hostStart;
}

void
URLHostName::trimTrailingChars()
{
    char *t;

    if ((t = strchr(Host, '/')))
        *t = '\0';

    if ((t = strrchr(Host, ':')))
        *t = '\0';

    if ((t = strchr(Host, ']')))
        *t = '\0';
}

void
URLHostName::trimAuth()
{
    char *t;

    if ((t = strrchr(Host, '@'))) {
        ++t;
        memmove(Host, t, strlen(t) + 1);
    }
}

char * const
URLHostName::extract(char const *const aUrl)
{
    init(aUrl);
    findHostStart();

    if (hostStart == NULL)
        return NULL;

    xstrncpy(Host, hostStart, SQUIDHOSTNAMELEN);

    trimTrailingChars();

    trimAuth();

    return Host;
}

