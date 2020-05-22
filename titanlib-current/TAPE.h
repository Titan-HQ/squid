/* 
 * $Id$
 *
 */

#ifndef TAPE_H
#define	TAPE_H
#include "global.h"
#include <libpq-fe.h>
//------------------------------------------------------------------------------   
typedef enum {
   PROTO_NONE = 0,
   PROTO_HTTP,
   PROTO_FTP,
   PROTO_HTTPS,
   PROTO_COAP,
   PROTO_COAPS,
   PROTO_GOPHER,
   PROTO_WAIS,
   PROTO_CACHE_OBJECT,
   PROTO_ICP,
   #if USE_HTCP
      PROTO_HTCP,
   #endif
   PROTO_URN,
   PROTO_WHOIS,
   //PROTO_INTERNAL,
   PROTO_ICY,
   PROTO_DNS,
   PROTO_UNKNOWN,
   PROTO_MAX
} t_proto_types;
//------------------------------------------------------------------------------   
typedef enum {
   scNone = 0,
   scContinue = 100,
   scSwitchingProtocols = 101,
   scProcessing = 102,      // RFC2518 section 10.1
   scEarlyHints = 103,      /**< draft-kazuho-early-hints-status-code */
   scOkay = 200,
   scCreated = 201,
   scAccepted = 202,
   scNonAuthoritativeInformation = 203,
   scNoContent = 204,
   scResetContent = 205,
   scPartialContent = 206,
   scMultiStatus = 207,     ///< RFC2518 section 10.2 / RFC4918
   scAlreadyReported = 208, //< RFC5842
   scImUsed = 226,          //< RFC3229
   scMultipleChoices = 300,
   scMovedPermanently = 301,
   scFound = 302,
   scSeeOther = 303,
   scNotModified = 304,
   scUseProxy = 305,
   scTemporaryRedirect = 307,
   scPermanentRedirect = 308, //< RFC7238
   scBadRequest = 400,
   scUnauthorized = 401,
   scPaymentRequired = 402,
   scForbidden = 403,
   scNotFound = 404,
   scMethodNotAllowed = 405,
   scNotAcceptable = 406,
   scProxyAuthenticationRequired = 407,
   scRequestTimeout = 408,
   scConflict = 409,
   scGone = 410,
   scLengthRequired = 411,
   scPreconditionFailed = 412,
   scPayloadTooLarge = 413,
   scUriTooLong = 414,
   scUnsupportedMediaType = 415,
   scRequestedRangeNotSatisfied = 416,
   scExpectationFailed = 417,
   scMisdirectedRequest = 421,     /**< draft-ietf-httpbis-http2-16 section 9.1.2 */           
   scUnprocessableEntity = 422,    //< RFC2518 section 10.3 / RFC4918
   scLocked = 423,                 //< RFC2518 section 10.4 / RFC4918
   scFailedDependency = 424,       //< RFC2518 section 10.5 / RFC4918
   scUpgradeRequired = 426,
   scPreconditionRequired = 428,   //< RFC6585
   scTooManyRequests = 429,        //< RFC6585
   scRequestHeaderFieldsTooLarge = 431, //< RFC6585
   scUnavailableForLegalReasons = 451,  //< RFC7725
   scInternalServerError = 500,
   scNotImplemented = 501,
   scBadGateway = 502,
   scServiceUnavailable = 503,
   scGatewayTimeout = 504,
   scHttpVersionNotSupported = 505,
   scVariantAlsoNegotiates = 506,  //< RFC2295
   scInsufficientStorage = 507,    //< RFC2518 section 10.6 / RFC4918
   scLoopDetected = 508,           //< RFC5842
   scNotExtended = 510,            //< RFC2774
   scNetworkAuthenticationRequired = 511, //< RFC6585

    // The 6xx codes below are for internal use only: Bad requests result
    // in scBadRequest; bad responses in scGatewayTimeout.

   scInvalidHeader = 600,          //< Squid header parsing error
   scHeaderTooLarge = 601          // Header too large to process
} t_status_codes;
//------------------------------------------------------------------------------   
typedef enum {
   ERR_NONE,

   /* Access Permission Errors.  Prefix new with ERR_ACCESS_ */
   ERR_ACCESS_DENIED,
   ERR_CACHE_ACCESS_DENIED,
   ERR_CACHE_MGR_ACCESS_DENIED,
   ERR_FORWARDING_DENIED,
   ERR_NO_RELAY,
   ERR_CANNOT_FORWARD,

   /* TCP Errors. */
   ERR_READ_TIMEOUT,
   ERR_LIFETIME_EXP,
   ERR_READ_ERROR,
   ERR_WRITE_ERROR,
   ERR_CONNECT_FAIL,
   ERR_SECURE_CONNECT_FAIL,
   ERR_SOCKET_FAILURE,

   /* DNS Errors */
   ERR_DNS_FAIL,
   ERR_URN_RESOLVE,

   /* HTTP Errors */
   ERR_ONLY_IF_CACHED_MISS,    /* failure to satisfy only-if-cached request */
   ERR_TOO_BIG,
   ERR_INVALID_RESP,
   ERR_UNSUP_HTTPVERSION,     /* HTTP version is not supported */
   ERR_INVALID_REQ,
   ERR_UNSUP_REQ,
   ERR_INVALID_URL,
   ERR_ZERO_SIZE_OBJECT,
   ERR_PRECONDITION_FAILED,
   ERR_CONFLICT_HOST,

   /* FTP Errors */
   ERR_FTP_DISABLED,
   ERR_FTP_UNAVAILABLE,
   ERR_FTP_FAILURE,
   ERR_FTP_PUT_ERROR,
   ERR_FTP_NOT_FOUND,
   ERR_FTP_FORBIDDEN,
   ERR_FTP_PUT_CREATED,        /* !error,a note that the file was created */
   ERR_FTP_PUT_MODIFIED,       /* modified, !created */

   /* ESI Errors */
   ERR_ESI,                    /* Failure to perform ESI processing */

   /* ICAP Errors */
   ERR_ICAP_FAILURE,

   /* Squid problem */
   ERR_GATEWAY_FAILURE,

   /* Special Cases */
   ERR_DIR_LISTING,            /* Display of remote directory (FTP, Gopher) */
   ERR_SQUID_SIGNATURE,        /* not really an error */
   ERR_SHUTTING_DOWN,

   // NOTE: error types defined below TCP_RESET are optional and do not generate
   //       a log warning if the files are missing
   TCP_RESET,                  // Send TCP RST packet instead of error page

   /* Cache Manager GUI can install a manager index/home page */
   MGR_INDEX,

   ERR_MAX
} t_err_type;
//------------------------------------------------------------------------------
typedef enum {
   METHOD_NONE = 0,
   // RFC 2616 (HTTP)
   METHOD_GET,
   METHOD_POST,
   METHOD_PUT,
   METHOD_HEAD,
   METHOD_CONNECT,
   METHOD_TRACE,
   METHOD_OPTIONS,
   METHOD_DELETE,
   // RFC 3253
   METHOD_CHECKOUT,
   METHOD_CHECKIN,
   METHOD_UNCHECKOUT,
   METHOD_MKWORKSPACE,
   METHOD_VERSION_CONTROL,
   METHOD_REPORT,
   METHOD_UPDATE,
   METHOD_LABEL,
   METHOD_MERGE,
   METHOD_BASELINE_CONTROL,
   METHOD_MKACTIVITY,
   // RFC 4918 (WebDAV)
   METHOD_PROPFIND,
   METHOD_PROPPATCH,
   METHOD_MKCOL,
   METHOD_COPY,
   METHOD_MOVE,
   METHOD_LOCK,
   METHOD_UNLOCK,
   // RFC 5323
   METHOD_SEARCH,

   // RFC 7540
   METHOD_PRI,              
   // Squid extension methods
   METHOD_PURGE,
   METHOD_OTHER,
   METHOD_ENUM_END  // MUST be last, (yuck) this is used as an array-initialization index constant!
} t_method_type;
//------------------------------------------------------------------------------   
typedef enum {
   HDR_BAD_HDR = -1,
   HDR_ACCEPT = 0,                     //< RFC 2608, 2616
   HDR_ACCEPT_CHARSET,                 //< RFC 2608, 2616
   HDR_ACCEPT_ENCODING,                //< RFC 2608, 2616
   //HDR_ACCEPT_FEATURES,              // experimental RFC 2295
   HDR_ACCEPT_LANGUAGE,                //< RFC 2608, 2616
   HDR_ACCEPT_RANGES,                  //< RFC 2608, 2616
   HDR_AGE,                            //< RFC 2608, 2616
   HDR_ALLOW,                          //< RFC 2608, 2616
   HDR_ALTERNATE_PROTOCOL,             //< GFE custom header we may have to erase
   HDR_AUTHENTICATION_INFO,            //< RFC 2617
   HDR_AUTHORIZATION,                  //< RFC 2608, 2616, 4559
   HDR_CACHE_CONTROL,                  //< RFC 2608, 2616
   HDR_CONNECTION,                     //< RFC 2608, 2616
   HDR_CONTENT_BASE,                   //< RFC 2608
   HDR_CONTENT_DISPOSITION,            //< RFC 2183, 2616
   HDR_CONTENT_ENCODING,               //< RFC 2608, 2616
   HDR_CONTENT_LANGUAGE,               //< RFC 2608, 2616
   HDR_CONTENT_LENGTH,                 //< RFC 2608, 2616
   HDR_CONTENT_LOCATION,               //< RFC 2608, 2616
   HDR_CONTENT_MD5,                    //< RFC 2608, 2616
   HDR_CONTENT_RANGE,                  //< RFC 2608, 2616
   HDR_CONTENT_TYPE,                   //< RFC 2608, 2616
   HDR_COOKIE,                         //< de-facto and RFC 2965 header we may need to erase
   HDR_COOKIE2,                        //< obsolete RFC 2965 header we may need to erase
   HDR_DATE,                           //< RFC 2608, 2616
   //HDR_DAV,                          // RFC 2518
   //HDR_DEPTH,                        // RFC 2518
   //HDR_DERIVED_FROM/                 // deprecated RFC 2608
   //HDR_DESTINATION,                  // RFC 2518
   HDR_ETAG,                           //< RFC 2608, 2616
   HDR_EXPECT,                         //< RFC 2616, 2616
   HDR_EXPIRES,                        //< RFC 2608, 2616
   HDR_FORWARDED,                      //< RFC 2608, 2616
   HDR_FROM,                           //< RFC 2608, 2616
   HDR_HOST,                           //< RFC 2608, 2616
   HDR_HTTP2_SETTINGS,                 //< HTTP/2.0 upgrade header. see draft-ietf-httpbis-http2-04
   //HDR_IF,                           //RFC 2518
   HDR_IF_MATCH,                       //< RFC 2608, 2616
   HDR_IF_MODIFIED_SINCE,              //< RFC 2608, 2616
   HDR_IF_NONE_MATCH,                  //< RFC 2608, 2616
   HDR_IF_RANGE,                       //< RFC 2608, 2616
   HDR_IF_UNMODIFIED_SINCE,            //< RFC 2608, 2616
   HDR_KEEP_ALIVE,                     //< obsolete HTTP/1.0 header we may need to erase
   HDR_KEY,                            //< experimental RFC Draft draft-fielding-http-key-02
   HDR_LAST_MODIFIED,                  //< RFC 2608, 2616
   HDR_LINK,                           //< RFC 2068
   HDR_LOCATION,                       //< RFC 2608, 2616
   //HDR_LOCK_TOKEN,                   // RFC 2518
   HDR_MAX_FORWARDS,                   //< RFC 2608, 2616
   HDR_MIME_VERSION,                   //< RFC 2626
   HDR_NEGOTIATE,                      //< experimental RFC 2295. Why only this one from 2295?
   //HDR_OVERWRITE,                    // RFC 2518
   HDR_ORIGIN,                         //CORS Draft specification (see http://www.w3.org/TR/cors/)
   HDR_PRAGMA,                         //< deprecated RFC 2068,2616 header we may need to erase
   HDR_PROXY_AUTHENTICATE,             //< RFC 2608, 2616, 2617
   HDR_PROXY_AUTHENTICATION_INFO,      //< RFC 2617
   HDR_PROXY_AUTHORIZATION,            //< RFC 2608, 2616, 2617
   HDR_PROXY_CONNECTION,               //< obsolete Netscape header we may need to erase.
   HDR_PROXY_SUPPORT,                  //< RFC 4559
   HDR_PUBLIC,                         //< RFC 2608
   HDR_RANGE,                          //< RFC 2608, 2616
   HDR_REFERER,                        //< RFC 2608, 2616
   HDR_REQUEST_RANGE,                  //< some clients use this, sigh
   HDR_RETRY_AFTER,                    //< RFC 2608, 2616
   HDR_SERVER,                         //< RFC 2608, 2616
   HDR_SET_COOKIE,                     //< de-facto standard header we may need to erase
   HDR_SET_COOKIE2,                    //< obsolete RFC 2965 header we may need to erase
   //HDR_STATUS_URI,                   // RFC 2518
   //HDR_TCN,                          // experimental RFC 2295
   HDR_TE,                             //< RFC 2616
   //HDR_TIMEOUT,                      // RFC 2518
   HDR_TITLE,                          // obsolete draft suggested header
   HDR_TRAILER,                        //< RFC 2616
   HDR_TRANSFER_ENCODING,              //< RFC 2608, 2616
   HDR_TRANSLATE,                      //< IIS custom header we may need to erase
   HDR_UNLESS_MODIFIED_SINCE,          //< IIS custom header we may need to erase
   HDR_UPGRADE,                        //< RFC 2608, 2616
   HDR_USER_AGENT,                     //< RFC 2608, 2616
   //HDR_VARIANT_VARY,                 // experimental RFC 2295
   HDR_VARY,                           //< RFC 2608, 2616
   HDR_VIA,                            //< RFC 2608, 2616
   HDR_WARNING,                        //< RFC 2608, 2616
   HDR_WWW_AUTHENTICATE,               //< RFC 2608, 2616, 2617, 4559
   HDR_X_CACHE,                        //< Squid custom header
   HDR_X_CACHE_LOOKUP,                 //< Squid custom header. temporary hack that became de-facto. TODO remove
   HDR_X_FORWARDED_FOR,                //< Squid custom header
   HDR_X_REQUEST_URI,                  //< Squid custom header appended if ADD_X_REQUEST_URI is defined
   HDR_X_SQUID_ERROR,                  //< Squid custom header on generated error responses
   //TITAN
   HDR_XTX_CMD,
   HDR_X_YTEDU,
   //TITAN
   #if X_ACCELERATOR_VARY
      HDR_X_ACCELERATOR_VARY,          //< obsolete Squid custom header.
   #endif
   /*
    * since we compile proxy with the 
    * --enable-follow-x-forwarded-for and/or --enable-icap-client 
    * enable HDR_X_NEXT_SERVICES
    */
   //#if USE_ADAPTATION
      HDR_X_NEXT_SERVICES,             //< Squid custom ICAP header
   //#endif

   HDR_SURROGATE_CAPABILITY,           //< Edge Side Includes (ESI) header
   HDR_SURROGATE_CONTROL,              //< Edge Side Includes (ESI) header
   HDR_FRONT_END_HTTPS,                //< MS Exchange custom header we may have to add
   HDR_FTP_COMMAND,                    //< Internal header for FTP command
   HDR_FTP_ARGUMENTS,                  //< Internal header for FTP command arguments
   HDR_FTP_PRE,                        //< Internal header containing leading FTP control response lines
   HDR_FTP_STATUS,                     //< Internal header for FTP reply status
   HDR_FTP_REASON,                     //< Internal header for FTP reply reason
   HDR_OTHER,                          //< internal tag value for "unknown" headers
   //TITAN
   HDR_CSP,                            //< Content-Security-Policy
   HDR_CSP_lc,                          //< content-security-policy (lower case)
   HDR_CSP_RO,                         //< Content-Security-Policy-Report-Only
   HDR_X_CSP,                           //< X-Content-Security-Policy
   HDR_X_CSP_lc,                        //< x-content-security-policy (lower case)
   HDR_X_WEBKIT_CSP,                    //<<X-WebKit-CSP
   HDR_X_FRAME_OPTIONS,                //< X-Frame-Options
   HDR_X_FRAME_OPTIONS_lc,             //< x-frame-options (lower case)
   HDR_X_XSS_PROTECTION,               //< X-XSS-Protection
   HDR_X_XSS_PROTECTION_lc,               //< x-xss-protection (lower case)
   HDR_ACCESS_CONTROL_ALLOW_ORIGIN,    //< Access-Control-Allow-Origin
   HDR_ACCESS_CONTROL_ALLOW_HEADERS,   //< Access-Control-Allow-Headers
   HDR_ACCESS_CONTROL_EXPOSE_HEADERS,  //< Access-Control-Expose-Headers
   HDR_YOUTUBE_RESTRICT,               //< YouTube-Restrict
   //TITAN
   HDR_RESTRICT_ACCESS_TO_TENANTS,
   HDR_RESTRICT_ACCESS_CONTEXT,
   HDR_ENUM_END
}t_http_hdr_types;
//------------------------------------------------------------------------------   

#ifdef __cplusplus
extern "C" {
#endif
typedef void t_anyarg;

typedef enum{
   tcap_none=0x00,
   tcap_pe=0x01,
   tcap_dnsc=0x02,
}t_tcap_type;

typedef bool (check_method)(t_anyarg * const);
typedef void (shutdown_method)(void);

/**
 * Titan C App Interface
 */
typedef struct{
   check_method * check;
   shutdown_method * shutdown;
}TCAp;

typedef enum{
   vl_quiet=0x00,
   vl_default=0x01,
   vl_basic_info=0x02,
   vl_verbose=0x04,
   vl_debug=0x08,   
}t_varbose_levels;

typedef struct{
   c_raw_ipaddr_t       ip;
   char *               fqdn;
   size_t               ctx;
   size_t               fqdn_len;
   t_varbose_levels     verbose;
   bool                 do_not_log;
}t_pe_test_call;


#ifndef IS_DEFAULT_
   #define IS_DEFAULT_(a_args_)      (a_args_->verbose==vl_default)
#endif
#ifndef SET_DEFAULT_
   #define SET_DEFAULT_(a_args_)     ((a_args_->verbose=vl_default))
#endif
#ifndef IS_VERB_
   #define IS_VERB_(a_args_)         (a_args_->verbose>=vl_verbose)
#endif
#ifndef SET_VERB_ 
   #define SET_VERB_(a_args_)        ((a_args_->verbose=vl_verbose)
#endif
#ifndef IS_QUIET_
   #define IS_QUIET_(a_args_)        (a_args_->verbose==vl_quiet)
#endif
#ifndef SET_QUIET_
   #define SET_QUIET_(a_args_)       (!(a_args_->verbose=vl_quiet))
#endif
#ifndef IS_DEBUG_
   #define IS_DEBUG_(a_args_)        (a_args_->verbose==vl_debug)
#endif
#ifndef SET_DEBUG_
   #define SET_DEBUG_(a_args_)       ((a_args_->verbose=vl_debug))
#endif
#ifndef IS_MORE_INFO_
   #define IS_MORE_INFO_(a_args_)    (a_args_->verbose>=vl_basic_info)
#endif
#ifndef INC_VL_
   #define INC_VL_(a_args_)          (( a_args_->verbose=(a_args_->verbose<<1)))
#endif


#ifdef __cplusplus
}
#endif

////////////////////////////////////////////////////////////////////////////////
//       others
////////////////////////////////////////////////////////////////////////////////
TXATR void titax_init_all(const bool);
TXATR  int utf8_cmp(const char *const, const char * const);
TXATR bool ttn_get_txdebug_state(void);
TXATR void ttn_set_txdebug_state(bool);
TXATR bool ttn_get_verbose_state(void);
TXATR void ttn_set_verbose_state(bool);

////////////////////////////////////////////////////////////////////////////////
//       gtape
////////////////////////////////////////////////////////////////////////////////
//TXATR bool gtape_reload_wada(void); disabled
TXATR bool gtape_reload_wbl_domains(vPGconn* const);
TXATR bool gtape_reload_ldap_domains(vPGconn* const);
TXATR bool gtape_init(vPGconn* const);
TXATR size_t gtape_wbl_check_domains(const char * const, const size_t,const ssize_t);
TXATR size_t gtape_wbl_check_all(const char * const, const char * const, const size_t,const ssize_t);
TXATR void gtape_uniqips_clear_old(void);
TXATR void gtape_lic_mgr_query(void);
TXATR bool gtape_lic_mgr_save_cache(void);

TXATR bool gtape_location_is_known_raw_ipaddr( const c_raw_ipaddr_t * const );

TXATR bool gtape_location_is_known( const c_raw_ipaddr_t * const,
                                    const char* const , 
                                    const size_t   );

TXATR bool gtape_location_is_known_str_ipaddr( const char * const );

TXATR bool gtape_location_add_session( const c_raw_ipaddr_t * const, 
                                       const size_t   );

TXATR bool gtape_location_reload(PGconn* const);
TXATR app_t gtape_app_mode(void);


////////////////////////////////////////////////////////////////////////////////
//       tools
////////////////////////////////////////////////////////////////////////////////

/**
 *  @fn ttn_raw_ipaddr2str_ipaddr_ex
 *  @abstract converts c_raw_ipaddr_t into its string representation (ipv4 or ipv6)
 *  @param ip[in] : c_raw_ipaddr_t (host byte order)
 *  @param out[out] : char ptr
 *  @param osz[in]: size_t 
 *  @return bool 
 */
TXATR bool ttn_raw_ipaddr2str_ipaddr_ex( const c_raw_ipaddr_t * const,
                                         char * const,
                                         const size_t );

/**
 *  @fn ttn_str_ipaddr2cidr_ex
 *  @abstract converts c str into cidr struct (ipv4 or ipv6)
 *  @param ip[in] : c str 
 *  @param ipsz[out] : size
 *  @param out[in]: c_cidr_t (host byte order)
 *  @return bool 
 */
TXATR bool ttn_str_ipaddr2cidr_ex(  const char* const,
                                    const size_t,
                                    c_cidr_t * const );

/**
 *  @fn ttn_str_ipaddr2raw_ipaddr_ex
 *  @abstract converts c str into raw ipaddr struct (ipv4 or ipv6)
 *  @param ip[in] : c str 
 *  @param ipsz[out] : size
 *  @param out[in]: c_raw_ipaddr_t (host byte order)
 *  @return bool 
 */
TXATR bool ttn_str_ipaddr2raw_ipaddr_ex( const char* const,
                                         const size_t,
                                         c_raw_ipaddr_t * const );

/**
 *  @fn ttn_str_ipaddr2raw_ipaddr
 *  @abstract converts c str into raw ipaddr struct (ipv4 or ipv6)
 *  @param ip[in] : c str 
 *  @param ipsz[out] : size
 *  @return c_raw_ipaddr_t (host byte order)  ip or invalid on error
 */
TXATR c_raw_ipaddr_t ttn_str_ipaddr2raw_ipaddr( const char* const,
                                                const size_t );

/**
 *  @fn ttn_is_valid_raw_ipaddr
 *  @abstract checks if given ip is valid (ipv4/ipv6)
 *  @param ip[in] : c_raw_ipaddr_t (host byte order) 
 *  @return bool 
 */
TXATR bool ttn_is_valid_raw_ipaddr( const c_raw_ipaddr_t * const );


/**
 *  @fn ttn_is_raw_ipaddr_ipv4
 *  @abstract checks if given ip is valid ipv4
 *  @param ip[in] : c_raw_ipaddr_t (host byte order) 
 *  @return bool 
 */
TXATR bool ttn_is_raw_ipaddr_ipv4( const c_raw_ipaddr_t * const );


/**
 *  @fn ttn_is_raw_ipaddr_ipv6
 *  @abstract checks if given ip is valid ipv6
 *  @param ip[in] : c_raw_ipaddr_t (host byte order) 
 *  @return bool 
 */
TXATR bool ttn_is_raw_ipaddr_ipv6( const c_raw_ipaddr_t * const );

/**
 *  @fn ttn_is_valid_str_ipaddr
 *  @abstract checks if given ip is valid (ipv4/v6)
 *  @param ip[in] : c str
 *  @return bool 
 */
TXATR bool ttn_is_valid_str_ipaddr( const char * const );

/**
 *  @fn ttn_in6_addr2raw_ipaddr_ex
 *  @abstract converts bin str into raw ipaddr struct (ipv4 or ipv6)
 *  @param bin[in] : struct in6_addr ptr 
 *  @param out[out] : raw_ipaddr_t ptr
 *  @return bool 
 */
TXATR bool ttn_in6_addr2raw_ipaddr( const struct in6_addr * const, 
                                    c_raw_ipaddr_t * const );

/**
 *  @fn ttn_sockaddr_in2raw_ipaddr_ex
 *  @abstract converts struct sockaddr_in into raw ipaddr struct (ipv4)
 *  @param sa[in] : struct sockaddr_in
 *  @param out[out] : c_raw_ipaddr_t
 *  @return bool 
 */
TXATR bool ttn_in4_addr2raw_ipaddr( const struct in_addr * const,
                                    c_raw_ipaddr_t * const );

/**
 *  @fn ttn_is_ipaddr_anyaddr
 *  @abstract checks if given raw ip addr is any addr (zero)
 *  @param ip[in] : c_raw_ipaddr_t (host byte order) 
 *  @return bool 
 */
TXATR bool ttn_is_ipaddr_anyaddr( const c_raw_ipaddr_t * const );


/**
 *  @fn ttn_print_raw_ipaddr
 *  @abstract prints in the stdout human readable representation of the ip address (v6  or v4)
 *  @param ip[in] : c_raw_ipaddr_t
 */
TXATR void ttn_print_raw_ipaddr( const c_raw_ipaddr_t * const );

TXATR int ttn_is_in6_addr( const struct in6_addr * const,
                           c_raw_ipaddr_t * const  );

TXATR int ttn_is_in6_addr_local( const struct in6_addr * const );

TXATR int ttn_is_ipaddr_local( const c_raw_ipaddr_t * const );

TXATR int ttn_is_ipaddr_any( const c_raw_ipaddr_t * const );

TXATR bool ttn_in6_addr2str_ipaddr_ex( const struct in6_addr * const,
                                       char * const,
                                       const size_t   );

TXATR bool ttn_in4_addr2str_ipaddr_ex( const struct in_addr * const,
                                       char * const,
                                       const size_t   );

TXATR bool ttn_dns_qname_decode( const char * const, 
                                 char * const,
                                 const  size_t,
                                 size_t *const );

TXATR t_urldb_rc urldb_send_request( urldb_call_t * const );

////////////////////////////////////////////////////////////////////////////////
//       db
////////////////////////////////////////////////////////////////////////////////
TXATR PGconn* db_config_connect(void);
TXATR PGconn* db_reporting_connect(void);
#endif	/* TAPE_H */
