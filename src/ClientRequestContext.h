/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_CLIENTREQUESTCONTEXT_H
#define SQUID_CLIENTREQUESTCONTEXT_H

#include "base/RefCount.h"
#include "cbdata.h"
#include "helper/forward.h"
#include "ipcache.h"

#if USE_ADAPTATION
#include "adaptation/forward.h"
#endif

class ACLChecklist;
class ClientHttpRequest;
class DnsLookupDetails;
class ErrorState;

class ClientRequestContext : public RefCountable
{

public:
    ClientRequestContext(ClientHttpRequest *);
    ~ClientRequestContext();

    void dump_http(std::ostream& out);
    friend std::ostream& operator<<(std::ostream& out, ClientRequestContext & obj){        
        out<<"ClientRequestContext:\n"
        <<"\t\t http_access_done:["<<obj.http_access_done<<"]\n"
        <<"\t\t readNextRequest:["<<obj.readNextRequest<<"]\n";
        if (obj.http){
            obj.dump_http(out);
        } else{
            out<<"\t\t http:[0]\n";
        };
        out<<"\t\t tacl_checklist:["<<(obj.acl_checklist?1:0)<<"]\n"        
        <<"\t\t redirect_state:["<<obj.redirect_state<<"]\n"
        <<"\t\t store_id_state:["<<obj.store_id_state<<"]\n"
        <<"\t\t redirect_fail_count:["<<obj.redirect_fail_count<<"]\n"
        <<"\t\t store_id_fail_count:["<<obj.store_id_fail_count<<"]\n"
        <<"\t\t host_header_verify_done:["<<obj.host_header_verify_done<<"]\n"
        <<"\t\t adapted_http_access_done:["<<obj.adapted_http_access_done<<"]\n"
        <<"\t\t adaptation_acl_check_done:["<<obj.adaptation_acl_check_done<<"]\n"
        <<"\t\t redirect_done:["<<obj.redirect_done<<"]\n"
        <<"\t\t store_id_done:["<<obj.store_id_done<<"]\n"
        <<"\t\t no_cache_done:["<<obj.no_cache_done<<"]\n"
        <<"\t\t interpreted_req_hdrs:["<<obj.interpreted_req_hdrs<<"]\n"
        <<"\t\t tosToClientDone:["<<obj.tosToClientDone<<"]\n"
        <<"\t\t nfmarkToClientDone:["<<obj.nfmarkToClientDone<<"]\n"
#if USE_SSL
        <<"\t\t sslBumpCheckDone:["<<obj.sslBumpCheckDone<<"]\n"
#endif
        <<"\t\t error:["<<(obj.error?1:0)<<"]\n";
        return (out);

    };
    bool httpStateIsValid();
    void hostHeaderVerify();
    void hostHeaderIpVerify(const ipcache_addrs* ia, const DnsLookupDetails &dns);
    void hostHeaderVerifyFailed(const char *const A, const char *const B);
    void clientAccessCheck();
    void clientAccessCheck2();
    void clientAccessCheckDone(const allow_t &answer);
    void clientRedirectStart();
    void clientRedirectDone(const Helper::Reply &reply);
    void clientStoreIdStart();
    void clientStoreIdDone(const Helper::Reply &reply);
    void checkNoCache();
    void checkNoCacheDone(const allow_t &answer);
#if USE_ADAPTATION

    void adaptationAccessCheck();
#endif
#if USE_OPENSSL
    /**
     * Initiates and start the acl checklist to check if the a CONNECT
     * request must be bumped.
     \retval true if the acl check scheduled, false if no ssl-bump required
     */
    bool sslBumpAccessCheck();
    /// The callback function for ssl-bump access check list
    void sslBumpAccessCheckDone(const allow_t &answer);
#endif

    ClientHttpRequest *http;
    ACLChecklist *acl_checklist;        /* need ptr back so we can unreg if needed */
    int redirect_state;
    int store_id_state;

    /**
     * URL-rewrite/redirect helper may return BH for internal errors.
     * We attempt to recover by trying the lookup again, but limit the
     * number of retries to prevent lag and lockups.
     * This tracks the number of previous failures for the current context.
     */
    uint8_t redirect_fail_count;
    uint8_t store_id_fail_count;

    bool host_header_verify_done;
    bool http_access_done;
    bool adapted_http_access_done;
#if USE_ADAPTATION
    bool adaptation_acl_check_done;
#endif
    bool redirect_done;
    bool store_id_done;
    bool no_cache_done;
    bool interpreted_req_hdrs;
    bool tosToClientDone;
    bool nfmarkToClientDone;
#if USE_OPENSSL
    bool sslBumpCheckDone;
#endif
    ErrorState *error; ///< saved error page for centralized/delayed processing
    bool readNextRequest; ///< whether Squid should read after error handling

private:
    CBDATA_CLASS2(ClientRequestContext);
};

#endif /* SQUID_CLIENTREQUESTCONTEXT_H */

