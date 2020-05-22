/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 17    Request Forwarding */

#include "squid.h"
#include "acl/FilledChecklist.h"
#include "base/AsyncCbdataCalls.h"
#include "CachePeer.h"
#include "client_side.h"
#include "comm/Loops.h"
#include "errorpage.h"
#include "fde.h"
#include "globals.h"
#include "helper/ResultCode.h"
#include "HttpRequest.h"
#include "neighbors.h"
#include "SquidConfig.h"
#include "ssl/bio.h"
#include "ssl/cert_validate_message.h"
#include "ssl/Config.h"
#include "ssl/ErrorDetail.h"
#include "ssl/helper.h"
#include "ssl/PeerConnector.h"
#include "ssl/ServerBump.h"
#include "ssl/support.h"

//Titan
#include "log.h"

CBDATA_NAMESPACED_CLASS_INIT(Ssl, PeerConnector);

Ssl::PeerConnector::PeerConnector(
    HttpRequestPointer &aRequest,
    const Comm::ConnectionPointer &aServerConn,
    const Comm::ConnectionPointer &aClientConn,
    AsyncCall::Pointer &aCallback,
    const time_t timeout):
    AsyncJob("Ssl::PeerConnector"),
    request(aRequest),
    serverConn(aServerConn),
    clientConn(aClientConn),
    callback(aCallback),
    negotiationTimeout(timeout),
    startTime(squid_curtime),
    splice(false),
    resumingSession(false),
    serverCertificateHandled(false)
{
    // if this throws, the caller's cb dialer is not our CbDialer
    Must(dynamic_cast<CbDialer*>(callback->getDialer()));
}

Ssl::PeerConnector::~PeerConnector()
{

   if (serverConn!=NULL){
      Comm::ResetSelectEX(serverConn->fd,this);
   }

   if (clientConn!=NULL){
      Comm::ResetSelectEX(clientConn->fd,this);
   };

   debugs(83, 5, "Peer connector " << this << " gone");
}

bool Ssl::PeerConnector::doneAll() const
{
    return (!callback || callback->canceled()) && AsyncJob::doneAll();
}

/// Preps connection and SSL state. Calls negotiate().
void
Ssl::PeerConnector::start()
{
    AsyncJob::start();

    if (prepareSocket()) {
        initializeSsl();
        negotiateSsl();
    }
}

void
Ssl::PeerConnector::commCloseHandler(const CommCloseCbParams &params)
{
   debugs(83, 5, "FD " << params.fd << ", Ssl::PeerConnector=" << params.data);
   connectionClosed("Ssl::PeerConnector::commCloseHandler");
}

void
Ssl::PeerConnector::connectionClosed(const char *reason)
{
   mustStop(reason);
   callback = NULL;
}

bool
Ssl::PeerConnector::prepareSocket()
{
    const int fd = serverConnection()->fd;
    if (!Comm::IsConnOpen(serverConn) || fd_table[serverConn->fd].closing()) {
        connectionClosed("Ssl::PeerConnector::prepareSocket");
        return false;
    }

    // watch for external connection closures
    typedef CommCbMemFunT<Ssl::PeerConnector, CommCloseCbParams> Dialer;
    closeHandler = JobCallback(9, 5, Dialer, this, Ssl::PeerConnector::commCloseHandler);
    comm_add_close_handler(fd, closeHandler);
    return true;
}

void
Ssl::PeerConnector::initializeSsl()
{
    SSL_CTX *sslContext = NULL;
    const CachePeer *peer = serverConnection()->getPeer();
    const int fd = serverConnection()->fd;

    if (peer) {
        assert(peer->use_ssl);
        sslContext = peer->sslContext;
    } else {
        sslContext = ::Config.ssl_client.sslContext;
    }

    assert(sslContext);

    SSL *ssl = Ssl::CreateClient(sslContext, fd, "server https start");
    if (!ssl) {
        ErrorState *anErr = new ErrorState(ERR_SOCKET_FAILURE, Http::scInternalServerError, request.getRaw());
        anErr->xerrno = errno;
        debugs(83, DBG_IMPORTANT, "Error allocating SSL handle: " << ERR_error_string(ERR_get_error(), NULL));
        bail(anErr);
        return;
    }

    if (peer) {
        SBuf *host = new SBuf(peer->ssldomain ? peer->ssldomain : peer->host);
        SSL_set_ex_data(ssl, ssl_ex_index_server, host);

        if (peer->sslSession)
            SSL_set_session(ssl, peer->sslSession);
    } else if (ConnStateData * const csd =static_cast<ConnStateData * const>(request->clientConnectionManager.valid())) {
        // client connection is required in the case we need to splice
        // or terminate client and server connections
        assert(clientConn != NULL);
        SBuf *hostName = NULL;
        Ssl::ClientBio *cltBio = NULL;

        //Enable Status_request tls extension, required to bump some clients
        SSL_set_tlsext_status_type(ssl, TLSEXT_STATUSTYPE_ocsp);

        // In server-first bumping mode, clientSsl is NULL.
        if (SSL *clientSsl = fd_table[clientConn->fd].ssl) {
            BIO *const b = SSL_get_rbio(clientSsl);
            cltBio = static_cast<Ssl::ClientBio *>(b->ptr);
            const Ssl::Bio::sslFeatures &features = cltBio->getFeatures();
            if (!features.serverName.isEmpty())
                hostName = new SBuf(features.serverName);
        }

        if (!hostName) {
            // While we are peeking at the certificate, we may not know the server
            // name that the client will request (after interception or CONNECT)
            // unless it was the CONNECT request with a user-typed address.
            const bool isConnectRequest = !csd->port->flags.isIntercepted();
            if (!request->flags.sslPeek || isConnectRequest)
                hostName = new SBuf(request->GetHost());
        }

        if (hostName)
            SSL_set_ex_data(ssl, ssl_ex_index_server, (void*)hostName);

        Must(!csd->serverBump() || csd->serverBump()->step <= Ssl::bumpStep2);
        if (csd->sslBumpMode == Ssl::bumpPeek || csd->sslBumpMode == Ssl::bumpStare) {
            assert(cltBio);
            const Ssl::Bio::sslFeatures &features = cltBio->getFeatures();
            if (features.sslVersion != -1) 
                features.applyToSSL(ssl, csd->sslBumpMode);

	    BIO *b = SSL_get_rbio(ssl);
	    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(b->ptr);
	    // Inherite client features, like SSL version, SNI and other
	    srvBio->setClientFeatures(features);
	    srvBio->recordInput(true);
	    srvBio->mode(csd->sslBumpMode);	    
        } else {
            // Set client SSL options
            SSL_set_options(ssl, ::Config.ssl_client.parsedOptions);

            // Use SNI TLS extension only when we connect directly
            // to the origin server and we know the server host name.
            const char *sniServer = NULL;
            const bool redirected = request->flags.redirected && ::Config.onoff.redir_rewrites_host;
            if (!hostName || redirected)
                sniServer = !request->GetHostIsNumeric() ? request->GetHost() : NULL;
            else
                sniServer = hostName->c_str();

            if (sniServer)
                Ssl::setClientSNI(ssl, sniServer);
        }

        if (Ssl::ServerBump *serverBump = csd->serverBump())
            serverBump->attachServerSSL(ssl);
    }

    // If CertValidation Helper used do not lookup checklist for errors,
    // but keep a list of errors to send it to CertValidator
    if (!Ssl::TheConfig.ssl_crt_validator) {
        // Create the ACL check list now, while we have access to more info.
        // The list is used in ssl_verify_cb() and is freed in ssl_free().
        if (acl_access *acl = ::Config.ssl_client.cert_error) {
            ACLFilledChecklist *check = new ACLFilledChecklist(acl, request.getRaw(), dash_str);
            // check->fd(fd); XXX: need client FD here
            SSL_set_ex_data(ssl, ssl_ex_index_cert_error_check, check);
        }
    }

    // store peeked cert to check SQUID_X509_V_ERR_CERT_CHANGE
   X509 *peeked_cert=NULL;
   if (ConnStateData * const _csd=static_cast<ConnStateData * const>(request->clientConnectionManager.valid())){
      if ( _csd->serverBump() && (peeked_cert = _csd->serverBump()->serverCert.get())) {
         CRYPTO_add(&(peeked_cert->references),1,CRYPTO_LOCK_X509);
         SSL_set_ex_data(ssl, ssl_ex_index_ssl_peeked_cert, peeked_cert);
      };
   };

}

void
Ssl::PeerConnector::setReadTimeout()
{
    int timeToRead;
    if (negotiationTimeout) {
        const int timeUsed = squid_curtime - startTime;
        const int timeLeft = max(0, static_cast<int>(negotiationTimeout - timeUsed));
        timeToRead = min(static_cast<int>(::Config.Timeout.read), timeLeft);
    } else
        timeToRead = ::Config.Timeout.read;
    AsyncCall::Pointer nil;
    commSetConnTimeout(serverConnection(), timeToRead, nil);
}

void
Ssl::PeerConnector::negotiateSsl()
{

   int fd;
   Comm::ConnectionPointer _conn=serverConnection();
   if (_conn==NULL || -1==(fd=_conn->fd) || !fd_table){
      assert(0 && "Ssl::PeerConnector::negotiateSsl");
      return;
   }

   if (!Comm::IsConnOpen(serverConnection()) || fd_table[fd].closing()){
      return;
   }
   

   fde *const F = &fd_table[fd]; // to get more data from dump
   if (SSL *const ssl = F->ssl){
      const int result = SSL_connect(ssl);
      if (result <= 0) {
         handleNegotiateError(result);
         return; // we might be gone by now
      }

      if (serverConnection()->getPeer() && !SSL_session_reused(ssl)) {
          if (serverConnection()->getPeer()->sslSession)
              SSL_SESSION_free(serverConnection()->getPeer()->sslSession);

          serverConnection()->getPeer()->sslSession = SSL_get1_session(ssl);
      }

      if (!sslFinalized())
          return;
      callBack();
   };
}

void
Ssl::PeerConnector::handleServerCertificate()
{
    if (serverCertificateHandled)
        return;

    if (ConnStateData * const csd =static_cast<ConnStateData * const>(request->clientConnectionManager.valid())) {
        const int fd = serverConnection()->fd;
        SSL *ssl = fd_table[fd].ssl;
        Ssl::X509_Pointer serverCert(SSL_get_peer_certificate(ssl));
        if (!serverCert.get())
            return;

        serverCertificateHandled = true;

        // remember the server certificate for later use
        if (Ssl::ServerBump *const serverBump =static_cast<Ssl::ServerBump * const>( csd->serverBump())) {
            serverBump->serverCert.reset(serverCert.release());
        }
    }
}

void
Ssl::PeerConnector::serverCertificateVerified()
{
    if (ConnStateData *const csd = static_cast<ConnStateData * const>(request->clientConnectionManager.valid())) {
        Ssl::X509_Pointer serverCert;
        if(Ssl::ServerBump *const serverBump =static_cast<Ssl::ServerBump * const>( csd->serverBump()))
            serverCert.resetAndLock(serverBump->serverCert.get());
        else {
            const int fd = serverConnection()->fd;
            SSL *ssl = fd_table[fd].ssl;
            serverCert.reset(SSL_get_peer_certificate(ssl));
        }
        if (serverCert.get()) {
            char _cn[1024]={};
            if (Ssl::CommonHostName(serverCert.get(), _cn,sizeof(_cn))) {
               csd->resetSslCommonName(_cn);
            }
            debugs(83, 5, "HTTPS server CN: " << csd->sslCommonName() <<
                   " bumped: " << *serverConnection());
        }
    }
}

bool
Ssl::PeerConnector::sslFinalized()
{
    const int fd = serverConnection()->fd;
    SSL *ssl = fd_table[fd].ssl;

    // In the case the session is resuming, the certificates does not exist and
    // we did not do any cert validation
    if (resumingSession)
        return true;

    handleServerCertificate();

    if (Ssl::TheConfig.ssl_crt_validator) {
        Ssl::CertValidationRequest validationRequest;
        // WARNING: Currently we do not use any locking for any of the
        // members of the Ssl::CertValidationRequest class. In this code the
        // Ssl::CertValidationRequest object used only to pass data to
        // Ssl::CertValidationHelper::submit method.
        validationRequest.ssl = ssl;
        validationRequest.domainName = request->GetHost();
        if (Ssl::CertErrors *errs = static_cast<Ssl::CertErrors *>(SSL_get_ex_data(ssl, ssl_ex_index_ssl_errors)))
            // validationRequest disappears on return so no need to cbdataReference
            validationRequest.errors = errs;
        else
            validationRequest.errors = NULL;
        try {
            debugs(83, 5, "Sending SSL certificate for validation to ssl_crtvd.");
            AsyncCall::Pointer call = asyncCall(83,5, "Ssl::PeerConnector::sslCrtvdHandleReply", Ssl::CertValidationHelper::CbDialer(this, &Ssl::PeerConnector::sslCrtvdHandleReply, NULL));
            Ssl::CertValidationHelper::GetInstance()->sslSubmit(validationRequest, call);
            return false;
        } catch (const std::exception &e) {
            debugs(83, DBG_IMPORTANT, "ERROR: Failed to compose ssl_crtvd " <<
                   "request for " << validationRequest.domainName <<
                   " certificate: " << e.what() << "; will now block to " <<
                   "validate that certificate.");
            // fall through to do blocking in-process generation.
            ErrorState *anErr = new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw());
            bail(anErr);
            if (serverConnection()->getPeer()) {
                peerConnectFailed(serverConnection()->getPeer());
            }
            serverConn->close();
            return true;
        }
    }

    serverCertificateVerified();
    return true;
}

void switchToTunnel(HttpRequest *const request, Comm::ConnectionPointer & clientConn, Comm::ConnectionPointer &srvConn);

void
Ssl::PeerConnector::cbCheckForPeekAndSpliceDone(allow_t answer, void *data)
{
    Ssl::PeerConnector *peerConnect = (Ssl::PeerConnector *) data;
    CallJobHere1(83, 7, CbcPointer<PeerConnector>(peerConnect), Ssl::PeerConnector, checkForPeekAndSpliceDone, answer);
}

void
Ssl::PeerConnector::checkForPeekAndSpliceDone(allow_t answer)
{
    const Ssl::BumpMode finalAction = (answer.code == ACCESS_ALLOWED) ?
                                      static_cast<Ssl::BumpMode>(answer.kind):
                                      checkForPeekAndSpliceGuess();
    checkForPeekAndSpliceMatched(finalAction);
}

void
Ssl::PeerConnector::checkForPeekAndSplice()
{
   // Mark Step3 of bumping
   if (ConnStateData * const _csd=static_cast<ConnStateData * const>(request->clientConnectionManager.valid())){    
      if (Ssl::ServerBump *const serverBump =static_cast<Ssl::ServerBump * const>( _csd->serverBump())) {
         serverBump->step = Ssl::bumpStep3;
      };
   };

    handleServerCertificate();

    ACLFilledChecklist *const acl_checklist = new ACLFilledChecklist(
        ::Config.accessList.ssl_bump,
        request.getRaw(), NULL);
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpNone));
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpPeek));
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpStare));
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpClientFirst));
    acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpServerFirst));
    SSL *ssl = fd_table[serverConn->fd].ssl;
    BIO *b = SSL_get_rbio(ssl);
    Ssl::ServerBio *srvBio = static_cast<Ssl::ServerBio *>(b->ptr);
    if (!srvBio->canSplice())
        acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpSplice));
    if (!srvBio->canBump())
        acl_checklist->banAction(allow_t(ACCESS_ALLOWED, Ssl::bumpBump));
    acl_checklist->nonBlockingCheck(Ssl::PeerConnector::cbCheckForPeekAndSpliceDone, this);
}

void
Ssl::PeerConnector::checkForPeekAndSpliceMatched(const Ssl::BumpMode action)
{
    if (-1!=serverConn->fd && -1!=clientConn->fd){

       SSL *const ssl = fd_table[serverConn->fd].ssl;
       if (!ssl) return;
       BIO *const b = SSL_get_rbio(ssl);
       if (!b) return;
       Ssl::ServerBio *const srvBio = static_cast<Ssl::ServerBio *const>(b->ptr);
       if (!srvBio) return;

       debugs(83,5, "Will check for peek and splice on FD " << serverConn->fd);

       Ssl::BumpMode finalAction = action;
       // adjust the final bumping mode if needed
      if (finalAction < Ssl::bumpSplice)
          finalAction = Ssl::bumpBump;
      if (finalAction == Ssl::bumpSplice && !srvBio->canSplice())
          finalAction = Ssl::bumpBump;
      else if (finalAction == Ssl::bumpBump && !srvBio->canBump())
          finalAction = Ssl::bumpSplice;

       // Record final decision
      if (ConnStateData * const _csd=static_cast<ConnStateData * const>(request->clientConnectionManager.valid())){
         _csd->sslBumpMode=finalAction;
         _csd->serverBump()->act.step3 = finalAction;
      };

       if (finalAction == Ssl::bumpTerminate) {
          serverConn->close();
          clientConn->close();
       } else if (finalAction != Ssl::bumpSplice) {
           //Allow write, proceed with the connection
           srvBio->holdWrite(false);
           srvBio->recordInput(false);
           Comm::SetSelect(serverConn->fd, COMM_SELECT_WRITE, &NegotiateSsl, this, 0);
           debugs(83,5, "Retry the fwdNegotiateSSL on FD " << serverConn->fd);
       } else {
           splice = true;
           // Ssl Negotiation stops here. Last SSL checks for valid certificates
           // and if done, switch to tunnel mode
           if (sslFinalized())
               switchToTunnel(request.getRaw(), clientConn, serverConn);
       }
       return;
    };
    assert(0 && "checkForPeekAndSpliceDone:deadend");
}

Ssl::BumpMode
Ssl::PeerConnector::checkForPeekAndSpliceGuess() const
{
    if (const ConnStateData *const csd =static_cast<ConnStateData * const>( request->clientConnectionManager.valid())) {
        const Ssl::BumpMode currentMode = csd->sslBumpMode;
        if (currentMode == Ssl::bumpStare) {
            debugs(83,5, "default to bumping after staring");
            return Ssl::bumpBump;
        }
        debugs(83,5, "default to splicing after " << currentMode);
    } else {
        debugs(83,3, "default to splicing due to missing info");
    }

    return Ssl::bumpSplice;
}

void
Ssl::PeerConnector::sslCrtvdHandleReply(Ssl::CertValidationResponse::Pointer validationResponse)
{
    Must(validationResponse != NULL);

    Ssl::ErrorDetail *errDetails = NULL;
    bool validatorFailed = false;
    if (!Comm::IsConnOpen(serverConnection())) {
        return;
    }

    debugs(83,5, request->GetHost() << " cert validation result: " << validationResponse->resultCode);

    if (validationResponse->resultCode == ::Helper::Error) {
        if (Ssl::CertErrors *errs = sslCrtvdCheckForErrors(*validationResponse, errDetails)) {
            SSL *ssl = fd_table[serverConnection()->fd].ssl;
            Ssl::CertErrors *oldErrs = static_cast<Ssl::CertErrors*>(SSL_get_ex_data(ssl, ssl_ex_index_ssl_errors));
            SSL_set_ex_data(ssl, ssl_ex_index_ssl_errors,  (void *)errs);
            delete oldErrs;
        }
    } else if (validationResponse->resultCode != ::Helper::Okay)
        validatorFailed = true;

    if (!errDetails && !validatorFailed) {
        serverCertificateVerified();
        if (splice)
            switchToTunnel(request.getRaw(), clientConn, serverConn);
        else
            callBack();
        return;
    }

    ErrorState *anErr = NULL;
    if (validatorFailed) {
        anErr = new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw());
    }  else {
        anErr =  new ErrorState(ERR_SECURE_CONNECT_FAIL, Http::scServiceUnavailable, request.getRaw());
        anErr->detail = errDetails;
        /*anErr->xerrno= Should preserved*/
    }

    bail(anErr);
    if (serverConnection()->getPeer()) {
        peerConnectFailed(serverConnection()->getPeer());
    }
    serverConn->close();
    return;
}

/// Checks errors in the cert. validator response against sslproxy_cert_error.
/// The first honored error, if any, is returned via errDetails parameter.
/// The method returns all seen errors except SSL_ERROR_NONE as Ssl::CertErrors.
Ssl::CertErrors *
Ssl::PeerConnector::sslCrtvdCheckForErrors(Ssl::CertValidationResponse const &resp, Ssl::ErrorDetail *& errDetails)
{
    Ssl::CertErrors *errs = NULL;

    ACLFilledChecklist *check = NULL;
    if (acl_access *const acl = ::Config.ssl_client.cert_error)
        check = new ACLFilledChecklist(acl, request.getRaw(), dash_str);
    typedef Ssl::CertValidationResponse::RecvdErrors::const_iterator SVCRECI;
    for (SVCRECI i = resp.errors.begin(); i != resp.errors.end(); ++i) {
        debugs(83, 7, "Error item: " << i->error_no << " " << i->error_reason);

        assert(i->error_no != SSL_ERROR_NONE);

        if (!errDetails) {
            bool allowed = false;
            if (check) {
                check->sslErrors = new Ssl::CertErrors(Ssl::CertError(i->error_no, i->cert.get()));
                if (check->fastCheck() == ACCESS_ALLOWED)
                    allowed = true;
            }
            // else the Config.ssl_client.cert_error access list is not defined
            // and the first error will cause the error page

            if (allowed) {
                debugs(83, 3, "bypassing SSL error " << i->error_no << " in " << "buffer");
            } else {
                debugs(83, 5, "confirming SSL error " << i->error_no);
                if (SSL *const ssl = fd_table[serverConnection()->fd].ssl){
                   X509 *const brokenCert = i->cert.get();
                   Ssl::X509_Pointer peerCert(SSL_get_peer_certificate(ssl));
                   const char *const aReason = i->error_reason.empty() ? NULL : i->error_reason.c_str();
                   errDetails = new Ssl::ErrorDetail(i->error_no, peerCert.get(), brokenCert, aReason);
                } else{
                  assert(0 && "Ssl::PeerConnector::sslCrtvdCheckForErrors");
                }
            }
            if (check) {
                delete check->sslErrors;
                check->sslErrors = NULL;
            }
        }

        if (!errs)
            errs = new Ssl::CertErrors(Ssl::CertError(i->error_no, i->cert.get()));
        else
            errs->push_back_unique(Ssl::CertError(i->error_no, i->cert.get()));
    }
    if (check)
        delete check;

    return errs;
}

/// A wrapper for Comm::SetSelect() notifications.
void
Ssl::PeerConnector::NegotiateSsl(int, void *data)
{
    if (PeerConnector *const pc = (PeerConnector *const)data) {
        if (pc->clientConn!=NULL && pc->clientConn->fd != -1) {
            if (pc->serverConn==NULL || pc->serverConn->fd == -1) {
               titax_log(LOG_WARNING,"NegotiateSsl-error-close(-1:%d):[%s]\n",pc->clientConn->fd,(pc->request!=NULL?pc->request->get_canonical().c_str():"<NULL>"));
               pc->clientConn->close();
               return;
            }
            // Use job calls to add done() checks and other job logic/protections.
            try {
                CallJobHere(83, 7, pc, Ssl::PeerConnector, negotiateSsl);
            }
            catch( std::exception & l_e) {
                debugs(81,1, "PeerConnector::NegotiateSsl() caught exception: " << l_e.what() );
                titax_log(LOG_ERR, "PeerConnector::NegotiateSsl() caught exception: %s", l_e.what() );
                //pc->serverConn->close();
            }
        }
    }
}

void
Ssl::PeerConnector::handleNegotiateError(const int ret)
{
    const int fd = this->serverConn->fd;
    unsigned long ssl_lib_error = SSL_ERROR_NONE;
    SSL *const ssl = fd_table[fd].ssl;
    assert(ssl);
    int ssl_error = SSL_get_error(ssl, ret);
    BIO *const b = SSL_get_rbio(ssl);
    assert(b);
    Ssl::ServerBio *const srvBio = static_cast<Ssl::ServerBio *const>(b->ptr);
    assert(srvBio);

#ifdef EPROTO
    int sysErrNo = EPROTO;
#else
    int sysErrNo = EACCES;
#endif

    switch (ssl_error) {

    case SSL_ERROR_WANT_READ:
        setReadTimeout();
        Comm::SetSelect(fd, COMM_SELECT_READ, &NegotiateSsl, this, 0);
        return;

    case SSL_ERROR_WANT_WRITE:
        if ((srvBio->bumpMode() == Ssl::bumpPeek || srvBio->bumpMode() == Ssl::bumpStare) && srvBio->holdWrite()) {
            debugs(81, 3, "hold write on SSL connection on FD " << fd);
            checkForPeekAndSplice();
            return;
        }
        Comm::SetSelect(fd, COMM_SELECT_WRITE, &NegotiateSsl, this, 0);
        return;

    case SSL_ERROR_SSL:
    case SSL_ERROR_SYSCALL:{
        ssl_lib_error = ERR_get_error();

        // In Peek mode, the ClientHello message sent to the server. If the
        // server resuming a previous (spliced) SSL session with the client,
        // then probably we are here because local SSL object does not know
        // anything about the session being resumed.
        //
        if (srvBio->bumpMode() == Ssl::bumpPeek && (resumingSession = srvBio->resumingSession())) {
            // we currently splice all resumed sessions unconditionally
            if (const bool spliceResumed = true) {
                checkForPeekAndSpliceMatched(Ssl::bumpSplice);
                return;
            } // else fall through to find a matching ssl_bump action (with limited info)
        }

        // If we are in peek-and-splice mode and still we did not write to
        // server yet, try to see if we should splice.
        // In this case the connection can be saved.
        // If the checklist decision is do not splice a new error will
        // occure in the next SSL_connect call, and we will fail again.
        // Abort on certificate validation errors to avoid splicing and
        // thus hiding them.
        // Abort if no certificate found probably because of malformed or
        // unsupported server Hello message (TODO: make configurable).
#if 1
        if (!SSL_get_ex_data(ssl, ssl_ex_index_ssl_error_detail) &&
                (srvBio->bumpMode() == Ssl::bumpPeek  || srvBio->bumpMode() == Ssl::bumpStare) && srvBio->holdWrite()) {
            Ssl::X509_Pointer serverCert(SSL_get_peer_certificate(ssl));
            if (serverCert.get()) {
                debugs(81, 3, "Error ("  << ERR_error_string(ssl_lib_error, NULL) <<  ") but, hold write on SSL connection on FD " << fd);
                checkForPeekAndSplice();
                return;
            }
        }
#endif

        // store/report errno when ssl_error is SSL_ERROR_SYSCALL, ssl_lib_error is 0, and ret is -1
        if (ssl_error == SSL_ERROR_SYSCALL && ret == -1 && ssl_lib_error == 0)
            sysErrNo = errno;
        debugs(83, DBG_IMPORTANT, "Error negotiating server SSL ["<<"sni="<<(request!=NULL ? request->get_sni():"")<<" host="<<(request!=NULL?request->get_host():"")<<" local=" << serverConn->local << " remote=" << serverConn->remote <<"] on FD " << fd <<
               ": " << ERR_error_string(ssl_lib_error, NULL) << " (" <<
               ssl_error << "/" << ret << "/" << errno << ")");

    }break; // proceed to the general error handling code

    default:
        break; // no special error handling for all other errors
    }

    ErrorState *const anErr = ErrorState::NewForwarding(ERR_SECURE_CONNECT_FAIL, request.getRaw());
    anErr->xerrno = sysErrNo;

   if (this->request!=NULL) {
       request->get_flags().ttn_ssl_error = true;
   }

    Ssl::ErrorDetail *const errFromFailure = (Ssl::ErrorDetail *const)SSL_get_ex_data(ssl, ssl_ex_index_ssl_error_detail);
    if (errFromFailure != NULL) {
        // The errFromFailure is attached to the ssl object
        // and will be released when ssl object destroyed.
        // Copy errFromFailure to a new Ssl::ErrorDetail object
        anErr->detail = new Ssl::ErrorDetail(*errFromFailure);
    } else {
        // server_cert can be NULL here
        X509 *const server_cert = SSL_get_peer_certificate(ssl);
        anErr->detail = new Ssl::ErrorDetail(SQUID_ERR_SSL_HANDSHAKE, server_cert, NULL);
        X509_free(server_cert);
    }

    if (ssl_lib_error != SSL_ERROR_NONE){
        anErr->detail->setLibError(ssl_lib_error);
    }


   if (ConnStateData * const _csd=static_cast<ConnStateData * const>(request->clientConnectionManager.valid())){
        // remember the server certificate from the ErrorDetail object
      if (Ssl::ServerBump *const serverBump =static_cast<Ssl::ServerBump * const>(_csd->serverBump()))
            serverBump->serverCert.resetAndLock(anErr->detail->peerCert());

        // For intercepted connections, set the host name to the server
        // certificate CN. Otherwise, we just hope that CONNECT is using
        // a user-entered address (a host name or a user-entered IP).
      const bool isConnectRequest = !_csd->port->flags.isIntercepted();
        if (request->flags.sslPeek && !isConnectRequest) {
            if (X509 *const srvX509 = anErr->detail->peerCert()) {
               char _name[1024]={};
                if (Ssl::CommonHostName(srvX509,_name,sizeof(_name))) {
                    request->SetHost(_name);
                    debugs(83, 3, HERE << "reset request host: " << _name);
              };
          };
      };
   };

    bail(anErr);
}

void
Ssl::PeerConnector::bail(ErrorState *error)
{
    Must(error); // or the recepient will not know there was a problem

    // XXX: forward.cc calls peerConnectSucceeded() after an OK TCP connect but
    // we call peerConnectFailed() if SSL failed afterwards. Is that OK?
    // It is not clear whether we should call peerConnectSucceeded/Failed()
    // based on TCP results, SSL results, or both. And the code is probably not
    // consistent in this aspect across tunnelling and forwarding modules.
    if (CachePeer *p = serverConnection()->getPeer()){
        peerConnectFailed(p);
    };

    Must(callback != NULL);
    CbDialer *dialer = dynamic_cast<CbDialer*>(callback->getDialer());
    Must(dialer);
    dialer->answer().error = error;

    callBack();
    // Our job is done. The callabck recepient will probably close the failed
    // peer connection and try another peer or go direct (if possible). We
    // can close the connection ourselves (our error notification would reach
    // the recepient before the fd-closure notification), but we would rather
    // minimize the number of fd-closure notifications and let the recepient
    // manage the TCP state of the connection.
}

void
Ssl::PeerConnector::callBack()
{
   if (callback!=NULL){

      AsyncCall::Pointer cb = callback;      
      if (CbDialer * const dialer = dynamic_cast<CbDialer*const >(cb->getDialer())){

         // Do this now so that if we throw below, swanSong() assert that we _tried_
         // to call back holds.
         callback = NULL; // this should make done() true

         // remove close handler
         comm_remove_close_handler(serverConnection()->fd, closeHandler);

         //Must(dialer);
         dialer->answer().conn = serverConnection();
         ScheduleCallHere(cb);    
      };
   };
}

void
Ssl::PeerConnector::swanSong()
{
    // XXX: unregister fd-closure monitoring and CommSetSelect interest, if any
    AsyncJob::swanSong();
    if (callback != NULL) { // paranoid: we have left the caller waiting
        debugs(83, DBG_IMPORTANT, "BUG: Unexpected state while connecting to a cache_peer or origin server");
        ErrorState *anErr = new ErrorState(ERR_GATEWAY_FAILURE, Http::scInternalServerError, request.getRaw());
        bail(anErr);
        assert(!callback);
        return;
    }
}

const char *
Ssl::PeerConnector::status() const
{
    static MemBuf buf;
    buf.reset();

    // TODO: redesign AsyncJob::status() API to avoid this
    // id and stop reason reporting duplication.
    buf.append(" [", 2);
    if (stopReason != NULL) {
        buf.Printf("Stopped, reason:");
        buf.Printf("%s",stopReason);
    }
    if (serverConn != NULL)
        buf.Printf(" FD %d", serverConn->fd);
    buf.Printf(" %s%u]", id.prefix(), id.value);
    buf.terminate();

    return buf.content();
}

/* PeerConnectorAnswer */

Ssl::PeerConnectorAnswer::~PeerConnectorAnswer()
{
    delete error.get();
}

std::ostream &
Ssl::operator <<(std::ostream &os, const Ssl::PeerConnectorAnswer &answer)
{
    return os << answer.conn << ", " << answer.error;
}

