/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 28    Access Control */

#include "squid.h"
#include "HttpRequest.h"
#include "SquidConfig.h"
#include "StatCounters.h"
#include "TAPE.hxx"
#include "acl/FilledChecklist.h"
#include "acl/TitanApp.h"
#include "comm/Connection.h"
#include "comm/Read.h"
#include "comm/Write.h"
#include "fd.h"
#include "fde.h"
#include "log.h"
#include "tools.h"
#include "ttn_cidr.hxx"
#include "ttn_cidr_types.hxx"

using namespace titan_v3;

CBDATA_CLASS_INIT(TitanAppHandler);

ACLTitanApp::ACLTitanApp(char const* type) :
   type_(type) {}

ACLTitanApp::ACLTitanApp (ACLTitanApp const &old) : type_(old.type_)
{}

ACLTitanApp &
ACLTitanApp::operator= (ACLTitanApp const &rhs)
{
    type_ = rhs.type_;
    return *this;
}

char const *
ACLTitanApp::typeString() const
{
    return type_;
}

int
ACLTitanApp::match(ACLChecklist *cl)
{
    ACLFilledChecklist * const _fcl = Filled(cl);

    if (!_fcl || !_fcl->request){
       assert( false && "outch we shouldn't be here !!!");
       return 0;
    }

    IHRequest& _ir = *_fcl->request;

    if (!_ir.headers_has(HDR_ACCEPT)) return 0;

    std::string _r=_ir.headers_get(HDR_ACCEPT);
    if (!_r.size() || 
       (_r.find(TITAX_APP_MIME)==std::string::npos) || 
       !_ir.headers_has(HDR_AUTHORIZATION) || 
       !_ir.headers_has(HDR_XTX_CMD))
	return (0);

    //fixme: optimistic cmd extractor - no error checking
    std::string scmd=_ir.headers_get(HDR_XTX_CMD);
    std::size_t _p = scmd.find(TITAX_APP_HDR_SPLIT);
    _ir.ttag.app_type = txapp_cmd_none;

    if (_p == std::string::npos) {
       _ir.ttag.app_type = static_cast<t_txapp_cmds>(strtol(scmd.c_str(), NULL, 10));
    }
    else {
       _ir.ttag.app_type = static_cast<t_txapp_cmds>(strtol(scmd.substr(0,_p).c_str(),NULL,10));
       _p += TITAX_APP_HDR_SPLIT_SZ;
       _ir.ttag.app_args = scmd.substr(_p,(scmd.size() - _p) - 1);
    }

    if ((_ir.get_flags().ttn_has_been_logged = !(!(_ir.ttag.app_type & TXAPP_LOGGING_OFF)))) {
       _ir.ttag.app_type = ((_ir.ttag.app_type&txapp_cmd_trun_logging_off)?static_cast<t_txapp_cmds>(_ir.ttag.app_type^txapp_cmd_trun_logging_off):_ir.ttag.app_type);
    }

    if (_ir.ttag.app_type==txapp_cmd_none) {
       _ir.ttag.app_type = txapp_cmd_check_dm;
    }

    switch(_ir.ttag.app_type)
    {
      case txapp_cmd_check_dm_from_dp:
      case txapp_cmd_check_dm:
      {
          if ( _ir.headers_has(HDR_X_FORWARDED_FOR) ) 
          {
                using namespace titan_v3::cidr;
                scmd = _ir.headers_get(HDR_X_FORWARDED_FOR);
                if ( scmd.size() ) {
                    auto l_s = factory::make_ipaddr( scmd );
                    if ( l_s.second )
                       _ir.set_client_addr( l_s.first );
                }
          }
         _ir.headers_clear();
         return 0;
      }
      break;

      case txapp_cmd_update_btoken:{
         if (_ir.ttag.app_args.size() == 0){
            _ir.ttag.http.status_msg = std::string{"Update token info failed (0)"};
            _ir.ttag.http.status_code = scBadRequest;
         }
         else {
            StringList* params=NULL;
            if (!(params=split(_ir.ttag.app_args.c_str(), const_cast<char*>("|")))){
               _ir.ttag.http.status_msg = std::string{"Update token info failed (1)"};
               _ir.ttag.http.status_code = scBadRequest;
            }
            else {
               TitaxCKey* ck;
               if ((ck = titax_user_dic_add_token(params))){
                  _ir.ttag.http.status_code = scOkay;
               }
               else {
                  _ir.ttag.http.status_msg = std::string{"Update token info failed (2)"};
                  _ir.ttag.http.status_code = scBadRequest;
               }
               string_list_free(params);
            }
         }

         return 1;
      }break;

      case txapp_cmd_update_from_wada:
      {
         _ir.get_flags().ttn_do_not_check = true;
         _ir.get_flags().ttn_has_been_processed = true;

         const char* _last = nullptr;
         const char* _data = nullptr;

         _ir.ttag.request_error_ctx = 0;

         //_ir.get_flags().ttn_is_local_request=true;
         const int64_t _ccl=_ir.get_content_length();

         BodyPipe::Pointer const _bp = _fcl->request->body_pipe;

         if ((_bp != NULL) && _ir.get_method() == METHOD_POST &&  
		 _ir.ttag.consumed_body_sz < _ccl)
         {
            std::string s = titan_v3::cidr::factory::to_string( _ir.get_client_addr() );
            titax_log(LOG_WARNING,"PROXY:WADA:new update received from {%s} (%lu/%lu)\n",
                      s.c_str(),
                      _ir.ttag.consumed_body_sz, _ccl );
            
            auto* const __csd = static_cast<ConnStateData* const>(_fcl->request->clientConnectionManager.get());

            _fcl->titan_app_handler = new TitanAppHandler(_ir, _bp, __csd); /*RefCounted*/
            if (!_ir.get_flags().ttn_rreply_100_continue
                && _ir.headers_has(HDR_EXPECT)
                && _ir.headers_get(HDR_EXPECT).find("100-continue")!=std::string::npos) {
               titax_log(LOG_NOTICE, "PROXY:WADA:INFO:Expect:100-continue detected!\n");

               _fcl->titan_app_handler->setWrite100Continue();
               if (cl->goAsync(TitanAppLookup::Instance())) {
                  _fcl->titan_app_handler = NULL;
                  return -1;
               }
            }
	   
            else {
               if (_fcl->titan_app_handler->processReadData()) {
                  _fcl->titan_app_handler = NULL;
                  //TODO: Enable WADA
                  if (!titan_v3::GTAPE.wada.as_api()->save_to_file(false)) titax_log(LOG_ERROR,"WADA SAVE ERROR");
               }
               else {
                  //There is more data to read. Go asynchronous.
                  //Wada update is finished in the method LookupDone.
                  if (cl->goAsync(TitanAppLookup::Instance())) {
                     _fcl->titan_app_handler = NULL;
                     return -1;
                  }
               }
            }
         }

         return 1;
      }break;
      default:{
         _ir.ttag.http.status_msg=std::string{"unknown app (0)"};
         _ir.ttag.http.status_code=scBadRequest;
         _ir.ttag.identity.eph.reason.major=MAJ_REASON_UNKNOWN_ERROR;
         _ir.get_flags().ttn_has_been_logged=true;
         _ir.get_flags().ttn_has_been_processed=true;
         _ir.get_flags().ttn_request_is_blocked=true;
         return 1;
      }break;
   }
   return 1;
}


void TitanAppHandler::noteMoreDataAvailable(const CommIoCbParams &io, TitanAppState*const  state) {

   /* Bail out quickly on Comm::ERR_CLOSING - close handlers will tidy up */
   if (io.flag == Comm::ERR_CLOSING) {
      if (state){
         state->doneHandler(state->checklist);
         delete(state);
      };
      return;
   };
   _csd->in.maybeMakeSpaceAvailable();
   CommIoCbParams rd(this); // will be expanded with ReadNow results
   rd.conn = io.conn;
   switch (Comm::ReadNow(rd, _csd->in.buf)) {
   case Comm::INPROGRESS:
      readMoreData(state);
      return;

   case Comm::OK:
      kb_incr(&(statCounter.client_http.kbytes_in), rd.size);
      if (!_csd->handleReadData()) {
         if (state){
            state->doneHandler(state->checklist);
            delete(state);
         };
         return;
      }

      /* Continue to process previously read data */
      break;

   case Comm::ENDFILE: // close detected by 0-byte read
      if (_csd->connFinishedWithConn(rd.size)) {
         _csd->clientConnection->close();
         if (state) delete(state);
         return;
      }

      /* It might be half-closed, we can't tell */
      fd_table[io.conn->fd].flags.socket_eof = true;
      commMarkHalfClosed(io.conn->fd);
      fd_note(io.conn->fd, "half-closed");

      /* There is one more close check at the end, to detect aborted
       * (partial) requests. At this point we can't tell if the request
       * is partial.
       */

      /* Continue to process previously read data */
      break;

   // case Comm::COMM_ERROR:
   default: // no other flags should ever occur
      _csd->notifyAllContexts(rd.xerrno);
      if (state){
         state->doneHandler(state->checklist);
         delete(state);
      };
      return;
   }

   if (!processReadData()) {
      readMoreData(state);
   }
   else {
      if (state){
         state->doneHandler(state->checklist);
         delete(state);
      };
   };
}


void TitanAppHandler::writeCompleted(const CommIoCbParams &io, TitanAppState* const state) {
   if (io.flag && state) {
      state->doneHandler(state->checklist);
      delete(state);
   }
   else {
      readMoreData(state);
   };
}


bool TitanAppHandler::processReadData()
{
   uint64_t _bsz = 0;
   uint64_t _dsz = 0;
   const char* _last = NULL;
   const char* _data = NULL;

   const int64_t _ccl = _ir.get_content_length();
   if (READ_RQ_TRY_MAX <= _ir.ttag.request_error_ctx++) {
      if ((_data=_bp->get_BodyContent()) && (_bsz=_bp->get_BodySize())){
         titax_log(LOG_WARNING,"PROXY:WADA:too many errors!!:dangling data consumed:{%lu|%s}\n",_bsz,_data);
         _bp->consume(_bsz);
      }
      return true;
   }

   if ((_data = _bp->get_BodyContent()) && (((_bsz=_bp->get_BodySize()) > 8) || ((_bsz=strlen(_data)) > 8))
        && (_last=(const char *)::memrchr(_data,'\n',_bsz)) && (_dsz=(uint64_t)(_last - _data)))
   {
       titax_log(LOG_WARNING,"PROXY:WADA:INFO:data sizes %lu/%lu, errors:%lu | (%lu/%lu)\n",
                 _dsz + 1, _bsz, _ir.ttag.request_error_ctx - 1, _ir.ttag.consumed_body_sz, _ccl);

       //TODO: Enable WADA
       if (!titan_v3::GTAPE.wada.as_api()->reload_from_http(_data, _dsz)) titax_log(LOG_ERROR,"WADA UPDATE ERROR");

       _ir.ttag.request_error_ctx=0;

       (void)_bp->consume_without_read(++_dsz);

       if ((_ir.ttag.consumed_body_sz += _dsz) == _ccl) {
          return true;
       }
   }

   return false;
}


void TitanAppHandler::doWrite100Continue(TitanAppState* const state) {
   _csd->flags.readMore = false;
   AsyncCall::Pointer call = asyncCall(   93, 5, "TitanAppHandler::writeCompleted",
                                          TitanAppDialer(CbcPointer<TitanAppHandler>(this), &TitanAppHandler::writeCompleted, state));

   Comm::Write(state->checklist->conn()->clientConnection, H100CONTINUE, ( sizeof( H100CONTINUE ) - 1 ), call, NULL);
}


void TitanAppHandler::readMoreData(TitanAppState* const  state) {
   _csd->flags.readMore = false;
   AsyncCall::Pointer call = asyncCall(93, 5, "TitanAppHandler::noteMoreDataAvailable",
              TitanAppDialer(CbcPointer<TitanAppHandler>(this), &TitanAppHandler::noteMoreDataAvailable, state));
   Comm::Read(state->checklist->conn()->clientConnection, call);
}


TitanAppLookup TitanAppLookup::instance_;

TitanAppLookup *
TitanAppLookup::Instance()
{
    return &instance_;
}


void
TitanAppLookup::checkForAsync(ACLChecklist *cl) const
{
    ACLFilledChecklist *checklist = Filled(cl);
    assert(!(checklist->titan_app_handler == NULL));

    if (checklist->titan_app_handler->getWrite100Continue()) {
       checklist->titan_app_handler->doWrite100Continue(new TitanAppState(LookupDone, checklist));
       /*NOTE: The TitanAppState instance is deleted in writeCompleted()*/
    }
    else {
       checklist->titan_app_handler->readMoreData(new TitanAppState(LookupDone, checklist));
       /*NOTE: the TitanAppState instance is deleted in noteMoreDataAvailable()*/
    }
}


void
TitanAppLookup::LookupDone(void *data)
{
    ACLFilledChecklist *checklist = Filled((ACLChecklist*)data);
    checklist->titan_app_handler = NULL;
    
    //TODO: ENable WADA
    if (!titan_v3::GTAPE.wada.as_api()->save_to_file(false)) titax_log(LOG_ERROR,"WADA SAVE ERROR");
    
    checklist->resumeNonBlockingCheck(TitanAppLookup::Instance());
}

SBufList
ACLTitanApp::dump() const
{
    SBufList sl;
    return sl;
}

bool
ACLTitanApp::empty() const
{
    return false;
}

ACL *
ACLTitanApp::clone() const
{
    return new ACLTitanApp(*this);
}

