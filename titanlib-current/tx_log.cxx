/*
 * $Id$
 */

#include "global.h"
#include "edgelib.h"
#include "log.h"
#include "sock_rw.h"
#include "tx_log.hxx"
#include "txbase16.h"
#include "txhash.h"
#include "txip.h"
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <ctime>
#include <ctime>
#include <exception>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/timespec.h>
#include <vector>

using namespace titan_v3;

#define WRITES_BF_FLUSH_MAX_              32
static size_t writes_bf_flush_cnt=WRITES_BF_FLUSH_MAX_;
   
bool tx_log::get_url_normalized(std::string & out) noexcept 
{

   if ( std::string( url, 0, 8 ).find("://") != std::string::npos ) {

      out = url;
      
      return true;
   }

   auto encode_url_=[&]( std::string nurl ) noexcept {

      if ( const size_t nurl_len = nurl.size() ) {

         const size_t enc_sz = ( 3 * nurl_len ) + 1;

         if ( url_encode( nurl.c_str(), nurl_len, enc_sz, encoded_.buf( enc_sz ) ) ) {

            out = encoded_;
            return true;
         }
      }

      return false;
   };

   size_t p_ = std::string::npos;

   if ( ( p_ = url.find(":443") ) != std::string::npos ) {

      const size_t l = url.size() - 4;

      return encode_url_( tools::functors::tos{"https://"} <<
                          std::move( url.insert( p_, url, p_+4, std::string::npos ).assign( url, 0, l ) ) );
   }

   return encode_url_( tools::functors::tos{"http://"}<<std::move(url)  );
}


bool tx_log::prepare_data_() noexcept
{
   if (!this->processing_prepare_data && !this->data_prepared && this->url.length())
   {
      this->processing_prepare_data=true;

      tx_alog::clear();
      (void)(!this->uname.length() && (this->uname=TITAX_ANON_DEFAULT_USER_NAME).length());
      time_t current_time=0;
      (void)time(&current_time); //slow
      struct tm  ts;
      (void)localtime_r(&current_time, &ts);
      *this<<this->prefix;
      *this<<tools::functors::tos{current_time}<<' ';
      *this<<tools::functors::tos{this->object_size}<<' ';
      *this<<tools::functors::tos{this->duration}<<' ';
      *this<<"00000000"<<' '; /* compatibility padding */
      *this<<tools::functors::tos{this->cached}<<' ';
      *this<<tools::functors::tos{this->blocking_source}<<' ';
      std::string nurl;
      if (!this->get_url_normalized(nurl)){
         this->data_prepared=false;
         this->processing_prepare_data=false;
         return (false);
      }
      *this<<nurl<<' ';
      *this<<this->uname<<'\n';
      uint_fast64_t sz=this->groups.size();
      uint_fast64_t i=0;
      while (i<sz) *this<<'G'<<this->groups[i++]<<'\n';
      (void)((sz=this->categories.size())>5 && (sz=0));
      i=0;
      while(i<sz) *this<<'C'<<this->categories[i++]<<'\n';
      sz=this->notifications.size();
      i=0;
      while(i<sz) *this<<"NE"<<this->notifications[i++]<<'\n';
      /* send only what we need */
      if (this->reason.size()) *this<<'R'<<this->reason<<'\n';
      if (this->cloud_key.size()) *this<<'K'<<this->cloud_key<<'\n';
      if (this->location.size()) *this<<'L'<<this->location<<'\n';
      if (this->parent_id>INVALID_) *this<<'S'<<tools::functors::tos{this->parent_id}<<'\n';
      if (this->meta_internal_ip_addr) *this<<'I'<<cidr::factory::to_string(this->meta_internal_ip_addr)<<'\n';
      if (this->meta_uname.size()) *this<<'U'<<this->meta_uname<<'\n';
      if (this->policy_name.size()) *this<<'P'<<this->policy_name<<'\n';
      *this<<'V'<<cidr::factory::to_string(this->ip_addr)<<'\n';
      sz=this->length();
      char * const r_=this->sb->pbase();
      //offset data by prefix
      if (!tx_log_parser::raw_header_new(r_+12,sz-12,static_cast<uint32_t>(sz-8),this->raw_h_)){
         this->data_prepared=false;
         this->processing_prepare_data=false;
         return (false);
      }
      (void)tx_safe_memcpy(reinterpret_cast<void*>(r_),this->raw_h_.raw,sizeof (this->raw_h_.raw));
      *(r_+sizeof(this->raw_h_.raw)+3)=0;
      this->data_prepared=true;

      this->processing_prepare_data=false;

      return ( true );
   }
   return (false);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////
static  bool log_(t_tx_log_log_call * const call)
{
   switch( call->open_call.type)
   {
      case ot_file:{
         if (call->use_locks && !flock(*(call->open_call.outfd), LOCK_EX)) return (false);
         ssize_t r=0;
         size_t b_sz=call->len;
         const char * b=call->buf;
         write_loop_:
            if ((r=::write(*(call->open_call.outfd),b,b_sz))>=0){

               if ((b_sz-=static_cast<size_t>(r))){
                  b+=r;
                  goto write_loop_;
               }

               if ( --writes_bf_flush_cnt == 0 ) {

                  writes_bf_flush_cnt=WRITES_BF_FLUSH_MAX_; 
                  fsync(*(call->open_call.outfd));
               }

               if ( call->use_locks ) {

                  flock(*(call->open_call.outfd), LOCK_UN);
               }

               return (b_sz>0);
            }
            (void)(call->use_locks && flock(*(call->open_call.outfd), LOCK_UN));
         return (false);
      }
      case ot_uds:
      case ot_tcp: {
          return (TX_SMART_SEND(*(call->open_call.outfd),call->buf,call->len,1,TIME_10MILISEC));
      }
      case ot_cout: {
         std::cout<<"log:{"<<call->buf+12<<"}"<<std::endl;
         return true;
      }
      default:break;
   }
   return (false);
}

TX_INTERNAL_INLINE
bool fd_test_(t_tx_log_open_call * const call) noexcept {
   int ierror=0;
   if (!call || ((*call->outfd)<0)){
      return (false);
   }

   switch (call->type){
      case ot_file:{
         if (flock((*call->outfd), LOCK_EX) || flock((*call->outfd), LOCK_UN))  {
            (void)::close((*call->outfd));
            (*call->outfd)=INVALID_;
            return (false);
         }
         (void)(call->ftrim && lseek((*call->outfd),0,SEEK_END));
         return (true);
      }
      case ot_uds:
      case ot_tcp:{
         if (!tx_get_sock_error((*call->outfd),&ierror)){
            (void)::shutdown((*call->outfd),SHUT_RDWR);
            (void)::close((*call->outfd));
            (*call->outfd)=INVALID_;
            return (false);
         }
         switch (tx_s_qs(ierror)){
            case tq_sup:{
               return (true);
            }
            case tq_tru:{
               return (true);
            }
            default:{
               if ((*call->outfd)>0){
                  (void)::shutdown((*call->outfd),SHUT_RDWR);
                  (void)::close((*call->outfd));
                  (*call->outfd)=INVALID_;
               }
               return (false);
            }
         }
      }
      default: return (false);
   }

}

bool titan_v3::fd_open(t_tx_log_open_call * const call) noexcept {
   if (call){
         if (*call->isopen && fd_test_(call))
            return (true);
         else
            (*call->isopen)=false;

         (*call->outfd)=INVALID_;
         switch (call->type){
            case ot_file:{
               if (((*call->outfd)=::open(call->path,O_CREAT |O_RDWR |  (call->ftrim?O_TRUNC:0) ))>=0 && 
                  (fchmod((*call->outfd), S_IRUSR | S_IWUSR |S_IRGRP |S_IWGRP |S_IROTH |S_IWOTH)<0)){
                  (void)::close((*call->outfd));
                  (*call->outfd)=INVALID_;
               }
            }break;
            case ot_uds:
            case ot_tcp:{
                  (void)(call->path && call->path[0] && !open_unix_connection(call->outfd,call->path));
                  if ((*call->outfd)>=0 && call->sock){
                     if (call->sock->type) return (false);
                     (void)(call->sock->port && ((*call->outfd)=tx_ip_socket_ex(call->sock)));
                  }
            }break;
            default:return (false);
         }
         return (((*call->isopen)=fd_test_(call)));
   }
   return (false);
}

bool titan_v3::fd_log(t_tx_log_log_call * const call) noexcept {
   if (call && call->len) {
   try_wrtite_:
      if((*call->open_call.isopen) && log_(call)){
         return (true);
      }
      if ((!((*call->open_call.isopen)=false)) && ((*call->open_call.outfd)>=0)){
         (void)::close((*call->open_call.outfd));
         (*call->open_call.outfd)=INVALID_;
      }
      if (++call->ntry<call->max){
         fd_open(&call->open_call);
         goto try_wrtite_;
      }
      return (false);
   }
   return (false);
}


