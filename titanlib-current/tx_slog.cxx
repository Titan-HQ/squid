/*
 * $Id$
 */
#include "global.h"
#include "sock_rw.h"
#include "tx_log.hxx"
#include "txip.h"
#include <cassert>
#include <cstdarg>
#include <cstdio>
#include <exception>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <sys/stat.h>

using namespace titan_v3;

#define MK_OPEN_(a_isopen_,a_outfd_,a_sock_,a_udspath_,                          \
                                             a_type_) __extension__ ({           \
   t_tx_log_open_call v_call__={                                                 \
      .isopen=(a_isopen_),                                                       \
      .outfd=(a_outfd_),                                                         \
      .sock=(a_sock_),                                                           \
      .path=(a_udspath_),                                                        \
      .type=(a_type_)                                                            \
   };                                                                            \
   fd_open(&v_call__);                                                           \
})

#define MK_LOG_TO_FD_CALL_(a_b_,a_l_,a_state_,a_fd_,a_socket_,                   \
                           a_path_,a_type_) __extension__ ({                     \
   t_tx_log_log_call v_call__={                                                  \
      .buf=(a_b_),                                                               \
      .len=(a_l_),                                                               \
      .max=2,                                                                    \
      .open_call.isopen=(a_state_),                                              \
      .open_call.outfd=(a_fd_),                                                  \
      .open_call.sock=(a_socket_),                                               \
      .open_call.path=(a_path_),                                                 \
      .open_call.type=(a_type_),                                                 \
   };                                                                            \
   fd_log(&v_call__);                                                            \
})

bool tx_slog::open() noexcept 
{
   if(  this->active_ ){
      return(false);
   }
   std::unique_lock<std::mutex> l_lu{this->lock_ , std::defer_lock};  /* Initially no lock managed */
   if (this->auto_lock)
      l_lu.lock(); 

   if (MK_OPEN_(&this->active_,
                &this->logger_fd,
                &this->txsocket,
                (this->path.length()?this->path.c_str():nullptr),this->type ))
   {
      return (this->active_);
   }
   this->active_ = false;
   return ( this->active_ );
   /* If lock (l_lu) was obtained then it is released here*/
}

bool tx_slog::log() noexcept {
   return (this->log(*this));
}

bool tx_slog::log(tx_alog & what) noexcept 
{
   if (this->active_){
      const char * const buf_{what};
      if ( buf_ ) {

        std::unique_lock<std::mutex> l_lu{this->lock_ , std::defer_lock};  /* Initially no lock managed */
        if (this->auto_lock)
           l_lu.lock();

         if (   what.data_prepared && 
                MK_LOG_TO_FD_CALL_(     buf_,
                                        what.length(),
                                        &this->active_,
                                        &this->logger_fd,
                                        &this->txsocket,
                                        (this->path.length()?this->path.c_str():nullptr),
                                        this->type )){
             return (true);
         }
      /*lock is unlocked*/
      }
   }
   return (false);
}

bool tx_slog::log_to_tcp(tx_alog & what, t_txip_socket_ex* const call_) noexcept {
   bool active__{};
   int fd_=INVALID_;
   if (call_){
      if (const char * const buf_=what){
         if (what.data_prepared && MK_LOG_TO_FD_CALL_(
         buf_,
         what.length(),
         &active__,
         &fd_,
         call_,
         nullptr,
         ot_tcp
         )) return (true);
      }
   }   
   return (false);
}

bool tx_slog::log_to_uds(tx_alog & what, const char * const udspath) noexcept {
   bool active__{};
   int fd_=INVALID_;
   if (udspath){
      if (const char * const buf_=what){
         if (what.data_prepared && MK_LOG_TO_FD_CALL_(
         buf_,
         what.length(),
         &active__,
         &fd_,
         nullptr,
         udspath,
         ot_uds
         )) return (true);
      }
   }
   return (false);
}
