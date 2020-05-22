/*
 * $Id$
 */
#include "global.h"
#include "tx_log.hxx"
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

#define MK_OPEN_(a_isopen_,a_outfd_,a_path_,a_type_,a_trim_) __extension__ ({    \
   t_tx_log_open_call v_call__{                                                  \
      .isopen = (a_isopen_),                                                     \
      .outfd = (a_outfd_),                                                       \
      .path = (a_path_),                                                         \
      .type = (a_type_),                                                         \
      .ftrim = (a_trim_)                                                         \
   };                                                                            \
   fd_open(&v_call__);                                                           \
})

#define MK_LOG_TO_FD_CALL_(a_b_,a_l_,a_state_,a_fd_,a_path_,                     \
                           a_type_,a_trim_) __extension__ ({                     \
   t_tx_log_log_call v_call__={                                                  \
      .buf = (a_b_),                                                             \
      .len = (a_l_),                                                             \
      .max = 2,                                                                  \
      .use_locks = false,                                                        \
      .open_call.isopen = (a_state_),                                            \
      .open_call.outfd = (a_fd_),                                                \
      .open_call.sock = NULL,                                                    \
      .open_call.path = (a_path_),                                               \
      .open_call.type = (a_type_),                                               \
      .open_call.ftrim = (a_trim_),                                              \
   };                                                                            \
   fd_log(&v_call__);                                                            \
})

bool tx_flog::open() noexcept 
{
   if (!this->active_ && this->auto_lock && !this->lock()){
      return (false);
   }

   if(MK_OPEN_(&this->active_,&this->logger_fd,this->path.c_str(),this->type,this->f_trim)){
      return (this->active_);
   }
   this->logger_fd=INVALID_;
   (void)(this->auto_lock && this->unlock());
   return ((this->active_=true));
}

bool tx_flog::log() noexcept
{
   return (static_cast<tx_flog*>(this)->log(*this));
}

bool tx_flog::log(tx_alog & what) noexcept {
   if (this->active_){
      if (const char * const buf_=what){
         std::cout<<"tx_flog::log:{"<<buf_<<"}:"<<what.data_prepared<<std::endl;
         if (what.data_prepared && MK_LOG_TO_FD_CALL_(
         buf_,
         what.length(),
         &this->active_,
         &this->logger_fd,
         this->path.c_str(),
         this->type,
         this->f_trim
         )) return (true);
      }
   }
   (void)(this->auto_lock && this->unlock());
   return (false);
}

bool tx_flog::log_to_file(tx_alog & what, const char * const path) noexcept {
   bool active__{};
   int fd_=INVALID_;
   if (path && what.prepare() && what.data_prepared && MK_LOG_TO_FD_CALL_(
   what,
   what.length(),
   &active__,
   &fd_,
   path,
   ot_file,
   false
   )) return (true);
   return (false);
}
