/*
 * $Id$
 */


#include "txip.h"
#include "global.h"
#include "log.h"
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/types.h>
#include <sys/un.h>

TX_INTERNAL_INLINE
bool tx_set_sock_opt_(const int pSocket,const int pLevel,const int pOpt, bool pVal){
   const int v=(int)pVal;
   return ((!setsockopt(pSocket, pLevel, pOpt, &v, sizeof(int))));
}

#define log_n_clean_n_leave(_S_,_E_){                                   \
   TXDEBLOG(                                                            \
         titax_log(  LOG_ERROR,                                         \
                     "%s : error %d : [ %d | %s ]\n",                   \
                     __func__,                                          \
                     (_E_),                                             \
                     errno,                                             \
                     strerror( errno )                );                \
         );                                                             \
   if ( INVALID_ < (_S_) ) {                                            \
      fcntl( (_S_), F_SETFL, fcntl( (_S_), F_GETFL, 0 ) ^ O_NONBLOCK ); \
      shutdown( (_S_), SHUT_RDWR);                                      \
      close( (_S_) );                                                   \
   }                                                                    \
   return (_E_);                                                        \
}

#define assert_option( _S_, _O_, _F_, _V_, _E_ )         \
if ( !tx_set_sock_opt_( (_S_), (_O_), (_F_), (_V_) ) ){  \
   log_n_clean_n_leave( _S_ , _E_ )                      \
}

int tx_ip_socket_ex( const t_txip_socket_ex * const restrict arg ) {

   int a_socket = t_sec_unknown;

   if ( arg && arg->port ) {

      errno = 0;

      struct sockaddr_in server_addr = {  .sin_family = AF_INET,
                                          .sin_port = htons( arg->port ) };

      if ( arg->ip[0] ){

         if ( !inet_aton( arg->ip, &server_addr.sin_addr ) ) {

            log_n_clean_n_leave( a_socket, t_sec_ip_format ) /* return */
         }
      } 
      else {

         server_addr.sin_addr.s_addr =INADDR_ANY;
      }

      if ( arg->op_so_stream ) {

         if ( INVALID_ == ( a_socket = socket( AF_INET, SOCK_STREAM, 0 ) ) ) {

            log_n_clean_n_leave( a_socket, t_sec_socket_create ) /* return */
         }

         if ( INVALID_ == setsockopt(  a_socket,
                                       SOL_SOCKET, 
                                       SO_LINGER,
                                       &arg->op_so_linger, sizeof arg->op_so_linger )  ) {

            log_n_clean_n_leave( a_socket, t_sec_socket_opt_linger ) /* return */
         }
      }

      assert_option( a_socket, SOL_SOCKET, SO_KEEPALIVE, arg->op_so_keep_alive, t_sec_socket_opt_keepalive )

      assert_option( a_socket, SOL_SOCKET, SO_REUSEADDR, arg->op_so_reuse_addr, t_sec_socket_opt_reuseaddr )

      assert_option( a_socket, SOL_SOCKET, SO_NOSIGPIPE, arg->op_so_nosigpipe, t_sec_socket_opt_nosigpipe )

      assert_option( a_socket, IPPROTO_TCP, TCP_NODELAY, arg->op_tcp_no_delay, t_sec_socket_opt_tcpnodely )

      if ( TXST_CLIENT == arg->type ){

         bool set_io_no_block = false;

         if ( arg->op_connect_no_block ){

            set_io_no_block = arg->op_io_no_block;

            fcntl( a_socket, F_SETFL, fcntl( a_socket, F_GETFL, 0 ) | O_NONBLOCK) ;
            errno = 0;
         }

         if( INVALID_ == connect( a_socket, (struct sockaddr *)&server_addr, sizeof( server_addr ) ) ) {

            if ( errno != EINPROGRESS){

               log_n_clean_n_leave( a_socket, t_sec_cli_connect ) /* return */
            }

            if ( arg->op_connect_no_block ) {

               fd_set rset, wset;
               FD_ZERO(&rset);
               FD_ZERO(&wset);
               FD_SET( (long unsigned int)a_socket, &rset);
               memcpy(&wset, &rset, sizeof(rset) );

               struct timeval timeout;
               
               memcpy( &timeout, &arg->connect_timeout, sizeof ( struct timeval ) );

               switch ( select( a_socket+1, &rset, &wset, NULL, (struct timeval *)&timeout ) ) {

                  case INVALID_: log_n_clean_n_leave( a_socket, t_sec_cli_nb_select ) /* return  */

                  case 0:{

                     errno = ETIMEDOUT;

                     log_n_clean_n_leave( a_socket, t_sec_cli_nb_timeout ) /* return */
                  }

                  default:{

                     if( FD_ISSET( (long unsigned int) a_socket, &rset ) || FD_ISSET( (long unsigned int)a_socket, &wset ) ) {

                        int error = 0;
                        size_t esize = sizeof(int);

                        if( !getsockopt( a_socket, SOL_SOCKET, SO_ERROR, &error, (socklen_t *)&esize ) ) {

                           if( !error ) {

                              if ( !set_io_no_block ) {

                                 fcntl( a_socket, F_SETFL, fcntl( a_socket, F_GETFL, 0 ) ^ O_NONBLOCK );
                              }

                           }
                           else {

                              errno = error;

                              log_n_clean_n_leave( a_socket, t_sec_cli_nb_connect ) /* return */
                           }
                        }
                     }

                  } break;

               } /* switch */

            } /* if op blocking */

         } /* if connect */

         if ( !set_io_no_block && arg->op_io_no_block ) {

            fcntl( a_socket, F_SETFL, fcntl( a_socket, F_GETFL, 0 ) | O_NONBLOCK );
         }

         return a_socket;

      } /* if client */

      /* else svr */

      if ( arg->op_io_no_block ){

         fcntl( a_socket, F_SETFL, fcntl( a_socket, F_GETFL, 0 ) | O_NONBLOCK );
      }

      //fcntl(a_socket, F_SETFL, O_ASYNC);

      if ( INVALID_ == bind( a_socket, (struct sockaddr *)&server_addr, sizeof(server_addr) ) ) {

         log_n_clean_n_leave( a_socket, t_sec_svr_bind ) /* return */
      }

      if ( INVALID_ == listen( a_socket, (int)arg->backlog_sz ) ) {

         log_n_clean_n_leave( a_socket, t_sec_svr_listen ) /* return */
      }

   } /* main if */

   return a_socket;
}

TX_INTERNAL_INLINE
int iserror_(const int s){
   int esize = sizeof(int);
   int ierr=0;
   if (0>getsockopt(s, SOL_SOCKET, SO_ERROR, &ierr, (socklen_t *)&esize)) return INVALID_;
   return ierr;
}

#define RETURN_(r_) __extension__ ({               \
   (void)(!nbs && fcntl(s,F_SETFL,orgSockStat));   \
   return (r_);                                    \
}) 


/**
 * tx_ip_try_send
 * @param s    :Socket/fd
 * @param ib   :In Buffer
 * @param ibs  :In Buffer Size - size of data 
 * @param tmo  :TimeOut - in sec
 * @param nbs  :Non Blocking Socket - used socket is already in the non-blocking mode
 * @return     :can return one of the following states:
 *             :tq_uns = ERROR - at least one of the arguments is invalid
 *             :tq_tru = OK 
 *             :tq_fal = ERROR - general error
 *             :tq_sup = TIMEOUT
 * 
 */

t_qbit tx_ip_try_send(const int s, const char * ib, size_t ibs, const time_t tmo,const bool nbs ){

   if (0<=s && ib && ibs && !iserror_(s) ){
      fd_set  wset,eset;
      FD_ZERO(&wset);
      FD_SET( (long unsigned int)s, &wset);
      eset=wset;
      struct timeval tv;
      tv.tv_sec=tmo;
      tv.tv_usec=0;
      int orgSockStat=0;
      if (!nbs){
         orgSockStat=fcntl(s, F_GETFL, NULL);
         fcntl(s,F_SETFL,orgSockStat | O_NONBLOCK);
      }

      size_t ctx=0;
      ssize_t c=0;
      while (++ctx<1024 && (c = send(s, ib, ibs,MSG_NOSIGNAL))>=0 && ibs>(size_t)c){
         switch (c){
            case INVALID_:{
               const int ierror=errno;
               if (tx_s_qs(ierror)==tq_sup){
                  switch (select(s+1,0,&wset,&eset, &tv)){
                     case INVALID_:{
                        RETURN_(tq_fal);//error
                     }break;
                     case 0:{
                        RETURN_(tq_sup);//timeout
                     }break;
                     default:{
                        if (FD_ISSET( (long unsigned int)s, &eset)) return tq_fal; //error
                        if (FD_ISSET( (long unsigned int)s, &wset) && !iserror_(s)) continue;  //ready
                        RETURN_(tq_fal);//error for sure
                     }break;
                  }
               }
               RETURN_(tq_fal); //error
            }break;
            default:{
               if (!iserror_(s)){
                  ibs-=(size_t)c;
                  ib+=(size_t)c;
                  continue; //trymore
               }
               RETURN_(tq_fal); //error
            }break;
         }
      }
      if (ctx<1024) return(tq_tru);//OK
      RETURN_(tq_fal); //error
   }
   return tq_uns; //error
}



/**
 * tx_ip_try_recv
 * @param s    :Socket/fd
 * @param ob   :Out Buffer
 * @param obs  :Out Buffer Size - max size allowed to read
 * @param os   :Out Size - actual size 
 * @param tmo  :TimeOut - in sec
 * @param nbs  :Non Blocking Socket - used socket is already in the non-blocking mode
 * @return     :can return one of the following states:
 *             :tq_uns = ERROR - at least one of the arguments is invalid
 *             :tq_tru = OK 
 *             :tq_fal = ERROR - general error
 *             :tq_sup = TIMEOUT
 * 
 */

t_qbit tx_ip_try_recv(const int s, char * const ob, const size_t obs, size_t * os, const time_t tmo, const bool nbs ){

   if (0<=s && ob && obs && os && !iserror_(s)){
      fd_set  rset,eset;
      FD_ZERO(&rset);
      FD_SET( (long unsigned int)s, &rset);
      eset=rset;
      struct timeval tv;
      tv.tv_sec=tmo;
      tv.tv_usec=0; 
      int orgSockStat=0;
      if (!nbs){
         orgSockStat=fcntl(s, F_GETFL, NULL);
         fcntl(s,F_SETFL,orgSockStat | O_NONBLOCK);
      } 
     
      switch (select(s+1,&rset,0,&eset, &tv)){
         case INVALID_:{ 
            RETURN_(tq_fal); //error
         }break;
         case 0:{
            RETURN_(tq_sup); //timeout
         }break;
         default:{
            if (FD_ISSET( (long unsigned int)s, &eset)) return(tq_fal);//error
            if (FD_ISSET( (long unsigned int)s, &rset) && !iserror_(s)){
               ssize_t c=0;
               switch ((c = recv(s, ob, obs,MSG_DONTWAIT))){
                  case INVALID_:{
                     RETURN_(tq_fal); //error
                  }break;
                  default:{
                     if (!iserror_(s) && c){
                        ob[c]=0;
                        *os=(size_t)c;
                        RETURN_(tq_tru); //OK
                     }
                     RETURN_(tq_fal); //error
                  }break;
               }
            }
            RETURN_(tq_fal); //error
         }break;
      }
      assert(0 && "tx_ip_try_recv crash!\n");
   }
   return (tq_uns); //error
}

#define LOG_MSG_(a_msg_){                    \
   titax_log(LOG_WARNING,"%s\n", a_msg_);    \
   (void)printf("%s\n", a_msg_);             \
}


/*
 * TODO:
 * 1. Unify tx_ip_try_send, tx_ip_try_recv,tx_smart_recv_ex,tx_smart_send_ex,tx_smart_recv_until_ex
 * into one/single model/function
 * 2. TEST tx_smart_recv_ex,tx_smart_send_ex
 */

bool tx_smart_recv_ex(t_tx_smart_socket_call * const restrict call){

   if (call)
   {      
      int ierror=0;
      if (  call->socket>0 && 
            call->buf.snd && 
            call->buf_sz && 
            tx_get_sock_error(call->socket,&ierror) ){

          fd_set io_fds;
          struct timeval tv={0,0};

         (*call->p_buf_sz)=0;
         size_t try_ctx=0;
         while (true){

            switch (tx_s_qs(ierror)){
               case tq_sup:{
                  FD_ZERO(&io_fds);
                  FD_SET( (long unsigned int)call->socket, &io_fds);
                  tv.tv_sec= 0;
                  tv.tv_usec = call->microsec_wait_tieout;
                  errno=0;
                  switch (select(call->socket+1,&io_fds, 0,0, &tv)){
                     case INVALID_:ierror=errno;
                     /* fall through */
                     case 0:{
                        if (++try_ctx<call->trymax) continue;
                        LOG_MSG_("tx_smart_recv_ex:error:0\n")
                        return false;
                     }
                     default:{
                        if (FD_ISSET( (long unsigned int)call->socket, &io_fds)){
                           if (tx_get_sock_error(call->socket,&ierror)) continue;
                        } else {
                           if (++try_ctx<call->trymax && tx_get_sock_error(call->socket,&ierror)) continue;
                        }
                        LOG_MSG_("tx_smart_recv_ex:error:1\n")
                        return false;
                     } 
                  }
               }
               case tq_tru:{
                  ssize_t cnt=recv(call->socket, call->buf.rcv, call->buf_sz_max,(call->blocking?0:MSG_DONTWAIT));
                  switch (cnt){
                     case INVALID_:ierror=errno;
                     /* fall through */
                     case 0:{
                        if (++try_ctx<call->trymax) continue;
                     }break;
                     default:{
                        //We shouldn't terminate the data
                        call->buf.rcv[(size_t)cnt] = 0;
                        (*call->p_buf_sz)=(size_t)cnt;
                        return true;
                     }
                  }
               }
               /* fall through */
               default:{
                  LOG_MSG_("tx_smart_recv_ex:error:2\n")
                  return false;
               }
            }
         }
      }
   }
   LOG_MSG_("tx_smart_recv_ex:error:3\n")
   return false;
}

bool tx_smart_send_ex(t_tx_smart_socket_call * const restrict call)
{
   if (call)
   {
      int ierror = 0;
      if (  call->socket>0 && 
            call->buf.snd && 
            call->buf_sz &&
            tx_get_sock_error(call->socket,&ierror) ) {

         fd_set io_fds;
         struct timeval tv={0,0};
         size_t try_ctx=0;
         while (true)
         {
            const t_qbit l_tqbit = tx_s_qs(ierror);
            switch (l_tqbit)
            {
               case tq_sup:{
                  FD_ZERO(&io_fds);
                  FD_SET( (long unsigned int)call->socket, &io_fds);
                  tv.tv_sec= 0;
                  tv.tv_usec = call->microsec_wait_tieout;
                  errno=0;
                  switch (select(call->socket+1, 0 ,&io_fds,0, &tv)){
                     case INVALID_:ierror=errno;
                     /* fall through */
                     case 0:{
                        if (++try_ctx<call->trymax) continue;
                        LOG_MSG_("tx_smart_send_ex:error:0\n")
                        return false;
                     }
                     default:{
                        if (FD_ISSET( (long unsigned int)call->socket, &io_fds)){
                           if (tx_get_sock_error(call->socket,&ierror)) continue;
                        } else {
                           if (++try_ctx<call->trymax && tx_get_sock_error(call->socket,&ierror)) continue;
                        }
                        LOG_MSG_("tx_smart_send_ex:error:1\n")
                        return false;
                     }
                  }
               }
               case tq_tru:{
                     size_t ctx=0;
                     ssize_t cnt=0;
                     while (++ctx<1024 && call->buf_sz && (cnt = send(call->socket, call->buf.snd, call->buf_sz,MSG_NOSIGNAL))>INVALID_){
                        call->buf_sz-=(size_t)cnt;
                        call->buf.snd+=(size_t)cnt;
                     }
                     if (!call->buf_sz) return (true); //done finished
                     if (ctx==1024){
                        LOG_MSG_("tx_smart_send_ex:error:2\n")
                        return false;
                     }
                     ierror=errno;
                     continue;
               }
               default:{
                  titax_log(LOG_WARNING,"tx_smart_send_ex:error:3 .... ierror %d\n", ierror);
                  return false;
               }
            }
         }
      }
   }
   LOG_MSG_("tx_smart_send_ex:error:4\n")
   return false;
}

bool tx_smart_recv_until_ex(t_tx_smart_socket_call * const call){
   int ierror;
   fd_set io_fds;
   struct timeval tv;
   FD_ZERO(&io_fds);
   unsigned int n=0;
   ssize_t cnt=0;

   (*call->p_buf_sz)=0;
   char * buff=call->buf.rcv;
   char * pos_until=NULL;
rcv_err_get__:
   if (!call || !call->socket || !tx_get_sock_error(call->socket,&ierror)){
      (void)printf("tx_smart_recv_until->_snd_err_get error\n");
      return false;
   }
rcv_err_test__:
   switch (tx_s_qs(ierror)){
      case tq_sup:{
rcv_try_loop__:
         FD_SET( (long unsigned int)call->socket, &io_fds);
         tv.tv_sec= 0;
         tv.tv_usec = call->microsec_wait_tieout;
         switch (select(call->socket+1,&io_fds,0,0, &tv)){
            case INVALID_:
            case 0:{
               if (++n>call->trymax)return (false);
               goto rcv_err_test__;
            }
            default:{
               switch((uint64_t)FD_ISSET( (long unsigned int)call->socket, &io_fds)){
                  case 0:{
                     if (++n>call->trymax)return (false);
                     goto rcv_err_test__;//loop
                  }
                  default:{
                     goto rcv_err_get__;
                  }
               }
            }
         }
      }
      case tq_tru:{
         goto rcv__;
      }
      default:{
         (void)printf("tx_smart_recv_until->_rcv_err_test:[%d|%d] other error \n",call->socket,ierror);
         return false;
      }
   }
rcv__:
   switch ((cnt=recv(call->socket, buff, call->buf_sz_max, MSG_PEEK | (call->blocking?0:MSG_DONTWAIT)))){
      case INVALID_:{
         ierror=errno;
         goto rcv_err_test__;
      }
      case 0:{
         if (++n>call->trymax)return (false);
         goto rcv_err_get__; 
      }
      default:{
         pos_until=(char*)memchr((void*)buff,call->until,(size_t)cnt);
         if (pos_until && ((cnt=(pos_until-buff+1))>0) ){
            cnt=recv(call->socket, call->buf.rcv, (size_t)cnt,MSG_DONTWAIT);
         } else {
            if (++n>call->trymax)return (false);
            (void)zm(buff,call->buf_sz_max);
            goto rcv_try_loop__;
         }
      }break;
   }
   call->buf.rcv[(size_t)cnt] = 0;
   (*call->p_buf_sz)=(size_t)cnt;
   return true;
}

t_qbit tx_s_qs(int en){switch (en){case 0:return tq_tru;case EAGAIN: return tq_sup;default:return tq_fal;} }

void close_fd(const int fd,const bool is_nblock){
   if (INVALID_<fd){
      (void)(is_nblock && fcntl(fd,F_SETFL,fcntl(fd,F_GETFL,0) ^ O_NONBLOCK));
      (void)shutdown(fd, SHUT_RDWR);
      (void)close(fd);
   }
}

bool tx_set_sock_opt(const int pSocket,const int pLevel,const int pOpt, bool pVal){
   return tx_set_sock_opt_(pSocket,pLevel,pOpt,pVal);
}

bool tx_get_sock_error(const int pSocket,int * restrict pErrOut){
   int esize = sizeof(int);
   return ((!getsockopt(pSocket, SOL_SOCKET, SO_ERROR, pErrOut, (socklen_t *)&esize)));
}

