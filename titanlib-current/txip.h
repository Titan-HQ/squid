/*
 * $Id$
 */

#ifndef TITAN_IP_H
#define TITAN_IP_H

#ifdef __cplusplus
extern "C" {
#endif
#include <assert.h>
#include <time.h>
#include "global.h"
#include "txal.h"



//////////////////////////////////////////////////////////////////////////////////////////////////


typedef struct{
   u_char                           until;
   int                              socket;
   bool                             blocking;
   union {
      const char *                  snd;
      char *                        rcv;
   }                                buf;
   suseconds_t                      microsec_wait_tieout;
   size_t                           buf_sz;
   size_t*                          p_buf_sz;
   size_t                           buf_sz_max;
   size_t                           trymax;
}t_tx_smart_socket_call;


#define SOCKET_OPEN_RETRY_LOOP_MAX  10
#define TIME_1MILISEC               1000
#define TIME_10MILISEC              10*TIME_1MILISEC
#define TIME_50MILISEC              5*TIME_10MILISEC
#define TIME_100MILISEC             2*TIME_50MILISEC

#ifdef __cplusplus
}
#endif


/////////////////////////////////////////////////////////////////////////////////////////////////////////////////

TXATR void close_fd(const int,const bool);
TXATR t_qbit tx_s_qs(int en);
TXATR bool tx_set_sock_opt(const int,const int,const int, bool);
TXATR bool tx_get_sock_error(const int,int *);
TXATR bool tx_smart_send_ex(t_tx_smart_socket_call * const );

#define TX_SMART_SEND(a_pSocket_,a_sndbuf_,a_sndbufsz_,a_trymax_,                \
                     a_microsec_wait_tieout_) __extension__ ({                   \
   t_tx_smart_socket_call v_call__={};                                           \
   v_call__.socket=a_pSocket_;                                                   \
   v_call__.buf.snd=a_sndbuf_;                                                   \
   v_call__.buf_sz=a_sndbufsz_;                                                  \
   v_call__.trymax=a_trymax_;                                                    \
   v_call__.microsec_wait_tieout=a_microsec_wait_tieout_;                        \
   tx_smart_send_ex(&v_call__);                                                  \
})

TXATR bool tx_smart_recv_ex(t_tx_smart_socket_call * const );

#define TX_SMART_RECV(a_pSocket_,a_rcvbuf_,a_rcvdatasz_,a_rcvmaxsz_,             \
                                 a_trymax_,a_microsec_wait_tieout_,a_blocking_)  \
                                                               __extension__ ({  \
   t_tx_smart_socket_call v_call__={};                                           \
   v_call__.socket=a_pSocket_;                                                   \
   v_call__.buf.rcv=a_rcvbuf_;                                                   \
   v_call__.p_buf_sz=a_rcvdatasz_;                                               \
   v_call__.buf_sz_max=a_rcvmaxsz_;                                              \
   v_call__.trymax=a_trymax_;                                                    \
   v_call__.microsec_wait_tieout=a_microsec_wait_tieout_;                        \
   v_call__.blocking=a_blocking_;                                                \
   tx_smart_recv_ex(&v_call__);                                                  \
})

TXATR bool tx_smart_recv_until_ex(t_tx_smart_socket_call * const);

#define TX_SMART_RECV_UNTIL(a_pSocket_,a_rcvbuf_,a_rcvdatasz_,a_rcvmaxsz_,       \
                           a_until_,a_trymax_,a_microsec_wait_tieout_,           \
                           a_blocking_) __extension__ ({                         \
   t_tx_smart_socket_call v_call__={};                                           \
   v_call__.socket=a_pSocket_;                                                   \
   v_call__.buf.rcv=a_rcvbuf_;                                                   \
   v_call__.p_buf_sz=a_rcvdatasz_;                                               \
   v_call__.buf_sz_max=a_rcvmaxsz_;                                              \
   v_call__.trymax=a_trymax_;                                                    \
   v_call__.microsec_wait_tieout=a_microsec_wait_tieout_;                        \
   v_call__.blocking=a_blocking_;                                                \
   v_call__.until=a_until_;                                                      \
   tx_smart_recv_until_ex(&v_call__);                                            \
})
   
  
#define TX_SMART_RECV_NEW_LINE(a_pSocket_,a_rcvbuf_,a_rcvdatasz_,a_rcvmaxsz_,    \
                              a_trymax_,a_microsec_wait_tieout_,a_blocking_)     \
                                                               __extension__ ({  \
   t_tx_smart_socket_call v_call__={};                                           \
   v_call__.socket=a_pSocket_;                                                   \
   v_call__.buf.rcv=a_rcvbuf_;                                                   \
   v_call__.p_buf_sz=a_rcvdatasz_;                                               \
   v_call__.buf_sz_max=a_rcvmaxsz_;                                              \
   v_call__.trymax=a_trymax_;                                                    \
   v_call__.microsec_wait_tieout=a_microsec_wait_tieout_;                        \
   v_call__.blocking=a_blocking_;                                                \
   v_call__.until='\n';                                                          \
   tx_smart_recv_until_ex(&v_call__);                                            \
})

typedef enum {

   t_sec_none =                  0,
   t_sec_ip_format =             -1,
   t_sec_socket_create =         -2,
   t_sec_socket_opt_linger =     -3,
   t_sec_socket_opt_keepalive =  -4,
   t_sec_socket_opt_reuseaddr =  -5,
   t_sec_socket_opt_nosigpipe =  -6,
   t_sec_socket_opt_tcpnodely =  -7,
   t_sec_svr_bind =              -8,
   t_sec_svr_listen =            -9,
   t_sec_cli_connect =           -10,
   t_sec_cli_nb_select =         -11,
   t_sec_cli_nb_timeout =        -12,
   t_sec_cli_nb_connect =        -13,
   t_sec_unknown =               -255
   
}t_socket_err_codes;

/**
 * @name tx_ip_socket_ex
 * @abstract setup a socket
 * @param pArg[in] <t_txip_socket_ex *>
 * @return socket fd or in case of the error one of the following:
 * -1:  ip format error / wrong ip 
 * -2:  create a socket
 * -3:  setsockopt SO_LINGER
 * -4:  setsockopt SO_KEEPALIVE
 * -5:  setsockopt SO_REUSEADDR
 * -6:  setsockopt SO_NOSIGPIPE
 * -7:  setsockopt TCP_NODELAY
 * -8:  for svr: bind error
 * -9:  for svr: listen
 * -10: for client: connect error
 * -11: for client if non blocking connect is on: select error
 * -12: for client if non blocking connect is on: timeout
 * -13: for client if non blocking connect is on: connect error
 * -255: unknown error
 */
TXATR int tx_ip_socket_ex(const t_txip_socket_ex * const );

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
TXATR t_qbit tx_ip_try_send(const int, const char * const, size_t, const time_t,const bool);

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
TXATR t_qbit tx_ip_try_recv(const int, char * const, const size_t, size_t * const, const time_t,const bool);

#endif /* TITAN_IP_H */
