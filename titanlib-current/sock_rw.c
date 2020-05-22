/*
 * $Id$
 */

#include "sock_rw.h"
#include <netinet/tcp.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>


bool open_tcpip_connection(int *const sockfd, const uint32_t ipaddr,const  uint16_t sock){
   struct sockaddr_in Address={.sin_family = AF_INET,.sin_port = htons(sock),.sin_addr.s_addr = htonl(ipaddr)};
   const int sockfd_local=socket(AF_INET, SOCK_STREAM, 0);
   if ( sockfd_local < 0 ){
      return false;
   }

   if (0 != connect(sockfd_local, (struct sockaddr *)&Address, sizeof(Address))){
      close(sockfd_local);
      return false;
   }

   *sockfd = sockfd_local;
   return true;
}

bool open_unix_connection(int *const sockfd, const char *const path){
   *sockfd=INVALID_;
   struct sockaddr_un Address={.sun_family = AF_LOCAL};
   (void)strlcpy(Address.sun_path, path,sizeof(Address.sun_path));

   const int sockfd_local = socket(AF_LOCAL, SOCK_STREAM, 0);
   if (sockfd_local < 0){
      return false;
   }
   const int l_cr = connect(sockfd_local, (struct sockaddr*)&Address, sizeof(Address));
   if (l_cr != 0)
   {
       printf("------open_unix_connection() errno = %d\n", errno);
      (void)close(sockfd_local);
      return false;
   }
   *sockfd = sockfd_local;
   return true;
}

bool open_unix_connection_noblock(int *const sockfd, const char *const path)
{
   struct sockaddr_un Address={.sun_family = AF_LOCAL};
   (void)strlcpy(Address.sun_path, path,sizeof(Address.sun_path));
   const int sockfd_local = socket(AF_LOCAL, SOCK_STREAM, 0);
   if (sockfd_local < 0){
      return false;
   }

   if (0 != connect(sockfd_local, (struct sockaddr*)&Address, sizeof(Address))){
      close(sockfd_local);
      return false;
   }
   fcntl(sockfd_local,F_SETFL,fcntl(sockfd_local,F_GETFL,0) | O_NONBLOCK);

   //errno
   *sockfd = sockfd_local;
   return true;
}

// Socket read and write functions,
// to read/write n bytes from/to a socket.
// Seem to be based on code from W. Richard Stevens books (??)
// (UNIX Network Programming Volume 1)

ssize_t writen (const int fd, const void *const vptr,const  size_t n){
   const char *ptr=vptr;
   size_t nleft = n;
   while (nleft > 0) {
      ssize_t nwritten=write (fd, ptr, nleft);
      if (nwritten<= 0) {
         if (errno == EINTR || errno == EAGAIN || errno ==ENOSPC)
            nwritten = 0;
         else
            return (INVALID_);
      }
      nleft -= (size_t)nwritten;
      ptr += nwritten;
   }
   return ((ssize_t)n);
}

ssize_t readn (const int fd, void *const vptr,const  size_t n){
   char *ptr=vptr;
   size_t nleft = n;
   while (nleft > 0){
      ssize_t nread=read (fd, ptr, nleft);
      if (nread < 0){
         // Permit EAGAIN, because if the socket is in non-blocking mode
         // (which can happen if setsockopt() is used to set a recv timeout)
         // then no data might be ready to read yet.
         if (errno == EINTR || errno == EAGAIN)
            nread = 0;
         else
            return (INVALID_);
      } else if (nread == 0)
         break;   /* EOF */
      nleft -= (size_t)nread;
      ptr += nread;
   }
   return (ssize_t)(n - nleft);
}
