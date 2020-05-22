/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 51    Filedescriptor Functions */

#include "squid.h"
#include "comm/Loops.h"
#include "Debug.h"
#include "fd.h"
#include "fde.h"
#include "globals.h"
#include "profiler/Profiler.h"
#include "SquidTime.h"

// Solaris and possibly others lack MSG_NOSIGNAL optimization
// TODO: move this into compat/? Use a dedicated compat file to avoid dragging
// sys/socket.h into the rest of Squid??
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

int default_read_method(const int, char *const, const int);
int default_write_method(const int, const char *const , const int);
#if _SQUID_WINDOWS_
int socket_read_method(int, char *, int);
int socket_write_method(int, const char *, int);
int file_read_method(int, char *, int);
int file_write_method(int, const char *, int);
#else
int msghdr_read_method(const int, char *const , const int);
int msghdr_write_method(const int, const char *const ,const  int);
#endif

const char *fdTypeStr[] = {
    "None",
    "Log",
    "File",
    "Socket",
    "Pipe",
    "MsgHdr",
    "Unknown"
};

static void fdUpdateBiggest(const int fd,const  int);

static void
fdUpdateBiggest(const int fd,const int opening)
{
    if (fd < Biggest_FD)
        return;

    assert(fd < Squid_MaxFD);

    if (fd > Biggest_FD) {
        /*
         * assert that we are not closing a FD bigger than
         * our known biggest FD
         */
        assert(opening);
        Biggest_FD = fd;
        return;
    }

    /* if we are here, then fd == Biggest_FD */
    /*
     * assert that we are closing the biggest FD; we can't be
     * re-opening it
     */
    assert(!opening);

    while (Biggest_FD >= 0 && !fd_table[Biggest_FD].flags.open)
        --Biggest_FD;
}

void
fd_close(const int fd)
{
    if (-1!=fd){
       fde *const F = &fd_table[fd];
       assert(F->flags.open);

       if (F->type == FD_FILE) {
           assert(F->read_handler == NULL);
           assert(F->write_handler == NULL);
       }

       debugs(51, 3, "fd_close FD " << fd << " " << F->desc);
       Comm::SetSelect(fd, COMM_SELECT_READ, NULL, NULL, 0);
       Comm::SetSelect(fd, COMM_SELECT_WRITE, NULL, NULL, 0);
       F->flags.open = false;
       fdUpdateBiggest(fd, 0);
       --Number_FD;
       *F = fde();
       return;
    };
    assert(0 && "fd_close");
}

#if _SQUID_WINDOWS_

int
socket_read_method(int fd, char *buf, int len)
{
    int i;
    PROF_start(recv);
    i = recv(fd, (void *) buf, len, 0);
    PROF_stop(recv);
    return i;
}

int
file_read_method(int fd, char *buf, int len)
{
    int i;
    PROF_start(read);
    i = _read(fd, buf, len);
    PROF_stop(read);
    return i;
}

int
socket_write_method(int fd, const char *buf, int len)
{
    int i;
    PROF_start(send);
    i = send(fd, (const void *) buf, len, 0);
    PROF_stop(send);
    return i;
}

int
file_write_method(int fd, const char *buf, int len)
{
    int i;
    PROF_start(write);
    i = (_write(fd, buf, len));
    PROF_stop(write);
    return i;
}

#else
int
default_read_method(const int fd, char *const buf,const  int len)
{
    if (-1!=fd){

       if (buf && len>0){
          PROF_start(read);
          const int i = read(fd, buf, len);
          PROF_stop(read);
          return i;
       };
       return -1;
    };
    assert(0 && "default_read_method");
    return -1;
}

int
default_write_method(const int fd, const char *const buf,const int len)
{

   if (-1!=fd){
      if (buf && len>0){
         PROF_start(write);
         const int i=write(fd, buf, len);
         PROF_stop(write);
         return i;
      }return -1;
   };
   assert(0 && "default_write_method");
   return -1;
}

int
msghdr_read_method(const int fd, char *const buf,const  int len)
{
   if (-1!=fd){
      if (buf && len>0){
         PROF_start(read);
         const int i = recvmsg(fd, reinterpret_cast<msghdr*>(buf), MSG_DONTWAIT);
         PROF_stop(read);
         return i;
      };
      return -1;
   }
   assert(0 && "msghdr_read_method");
   return -1;
}

int
msghdr_write_method(const int fd, const char *const buf, const int len)
{
   if (-1!=fd){
      if (buf && len>0){
         PROF_start(write);
         const int i = sendmsg(fd, reinterpret_cast<const msghdr*>(buf), MSG_NOSIGNAL);
         PROF_stop(write);
         return i > 0 ? len : i; // len is imprecise but the caller expects a match
      };
      return -1;
   };
   assert(0 && "msghdr_write_method");
   return -1;
}

#endif

void
fd_open(const int fd,const unsigned int type, const char *const desc)
{

    if (-1!=fd){
       fde *const F= &fd_table[fd];
       if (F->flags.open) {
           debugs(51, DBG_IMPORTANT, "WARNING: Closing open FD " << std::setw(4) << fd);
           fd_close(fd);
       }
       assert(!F->flags.open);
       debugs(51, 3, "fd_open() FD " << fd << " " << (desc?desc:"<empty>"));
       F->type = type;
       F->flags.open = true;
       F->epoll_state = 0;
   #if _SQUID_WINDOWS_

       F->win32.handle = _get_osfhandle(fd);

       switch (type) {

       case FD_SOCKET:

       case FD_PIPE:
           F->read_method = &socket_read_method;
           F->write_method = &socket_write_method;
           break;

       case FD_FILE:

       case FD_LOG:
           F->read_method = &file_read_method;
           F->write_method = &file_write_method;
           break;

       default:
           fatalf("fd_open(): unknown FD type - FD#: %i, type: %u, desc %s\n", fd, type, desc);
       }

   #else
       switch (type) {

       case FD_MSGHDR:
           F->read_method = &msghdr_read_method;
           F->write_method = &msghdr_write_method;
           break;

       default:
           F->read_method = &default_read_method;
           F->write_method = &default_write_method;
           break;
       }

   #endif

       fdUpdateBiggest(fd, 1);

       fd_note(fd, desc);

       ++Number_FD;
       return;
   };
    assert(0 && "fd_open");
}

void
fd_note(const int fd, const char *const s)
{
    if (-1!=fd)
    if (fde *const F = &fd_table[fd]){
       if (s)
           xstrncpy(F->desc, s, FD_DESC_SZ);
       else
           *(F->desc) = 0; // ""-string
    }
}

void
fd_bytes(const int fd,const  int len,const unsigned int type)
{
   if (-1!=fd && len>0)
   if (fde *const F = &fd_table[fd]){
      assert(type == FD_READ || type == FD_WRITE);

       if (type == FD_READ)
           F->bytes_read += len;
       else
           F->bytes_written += len;
   };
}


void
fdDumpOpen(void)
{
    for (int i = 0; i < Squid_MaxFD; ++i) {
        const fde *const F = &fd_table[i];

           if (!F->flags.open)
               continue;

           if (i == fileno(debug_log))
               continue;

           debugs(51, DBG_IMPORTANT, "Open FD "<< std::left<< std::setw(10) <<
                  (F->bytes_read && F->bytes_written ? "READ/WRITE" :
                   F->bytes_read ? "READING" : F->bytes_written ? "WRITING" :
                   "UNSTARTED")  <<
                  " "<< std::right << std::setw(4) << i  << " " << F->desc);
    };
}

int
fdNFree(void)
{
    return Squid_MaxFD - Number_FD - Opening_FD;
}

int
fdUsageHigh(void)
{
    int nrfree = fdNFree();

    if (nrfree < (RESERVED_FD << 1))
        return 1;

    if (nrfree < (Number_FD >> 2))
        return 1;

    return 0;
}

/* Called when we runs out of file descriptors */
void
fdAdjustReserved(void)
{
    int newReserve;
    int x;
    static time_t last = 0;
    /*
     * don't update too frequently
     */

    if (last + 5 > squid_curtime)
        return;

    /*
     * Calculate a new reserve, based on current usage and a small extra
     */
    newReserve = Squid_MaxFD - Number_FD + min(25, Squid_MaxFD / 16);

    if (newReserve <= RESERVED_FD)
        return;

    x = Squid_MaxFD - 20 - min(25, Squid_MaxFD / 16);

    if (newReserve > x) {
        /* perhaps this should be fatal()? -DW */
        debugs(51, DBG_CRITICAL, "WARNING: This machine has a serious shortage of filedescriptors.");
        newReserve = x;
    }

    if (Squid_MaxFD - newReserve < min(256, Squid_MaxFD / 2))
        fatalf("Too few filedescriptors available in the system (%d usable of %d).\n", Squid_MaxFD - newReserve, Squid_MaxFD);

    debugs(51, DBG_CRITICAL, "Reserved FD adjusted from " << RESERVED_FD << " to " << newReserve <<
           " due to failures (" << (Squid_MaxFD - newReserve) << "/" << Squid_MaxFD << " file descriptors available)");
    RESERVED_FD = newReserve;
}

