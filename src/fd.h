/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 51    Filedescriptor Functions */

#ifndef SQUID_FD_H_
#define SQUID_FD_H_

void fd_close(const int fd);
void fd_open(const int fd,const unsigned int type,const char *const);
void fd_note(const  int fd, const char *const);
void fd_bytes(const int fd, const int len,const  unsigned int type);
void fdDumpOpen(void);
int fdUsageHigh(void);
void fdAdjustReserved(void);
int default_read_method(const int, char *const, const int);
int default_write_method(const int, const char *const,const int);

#endif /* SQUID_FD_H_ */

