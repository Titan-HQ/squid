/*
 *  Copyright 2003 Packet Dynamics Limited. All rights reserved.
 */

/*
 * $Id$
 */

#include <stdbool.h>
#include "global.h"

#ifndef LIB_SOCKRW_H
#define LIB_SOCKRW_H

TXATR bool open_tcpip_connection(int *const, const uint32_t,const uint16_t);
TXATR bool open_unix_connection(int *const, const char *const);
TXATR bool open_unix_connection_noblock(int *const, const char *const);
TXATR ssize_t readn(const int, void* const vptr,const  size_t);
TXATR ssize_t writen (const int, const void *const vptr,const  size_t);

#endif /* #ifndef LIB_SOCKRW_H */
