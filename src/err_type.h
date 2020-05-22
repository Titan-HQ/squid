/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef _SQUID_ERR_TYPE_H
#define _SQUID_ERR_TYPE_H

#include "TAPE.h"
//WARNING : if changing list of known errors, please update manually the err_type.cc file
typedef t_err_type err_type;


extern const char *err_type_str[];

#endif /* _SQUID_ERR_TYPE_H */

