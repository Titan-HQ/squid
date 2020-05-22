/*
 * $Id$
 *
 */
#ifndef B64_H_
#define B64_H_
#include "global.h"

TXATR uint64_t ttn_base64_encode(const char * const , size_t, char * , size_t);
TXATR uint64_t ttn_base64_decode(const char * const ,const size_t, char * const , size_t);
TXATR bool tx_base64_valid(const char * const, const size_t);

#endif /* B64_H_ */
