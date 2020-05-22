/**
 * $Id$
 */

#ifndef TTN_TOOLS_C_HXX
#define TTN_TOOLS_C_HXX

//UNFORTUANTELY 
//#pragma once
//TRIGGERS AN ERROR WITH THE ANALYZER FROM CLANG 3.4 

#include "global.h"

#ifdef __cplusplus
extern "C" {
#endif

TX_INLINE_LIB 
bool FIND_SYMBOL_(  const char * const symbols,
                    const size_t sym_sz,
                    const char symbol           )
{
    size_t idx=0;

    while(  idx < sym_sz                && 
            symbols[ idx ] != symbol    && 
            ++idx                           )
        ; /* empty body */

    return ( idx < sym_sz );
}

/**
 * @name       ttn_strncspn
 * @abstract   safer version of the strcspn
 * @param in   input string 
 * @param isz  input string size
 * @param s    charset/symbols
 * @param ssz  symbols size
 * @return     position or -1 on errors
 */
TX_INLINE_LIB ssize_t ttn_strncspn( const char * const in, 
                                    const size_t isz,
                                    const char * const s,
                                    const size_t ssz        )
{
    if ( in && *in && isz && s && ssz ) {

        size_t i_ = 0;

        while ( isz > i_                        && 
                in[i_]                          && 
                !FIND_SYMBOL_( s, ssz, in[i_] ) && 
                ++i_                                )
            ; /* empty body */

        return TTN_UNI_CAST( ssize_t, i_ );
    }

    return INVALID_;
}

/**
 * @name       ttn_strnspn
 * @abstract   safer version of the strspn
 * @param in   input string
 * @param isz  input string size
 * @param s    charset/symbols
 * @param ssz  symbols size
 * @return     position or -1 on errors
 * @TODO       not fully tested!
 */
TX_INLINE_LIB size_t ttn_strnspn(   const char * const in,
                                    const size_t isz,
                                    const char * const s,
                                    const size_t ssz        )
{
    size_t i_=0;

    while ( isz > i_                        && 
            in[i_]                          && 
            FIND_SYMBOL_( s, ssz, in[i_] )  && 
            ++i_                                )
        ; /* empty body */

    return i_;
}

#ifdef __cplusplus
}
#endif

#endif /* TTN_TOOLS_C_HXX */

/* vim: set ts=4 sw=4 et : */
