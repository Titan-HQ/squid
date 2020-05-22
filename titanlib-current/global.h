/*
 * $Id$
 *
 * Copyright (c) 2005-2014, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 *
 * The software contained herein is proprietary to and embodies the
 * confidential technology of Copperfasten Technologies, Teoranta.
 * Possession, use, duplication or dissemination of the software and
 * media is authorized only pursuant to a valid written license from
 * Copperfasten Technologies, Teoranta.
 *
 */

#ifndef TITAN_GLOBAL_H
#define TITAN_GLOBAL_H

#include <stddef.h>
#include <stdbool.h>
#include <pthread_np.h>
#include "mytypes.h"
#include "blockreasons.h"

#include <netinet/in.h>

// From Bloxx.
#ifndef MAX_HOSTNAME
   #define MAX_HOSTNAME 63
#endif

#ifndef MAX_DOMAINNAME
   #define MAX_DOMAINNAME 255
#endif

#ifndef MAX_PATH
   #define MAX_PATH 16
#endif

#ifndef ACCESS_DENIED_PAGE
   #define ACCESS_DENIED_PAGE "/blocker/proxy/share/errors/English/ERR_ACCESS_DENIED"
#endif

#ifndef DEFAULT_BACKOFF
   #define DEFAULT_BACKOFF 5
#endif

#ifndef SQUID_MAX_URL
   #define SQUID_MAX_URL 0x2000
#endif

#ifndef MAX_VIRUS_NAME
   #define MAX_VIRUS_NAME 128
#endif

#ifndef SQUID_HOSTNAME_LEN
   #define SQUID_HOSTNAME_LEN 256
#endif

// Category.
#ifndef MAX_CATEGORY_NAME_LEN
   #define MAX_CATEGORY_NAME_LEN  63
#endif

#ifndef MAX_CATEGORIES
   #define MAX_CATEGORIES 64 // Max categories we can support
#endif

#ifndef MAX_CATEGORYID
   #define MAX_CATEGORYID 163
#endif

#ifndef DEFINED_TITAX_CATEGORIES
   #define DEFINED_TITAX_CATEGORIES 64
#endif


// Misc.
#ifndef MAX_UNIQ_IP_TTL4LIC
   #define MAX_UNIQ_IP_TTL4LIC 300
#endif

//1 mil (1 meg)
#ifndef MAX_UNIQ_IP_LIST_LEN
   #define MAX_UNIQ_IP_LIST_LEN 1048576
#endif

#ifndef MIN_IP_SESSION_TTL
   #define MIN_IP_SESSION_TTL 60
#endif

#ifndef MAX_URL // make sure it is eq. to whatever is defined in the squid
   #define MAX_URL   32768
#endif

#ifndef CLEAN_URI_SZ 
   #define CLEAN_URI_SZ MAX_URL+8+2
#endif

#ifndef MAX_TITAX_USER_NAME
   #define MAX_TITAX_USER_NAME      255
#endif

#ifndef MAX_TITAX_USER_FULLNAME
   #define MAX_TITAX_USER_FULLNAME  255
#endif

#ifndef MAX_TITAX_GROUP_POLICY
   #define MAX_TITAX_GROUP_POLICY   128
#endif

#ifndef MAX_TITAX_USER_LIC_MAX
   #define MAX_TITAX_USER_LIC_MAX   63
#endif

#ifndef MAX_CK_HASH_SZ
   #define MAX_CK_HASH_SZ           32
#endif

#ifndef MAX_CK_STR_SZ
   #define MAX_CK_STR_SZ            254
#endif

#ifndef DEFAULT_GROUP_NUM
    /* Define the permanent group numbers */
    #define DEFAULT_GROUP_NUM       1 
#endif

#ifdef TTN_ATESTS

#ifndef FIRST_NON_BUILDIN_GROUP_ID
   #define FIRST_NON_BUILDIN_GROUP_ID   3
#endif

#endif

#ifndef URLSVR_SOCK_PATH
   #define URLSVR_SOCK_PATH   "/var/run/urlsvr/urlsvr.sock"
#endif

#ifndef URL_MSG_NOTFOUND
   #define URL_MSG_NOTFOUND               "/A NOTFOUND"
#endif

#ifndef URL_MSG_NOTFOUND_SZ
   #define URL_MSG_NOTFOUND_SZ            (sizeof(URL_MSG_NOTFOUND)-1)
#endif

#ifndef URL_MSG_DBERR
   #define URL_MSG_DBERR                  "/A DBERR"
#endif

#ifndef URL_MSG_DBERR_SZ
   #define URL_MSG_DBERR_SZ               (sizeof(URL_MSG_DBERR)-1)
#endif

#ifndef CONF_DIR
   #define CONF_DIR "/blocker/conf/"
#endif

#ifndef LOG_DIR
   #define LOG_DIR "/blocker/logs/"
#endif

#ifndef PQ_CONFDB_CINFO
   #define PQ_CONFDB_CINFO "host=127.0.0.1 user=titax dbname=titax"
#endif

#ifndef PQ_CONFDB_CTRAFFIC
   #define PQ_CONFDB_CTRAFFIC "host=127.0.0.1 user=titax dbname=traffic"
#endif

/*
 * A page from Google's cache looks like this:
 * http://66.102.9.104/search?q=cache:5RpqEEzv3BwJ:www.packetdynamics.com
 * We need to identify the signature string from this, as well as the
 * offset beyond the start of the signature string at which the actual
 * domain name starts.
 */
#ifndef GOOGLE_SIGNATURE
   #define GOOGLE_SIGNATURE "/search?q=cache:"
#endif

#ifndef GOOGLE_SIGNATURE_SZ
   #define GOOGLE_SIGNATURE_SZ   (sizeof(GOOGLE_SIGNATURE)-1)
#endif

#ifndef GOOGLE_URL_OFFSET
   #define GOOGLE_URL_OFFSET 29
#endif

#ifndef TITAX_APP_MIME
   #define TITAX_APP_MIME                          "application/titax"
#endif

#ifndef TITAX_APP_DEF_CLI_NAME
   #define TITAX_APP_DEF_CLI_NAME                  "dns"
#endif

#ifndef TITAX_APP_DEF_CLI_NAME_SZ
   #define TITAX_APP_DEF_CLI_NAME_SZ               (sizeof(TITAX_APP_DEF_CLI_NAME)-1)
#endif

#ifndef TITAX_APP_HDR_FRM
   #define TITAX_APP_HDR_FRM                       "X-Titax-Cmd:%d; v=\"%s\"\r\n"
#endif

#ifndef TITAX_APP_HDR_SPLIT
   #define TITAX_APP_HDR_SPLIT                     "; v=\""
#endif

#ifndef TITAX_APP_HDR_SPLIT_SZ
   #define TITAX_APP_HDR_SPLIT_SZ                  (sizeof(TITAX_APP_HDR_SPLIT) - 1)
#endif

/*
 * see https://www.ietf.org/rfc/rfc1035.txt
 */
#ifndef RFC1035_MAX
   #define RFC1035_MAX           0xff
#endif

#ifndef RFC1035_LABEL_LIMIT
   #define RFC1035_LABEL_LIMIT   0x3f
#endif

#ifndef RFC1035_MAX_LABELS_LIMIT

   #define RFC1035_MAX_LABELS_LIMIT   ( RFC1035_MAX >> 1 )
#endif

#ifndef MIN_DNS_DOMAIN_SZ
   #define MIN_DNS_DOMAIN_SZ     0x01
#endif

#ifndef DNSMD_FLAGS
   #define DNSMD_FLAGS
   /*
    * DNS MetaData Flags
    * see wtc-dns-spec-ref.txt
    */
   #ifndef DNSMD_MASK_ENCODED
      #define DNSMD_MASK_ENCODED                   (1 << 0)
   #endif

   #ifndef DNSMD_MASK_USER
      #define DNSMD_MASK_USER                      (1 << 1)
   #endif

   #ifndef DNSMD_MASK_LOCATION
      #define DNSMD_MASK_LOCATION                  (1 << 2)
   #endif

   #ifndef DNSMD_MASK_IP
      #define DNSMD_MASK_IP                        (1 << 3)
   #endif

   #ifndef DNSMD_MASK_CRC
      #define DNSMD_MASK_CRC                       (1 << 4)
   #endif

   #ifndef DNSMD_MASK_DPIP
      #define DNSMD_MASK_DPIP                      (1 << 5)
   #endif

   #ifndef DNSMD_MASK_OFFSET
      #define DNSMD_MASK_OFFSET                    RFC1035_LABEL_LIMIT
   #endif

    #ifndef DNSMD_MASK_ALTVAL
      #define DNSMD_MASK_ALTVAL                    (1 << 0)
   #endif

   #ifndef DNSMD_MIN_RAW_SZ
      #define DNSMD_MIN_RAW_SZ                     0x0F
   #endif

   #ifndef DNSMD_RFB_ENC_USERID
      #define DNSMD_RFB_ENC_USERID                 (DNSMD_MASK_ENCODED|DNSMD_MASK_USER)+DNSMD_MASK_OFFSET
   #endif

   #ifndef DNSMD_RFB_ENC_LOCATIONID
      #define DNSMD_RFB_ENC_LOCATIONID             (DNSMD_MASK_ENCODED|DNSMD_MASK_LOCATION)+DNSMD_MASK_OFFSET
   #endif

   #ifndef DNSMD_RFB_ENC_IP
      #define DNSMD_RFB_ENC_IP                     (DNSMD_MASK_ENCODED|DNSMD_MASK_IP)+DNSMD_MASK_OFFSET
   #endif

   #ifndef DNSMD_RFB_ENC_CRC
      #define DNSMD_RFB_ENC_CRC                    (DNSMD_MASK_ENCODED|DNSMD_MASK_CRC)+DNSMD_MASK_OFFSET
   #endif

   #ifndef DNSMD_RFB_ENC_DPIP
      #define DNSMD_RFB_ENC_DPIP                   (DNSMD_MASK_ENCODED|DNSMD_MASK_DPIP)+DNSMD_MASK_OFFSET
   #endif

   #ifndef DNSMD_RFB_ENC_USERID_ALTVAL
      #define DNSMD_RFB_ENC_USERID_ALTVAL          DNSMD_RFB_ENC_USERID+DNSMD_MASK_ALTVAL
   #endif

   #ifndef DNSMD_RFB_ENC_IP_ALTVAL
      #define DNSMD_RFB_ENC_IP_ALTVAL              DNSMD_RFB_ENC_IP+DNSMD_MASK_ALTVAL
   #endif

   #ifndef  DNSMD_MAX_SZ
      #define DNSMD_MAX_SZ                         RFC1035_MAX
   #endif
#endif


#ifndef FQDN_MAX
   #define FQDN_MAX  256*256  
#endif

#ifndef TITAX_ANON_DEFAULT_USER_NAME
   #define TITAX_ANON_DEFAULT_USER_NAME   "anon-webtitan"
#endif

#ifndef TITAX_ANON_DEFAULT_USER_NAME_SZ
   #define TITAX_ANON_DEFAULT_USER_NAME_SZ   (sizeof(TITAX_ANON_DEFAULT_USER_NAME)-1)
#endif

#ifndef ITOA_EX
   #ifdef __cplusplus
      //DV:finish replace it with proper lib
      #define ITOA_EX(a_b_,a_b_sz_,a_v_)  tx_safe_snprintf((char*)a_b_,a_b_sz_,"%d",a_v_)
   #else
      #define ITOA_EX(a_b_,a_b_sz_,a_v_)  tx_safe_snprintf((char*)a_b_,a_b_sz_,"%d",a_v_);
   #endif
#endif

#ifndef UTOA_EX
   #ifdef __cplusplus
      //DV:finish replace it with proper lib
      #define UTOA_EX(a_b_,a_b_sz_,a_v_)  tx_safe_snprintf((char*)a_b_,a_b_sz_,"%u",a_v_)
   #else
      #define UTOA_EX(a_b_,a_b_sz_,a_v_)  tx_safe_snprintf((char*)a_b_,a_b_sz_,"%u",a_v_)
   #endif
#endif

#ifndef LTOA_EX
   #ifdef __cplusplus
      //DV:finish replace it with proper lib
      #define LTOA_EX(a_b_,a_b_sz_,a_v_)  tx_safe_snprintf((char*)a_b_,a_b_sz_,"%ld",a_v_)
   #else
      #define LTOA_EX(a_b_,a_b_sz_,a_v_)  tx_safe_snprintf((char*)a_b_,a_b_sz_,"%ld",a_v_)
   #endif
#endif


#ifndef LUTOA_EX
   #ifdef __cplusplus
      //DV:finish replace it with proper lib
      #define LUTOA_EX(a_b_,a_b_sz_,a_v_)    tx_safe_snprintf((char*)a_b_,a_b_sz_,"%lu",a_v_)
   #else
      #define LUTOA_EX(a_b_,a_b_sz_,a_v_)    tx_safe_snprintf((char*)a_b_,a_b_sz_,"%lu",a_v_)
   #endif
#endif
#ifndef LLTOA_EX
   #ifdef __cplusplus
      //DV:finish replace it with proper lib
      #define LLTOA_EX(a_b_,a_b_sz_,a_v_)    tx_safe_snprintf((char*)a_b_,a_b_sz_,"%lld",a_v_)
   #else
      #define LLTOA_EX(a_b_,a_b_sz_,a_v_)    tx_safe_snprintf((char*)a_b_,a_b_sz_,"%lld",a_v_)
   #endif
#endif

#ifndef LLUTOA_EX
   #ifdef __cplusplus
      //DV:finish replace it with proper lib
      #define LLUTOA_EX(a_b_,a_b_sz_,a_v_)   tx_safe_snprintf((char*)a_b_,a_b_sz_,"%llu",a_v_)
   #else
      #define LLUTOA_EX(a_b_,a_b_sz_,a_v_)   tx_safe_snprintf((char*)a_b_,a_b_sz_,"%llu",a_v_)
   #endif
#endif

#ifndef U64TOA_EX
   #ifdef __cplusplus
      //DV:finish replace it with proper lib
      #define U64TOA_EX(a_b_,a_b_sz_,a_v_)   tx_safe_snprintf((char*)a_b_,a_b_sz_,"%" PRIu64,a_v_)
   #else
      #define U64TOA_EX(a_b_,a_b_sz_,a_v_)   tx_safe_snprintf((char*)a_b_,a_b_sz_,"%" PRIu64,a_v_)
   #endif
#endif
#ifndef TXATR
   #ifdef __cplusplus
      #define TXATR extern "C"
   #else
      #define TXATR extern
   #endif
#endif

#ifndef TX_INTERNAL_INLINE
   #ifdef __clang__
      #ifndef WT_NOINLINE
         #define TX_INTERNAL_INLINE static  __attribute__((always_inline)) inline
      #else
         #define TX_INTERNAL_INLINE static
      #endif
   #endif
#endif

#ifndef TX_INLINE_LIB
   #ifdef __clang__
      #ifndef WT_NOINLINE
         #define TX_INLINE_LIB extern __attribute__ ((always_inline,gnu_inline)) inline
      #else
         #define TX_INLINE_LIB extern inline
      #endif
   #endif
#endif

#ifndef TX_CPP_INLINE_LIB
    #ifdef __cplusplus
         #define TX_CPP_INLINE_LIB extern __attribute__ ((always_inline)) inline
    #else
         #define TX_CPP_INLINE_LIB
    #endif
#endif

#ifndef STRINGIFY_
   #define STRINGIFY_(a_arg_) #a_arg_
#endif


#ifndef STR
   #define STR(a_val_)  STRINGIFY_(a_val_)
#endif


#ifndef CLU_
   #if __clang_major__==3 && __clang_minor__==7
      #define CLU_ _Pragma("unroll")
   #else
      #define CLU_
   #endif
#endif

#ifndef CLUN_
   #if __clang_major__==3 && __clang_minor__==7
      #define CLUN_(a_arg_) _Pragma(STRINGIFY_(unroll(a_arg_)))
   #else
      #define CLUN_(a_arg_)
   #endif  
#endif


#ifdef __cplusplus
   #if (__clang_major__ >= 3 && __clang_minor__ >= 7)
      /**
       * @macro: CTOR_ (constructor modernizer)
       * @abstract: new(er) clang & modern c++11 ctor that supports the initialization list.
       * This is the preferred way to construct new objects (even the temporary ones),
       * one of the benefits is e.g. it will automatically call all the necessary/implicit type casts
       */
      #define CTOR_(a_type,a_name,...) a_type a_name{__VA_ARGS__}
      /**
       * @macro: CTOR_ (casting constructor modernizer)
       * @abstract: new(er) clang & modern c++11 ctor that supports the initialization list.
       * This is the preferred way to construct new objects (even the temporary ones),
       * one of the benefits is e.g. it will automatically call all the necessary/implicit type casts
       */
      #define CCTOR_(a_type,...) CTOR_(a_type,,__VA_ARGS__)
   #else
      /**
       * @macro:  CTOR_ (constructor modernizer)
       * @abstract: older clang & classic c++ ctor, use newer clang (3.7+) to benefit from newer features
       */
      #define CTOR_(a_type,a_name,...) a_type a_name(__VA_ARGS__)
      /**
       * @macro:  CCTOR_   (casting constructor modernizer)
       * @abstract: older clang & classic c++ ctor, use newer clang (3.7+) to benefit from newer features
       */
      #define CCTOR_(a_type,...) CTOR_(a_type,,__VA_ARGS__)
   #endif
#else 
   /**
    * @macro:  CTOR_ (constructor modernizer)
    * @abstract: this is a dummy macro (exposed to C)
    */   
   #define CTOR_(a_type,a_name,...)
   #define CCTOR_(a_type,...)
#endif

#ifndef MD5BASE64_VAL_SIZE
   #define MD5BASE64_VAL_SIZE    32
//MD5BASE64_VAL_SIZE+padding (8 byte)
#endif
   
#ifndef MD5BASE64_MAX_SIZE
   #define MD5BASE64_MAX_SIZE    MD5BASE64_VAL_SIZE+8
#endif
   
#ifndef MD5RAW_SIZE
   #define MD5RAW_SIZE           16
#endif   
   
#ifndef MD5CONST1
   #define MD5CONST1 64
#endif   
/////////////

#ifndef BW_SWITCH_EX_
   #ifdef __cplusplus
      #define BW_SWITCH_EX_(a_type_,a_max_,a_value_, a_s_table_){\
         size_t v_bwhv_=1; while (v_bwhv_<=a_max_){ if (a_value_&v_bwhv_) switch (static_cast<a_type_>(v_bwhv_)){a_s_table_}; v_bwhv_<<=1;};\
      }
   #else
      #define BW_SWITCH_EX_(a_type_,a_max_,a_value_, a_s_table_){\
         size_t v_bwhv_=1; while (v_bwhv_<=a_max_){ if (a_value_&v_bwhv_) switch ((a_type_)v_bwhv_){a_s_table_}; v_bwhv_<<=1;};\
      }
   #endif
#endif

#ifndef SFCALL_
   #define SFCALL_(a_call_)  __extension__ ({a_call_;1;})
#endif
   
#ifndef IS_LOWER_C
   #define IS_LOWER_C(c) (c>='a' && c<='z')
#endif   

#ifndef IS_UPPER_C  
   #define IS_UPPER_C(c) (c>='A' && c<='Z')
#endif
   
#ifndef IS_ALPHA_C
   #define IS_ALPHA_C(c) ( IS_LOWER_C(c) || IS_UPPER_C(c))
#endif   

#ifndef IS_NUM 
   #define IS_NUM(c) (c>='0' && c<='9')
#endif
   
#ifndef TO_LOWER_C
   #define TO_LOWER_C(c) (char)( IS_UPPER_C(c)?(c | 0x20):c )
#endif   

#ifndef TO_UPPER_C
   #define TO_UPPER_C(c) (char)( IS_LOWER_C(c)?(c ^ 0x20):c )
#endif

#ifndef STRLCPY_SIZE_
   #define STRLCPY_SIZE_(a_len_,a_max_)   ((a_len_+1)<a_max_?(a_len_+1):a_max_)
#endif

#ifndef TEST_STRTOX_
   #define TEST_STRTOX_(a_text_ptr_,a_result_,a_exp_,a_min_,a_max_)\
      ( ( ( !(errno=0) &&  ( a_text_ptr_ && ( ( ( (a_result_=a_exp_) && ( (a_result_<a_min_ || a_result_>a_max_) && (errno=ERANGE) && (a_result_=UINT_MAX) ) ) || true ) || true ) ) ) || (errno=EINVAL) ) )
#endif

#ifndef TEST_STRTOX_UI_
   #define TEST_STRTOX_UI_(a_text_ptr_,a_result_,a_exp_,a_max_)\
      ((  ( !(errno=0) &&  (a_text_ptr_ && ( ( ( (a_result_=a_exp_) && (a_result_>a_max_ && (errno=ERANGE) && (a_result_=UINT_MAX) ) ) || true) || true)) ) || (errno=EINVAL)))

#endif

#ifndef WHITESPACE_SYMBOLS
   #define WHITESPACE_SYMBOLS "\x09\x0A\x0B\x0C\x0D\x20"
#endif

/**
 * see 
 * https://www.freebsd.org/doc/en/books/porters-handbook/versions.html
 */

/* first 10.0 */
#ifndef MIN_OS_FB_10
   #define MIN_OS_FB_10     1000000
#endif

/* first 10.3 */
#ifndef MIN_OS_FB_10_3
   #define MIN_OS_FB_10_3   1003000
#endif

/* first 10.4 */
#ifndef MIN_OS_FB_10_4
   #define MIN_OS_FB_10_4   1004000
#endif

/* first 11.0 */
#ifndef MIN_OS_FB_11
   #define MIN_OS_FB_11     1100000
#endif

/* first 11.1 */
#ifndef MIN_OS_FB_11_1
   #define MIN_OS_FB_11_1   1101000
#endif

/* first 12.0 */
#ifndef MIN_OS_FB_12
   #define MIN_OS_FB_12     1200000
#endif
/////////////////////////////////////////////////////////////////

TXATR void ttn_set_shutdown_now(void);
TXATR bool ttn_get_shutdown_now(void);
TXATR bool ttn_get_txdebug_state(void);
TXATR void ttn_set_txdebug_state(bool);
TXATR bool ttn_get_verbose_state(void);
TXATR void ttn_set_verbose_state(bool);

TXATR 
__attribute__((__format__ (__printf__, 1, 2)))
ssize_t ttn_out_raw(const char * const, ...);

#ifndef TXDEBUG
   #define TXDEBUG(format, ... ) if (ttn_get_txdebug_state()) printf(format, ##__VA_ARGS__)
#endif

#ifndef TXDEBLOG
   #define TXDEBLOG(EXP) if (ttn_get_txdebug_state()) EXP
#endif

#ifndef OVERLAP
   #define OVERLAP(a_dest_ptr_, a_src_ptr_,a_len_) ((((uintptr_t)a_src_ptr_)+a_len_) >=((uintptr_t)a_dest_ptr_) && (((uintptr_t)a_src_ptr_))<=(((uintptr_t)a_dest_ptr_)+a_len_))
#endif

#ifndef DEF_MAXUDP
   #define DEF_MAXUDP 200
#endif

#ifndef DEF_MAXTCP
   #define DEF_MAXTCP 20
#endif

#ifndef DEF_DNSTTL
   #define DEF_DNSTTL 10
#endif

#ifndef GUID_STR_SZ
   /* Hyphenated GUID */
   #define GUID_STR_SZ   36
#endif

#ifndef URLDB_TMP_R_BUF_MAX
   #define URLDB_TMP_R_BUF_MAX      RFC1035_MAX
#endif

#ifndef INVALID_
   #define INVALID_   EOF
#endif

#ifndef UNKNOWN_
      #define UNKNOWN_ "<unknown>"
#endif

#ifndef DEF_LOGGER_UDS_PATH
   #define DEF_LOGGER_UDS_PATH      "/var/run/logger/logger.sock"
#endif

#ifndef DEF_LOGGER_TYPE
   #define DEF_LOGGER_TYPE          ot_uds
#endif

#ifndef LOGGER_PATH_MAX_SZ
/**
 * based on max size of sun_path
 * https://www.freebsd.org/cgi/man.cgi?query=unix&apropos=0&sektion=0&manpath=FreeBSD+10.1-RELEASE&arch=default&format=html
 */ 
   #define LOGGER_PATH_MAX_SZ       103
#endif

#ifndef LOGGER_REASON_ALLOWED
   #define LOGGER_REASON_ALLOWED    2
#endif

#ifndef UNLIMITED_UNIQ_IP
   #define UNLIMITED_UNIQ_IP  0
#endif

/* wrapper macros because on FB older than 10.3 __bitcount64/32 maybe missing */

#ifndef __bitcount64
   #ifdef __cplusplus
      #define  ttn_bitcount64(x) __builtin_popcountll(static_cast<__uint64_t>((x)))
   #else 
      #define  ttn_bitcount64(x) __builtin_popcountll((__uint64_t)(x))
   #endif
#else
   #define     ttn_bitcount64(x) __bitcount64(x)
#endif

#ifndef __bitcount32
   #ifdef __cplusplus
      #define  ttn_bitcount32(x) __builtin_popcount(static_cast< __uint32_t>((x)))
   #else 
      #define  ttn_bitcount32(x) __builtin_popcount((__uint32_t)(x)))
   #endif
#else
   #define     ttn_bitcount32(x) __bitcount32(x)
#endif

#ifndef TTN_UNI_CAST 
   #ifdef __cplusplus
      #define TTN_UNI_CAST(TYPE,VAR) static_cast<TYPE>(VAR)
   #else 
      #define TTN_UNI_CAST(TYPE,VAR) (TYPE)(VAR)
   #endif
#endif

#ifndef BP_PATH_SZ
   #define BP_PATH_SZ   63
#endif


#ifndef tx_static_assert_type
   #ifndef __cplusplus

      #define tx_static_assert_type( LTYPE, RTYPE, EMSG ) \
         _Static_assert( _Generic( ( LTYPE ), __typeof(RTYPE): true, default: false), EMSG )
   #else 

      #define tx_static_assert_type( LTYPE, RTYPE, EMSG ) \
         static_assert( titan_v3::tools::traits::is_same_base_type< LTYPE, RTYPE >::value, EMSG );
   #endif
#endif

#ifndef tx_static_assert_true
   #ifndef __cplusplus
      #define tx_static_assert_true( STATE, EMSG ) \
         _Static_assert( (STATE) , EMSG )
   #else 

      #define tx_static_assert_true( STATE, EMSG ) \
         static_assert( (STATE), EMSG );
   #endif
#endif

#if ( !defined(__GNUC__) && !defined(__GNUG__) ) 

tx_static_assert_true(  __FreeBSD_version >= MIN_OS_FB_11 || __clang_major__ <= 6,
                        "Unable to compile using the LLVM 7 or 8 on the FreeBSD 10 : std lib error" );

#endif

#ifndef tx_gettid
   #define tx_gettid() pthread_getthreadid_np() 
#endif

#ifdef __cplusplus
extern "C" {
#endif


/* basic aliases */
typedef int             unassigned_t; 
typedef unassigned_t    policy_id_t; 
typedef policy_id_t     group_id_t; 
typedef size_t          user_id_t;

   
/**
 * @abstract C compatiblity for raw ip addres
 * @NOTE it implies the host byte order 
 */
typedef uint128_t ipv6_t;
typedef uint32_t  ipv4_t;
typedef uint8_t   prefix_t;
typedef struct{
   union{
     ipv6_t   v6;
     ipv4_t   v4;
   };
}c_raw_ipaddr_t;


/**
 * @abstract C compatiblity for cidr 
 */
typedef struct  {
    /* data MUST be in host byte order */
   c_raw_ipaddr_t    addr;
   prefix_t          prefix;
} c_cidr_t;

#ifndef IPV6_RAW_SZ
   #define IPV6_RAW_SZ        sizeof(ipv6_t)
#endif

#ifndef IPV6_RAW_HEX_SZ
   #define IPV6_RAW_HEX_SZ    (IPV6_RAW_SZ<<1)
#endif

#ifndef IPV4_RAW_SZ
   #define IPV4_RAW_SZ        sizeof(ipv4_t)
#endif

#ifndef IPV4_RAW_HEX_SZ
   #define IPV4_RAW_HEX_SZ    (IPV4_RAW_SZ<<1)
#endif

typedef struct{
   char             path[BP_PATH_SZ+1];
   c_raw_ipaddr_t   ip;
   size_t           path_sz;
   size_t           port;
}bp_backed_http_t;

typedef enum{
   tq_uns=0x00,   //00
   tq_tru=0x01,   //01
   tq_fal=0x02,   //10
   tq_sup=0x03,   //11
}t_qbit;

typedef enum{
   tpi_path,
   tpi_args,
}t_tx_proc_inf;

typedef enum {
   ot_none=             0x00,
   ot_cout=             0x02,
   ot_file=             0x04,
   ot_tcp=              0x08,
   ot_uds=              0x10,
   ot_max=              ot_uds
}t_txpe_output_type;

typedef struct{
   size_t               flagsD;
   size_t               policyAssociationCount;
   size_t               policyPermissionSize;
   t_category           categoryD;
   t_category           categoryE;  
   u_char *             policyPermission;
} AccessControl;


typedef enum {
   TXST_CLIENT=         0x00,
   TXST_SERVER=         0x01,
}TXSTS;

typedef struct{
   char                 ip[INET_ADDRSTRLEN];    /* ipv4 address (loaclhost)      */
   struct timeval       connect_timeout;        /* timeout                       */
   struct linger        op_so_linger;           /* linger                        */
   size_t               backlog_sz;             /* backlog size                  */
   TXSTS                type;                   /* type of a socket              */
   uint16_t             port;                   /* port number                   */
   bool                 op_so_stream;           /* use op_so_stream              */
   bool                 op_so_reuse_addr;       /* use op_so_reuse_addr          */
   bool                 op_so_keep_alive;       /* use op_so_keep_alive          */
   bool                 op_so_nosigpipe;        /* use op_so_nosigpipe           */
   bool                 op_tcp_no_delay;        /* use op_tcp_no_delay           */
   bool                 op_io_no_block;         /* use op_io_no_block            */
   bool                 op_connect_no_block;    /* use non blocking connection   */
}t_txip_socket_ex;

/**
 * @name urldb_call_t
 */
typedef struct{
   struct {
      AccessControl *            ac;      /* ptr to the AccessControl                     */
      char *                     buf;     /* ptr to the out buffer                        */
      const size_t               bsz;     /* size of the buffer it self                   */
   }out;                                  /* output                                       */
   struct {
      char *                     buf;     /* ptr to the string e.g. domain name/fqdn etc  */
      size_t                     bsz;     /* size of the input string                     */
   }in;                                   /* input                                        */
   struct {
      t_txip_socket_ex*          conn;    /* connection cfg                               */
      int *                      fd;      /* socket                                       */
   }urlsvr;                               /* urlsvr connection                            */
   const size_t                  max_try; /* max try                                      */
   bool                          debug;   /* debug                                        */
}urldb_call_t;


typedef struct{
   size_t    data_sz;
   size_t    db_sz;
   char *    db;
}t_data_buff; 

typedef struct{
   const char *   ptr_;
   size_t         sz_;
}t_strptr;

typedef struct{
   char                 path[LOGGER_PATH_MAX_SZ+1]; 
   char                 ip[INET_ADDRSTRLEN];
   size_t               path_sz;
   t_txpe_output_type   type;
   uint16_t             port;
}t_txpe_logging_cfg;

/**
 * @abstract tx hash type 
 */
typedef enum {
   txhh_none   = 0x00,  //00
   txhh_orchid = 0x02,  //02
   txhh_sdbm   = 0x04,  //04
   txhh_djb2   = 0x08,  //08
   txhh_fnv    = 0x10,  //16
   txhh_oat    = 0x20,  //32
   txhh_murmur = 0x40,  //64
} t_txhh;

/*
 * This enum not only defines handled types of labels 
 * but also defines the order of labels in the payload generated
 * by the ttn_dns_md_make (from the lowest to the highest)
 * See the wtc-dns-spec-ref.txt for examples of the payload (metadata)
 */
typedef enum{
   /**
    * @abstract no labels
    */
   mt_none=0x00,
   /**
    * @abstract dnsproxy ip  label
    * @note as of 20170421 is not implemented yet
    */
   mt_dpip=(1<<1),
   /**
    * @abstract ip address label
    */
   mt_ip=(1<<2),
   /**
    * @abstract location id label
    */
   mt_lid=(1<<3),
   /**
    * @abstract user id label
    */
   mt_uid=(1<<4),
   /**
    * @abstract crc label (optional)
    * @note as of 20161019 we haven't decided yet what type of crc/hash we want to use/send
    * it should allow to safely and efficiently confirm that given metadata was generated by our code/lib
    * (not too easy to spoof)
    */
   mt_crc=(1<<5),
   /**
    * @abstract compound flag COMPATIBLE with old dns proxy
    */
   mt_mini_dnsp=(mt_ip|mt_crc),
   /**
    * @abstract compound flag NOT compatible with old dns proxy
    * @note potentially the dnsp can be removed in favor of the otg
    */
   mt_dnsp=(mt_ip|mt_uid),
   /**
    * @abstract compound flag COMPATIBLE with old dns proxy
    */
   mt_old_dnsp=(mt_ip|mt_uid|mt_crc),
   /**
    * @abstract compound flag for otg include the location label
    * @note [20161019]:for now removed the mt_crc
    */
   mt_otg=(mt_ip|mt_lid|mt_uid), 
   /**
    * internal: don't remove it 
    */
   mt_max_=(mt_none|mt_ip|mt_lid|mt_uid|mt_crc), 
}t_meta_types;

typedef struct{
   /**
    * @abstract output buffer  
    */
   char *         output;
   /**
    * @abstract crc input args
    */
   void *         crc_input;
   /**
    * @abstract output buffer size: it has to have enough space to include the terminating null byte
    * @note min accepted size is 15
    */
   size_t         osz;
   /**
    * @abstract size of produced metdadata 
    */
   size_t         size;
   /**
    * @abstract list of labels to include see t_meta_types 
    */
   t_meta_types   labels;
   /**
    * @abstract type of crc label if used
    */
   t_txhh         crc_type;
   /** 
    * @abstract data: ip address 
    */
   c_raw_ipaddr_t       ip;
   /** 
    * @abstract data: user id 
    */
   uint32_t       uid;
   /**
    * @abstract data: location id 
    */
   uint32_t       lid;
   
   
}t_metadata_handler;

typedef struct{
   char                       otp_tag[RFC1035_MAX + 1];
   char                       crc[0xff];
   c_raw_ipaddr_t             iip;
   union {
      char *                  c;
      const char *            cc;
      const u_char *          cuc;
   }                          raw_ptr;
   size_t                     raw_size;
   size_t                     otp_tag_len;
   uint32_t                   iuid;
   uint32_t                   ilid;
   bool                       iuid_valid;
   bool                       ilid_valid;
   bool                       iip_valid;
}t_meta_data;


typedef struct {
   char             fqdn[RFC1035_MAX + 1];        /* Decoded DNS name. */
   char             new_domain[RFC1035_MAX + 1];
   t_meta_data      meta;
   c_raw_ipaddr_t   return_ip;                    /* ipv6 */
   const c_raw_ipaddr_t * client_ip;              /* ipv6 */
   char *           q;                            /* Encoded DNS name. */
   size_t           fqdn_len;                     /* Decoded DNS name's length. */
   uint32_t	        scope_id;                     /* ipv6 */
   char             qtype[2];
   char             qclass[2];
   char             qid[2];
   uint16_t         i_type;
   uint16_t         i_class;
   uint16_t         cport;
   uint16_t         i_id;
   bool             meta_present:1;
   bool             do_not_log:1;
   bool             waiting_for_user:1;
   bool             nxdomain:1;                     /* respond as nx domain */
} t_udp_args;


#define TXAPP_LOGGING_OFF 0x01
typedef enum{
   txapp_cmd_none=0x00,
   txapp_cmd_trun_logging_off=TXAPP_LOGGING_OFF,
   txapp_cmd_check_dm=0x02,
   txapp_cmd_get_licinf=0x04,
   txapp_cmd_update_btoken=0x08,
   txapp_cmd_update_location_info=0x10,
   txapp_cmd_update_from_wada=0x20,
   txapp_cmd_check_dm_from_dp=0x40,
   txapp_cmd_forward_auth_portal=0x80,
   txapp_cmd_emu_resp_with_std_http=0x400,
}t_txapp_cmds;

typedef void vPGconn; //alias for PGconn

typedef enum{
   urldb_rc_er_dec=-0x07,  // decode
   urldb_rc_er_cal=-0x06,  // call
   urldb_rc_er_unc=-0x05,  // unknown category
   urldb_rc_er_udb=-0x04,  // urldb
   urldb_rc_er_rcv=-0x03,  // recive
   urldb_rc_er_snd=-0x02,  // send
   urldb_rc_er_opn=-0x01,  // open
   urldb_rc_ok=0x00,       // ok
}t_urldb_rc;

typedef uint64_t  t_hash;
typedef uint128_t t_hash_ex;
typedef uint128_t t_uuid;

typedef  union{
   const char *            in;
   const uint8_t *         in_uchar;
   const uint16_t * const  out16;
   const uint32_t * const  out32;
   const uint64_t * const  out64;
} uint_aligned_cast_t;

typedef struct 
{
   enum 
   {

      gateway =   0x00,
      cloud =     0x01,
      dnsproxy =  0x02, //not ready yet

   } mode;

} app_t;

#ifdef __cplusplus
}
#endif


TXATR void tx_safe_free(void * const p);
TXATR void * tx_safe_realloc_ex(void * const,size_t,size_t);

TXATR void * tx_safe_malloc(const size_t);

TXATR void * tx_safe_calloc(const size_t,const size_t);

TXATR void * tx_safe_realloc(void *,const size_t);

TXATR bool tx_get_info(char*, size_t *,t_tx_proc_inf,bool);
TXATR bool tx_get_args_ex(char*, size_t *);
TXATR bool tx_get_path_ex(char*, size_t *);

TXATR bool tx_get_info_sz(t_tx_proc_inf pType, size_t * size);
TXATR char * tx_get_args(size_t *);
TXATR char * tx_get_path(size_t *);

TXATR void * tx_safe_memcpy(void * const,const void * const,const size_t);

TXATR 
__attribute__((__format__ (__printf__, 3, 4)))
size_t tx_safe_snprintf(char * const,const size_t,const char * const,...);


TXATR bool tx_safe_atoi(const  char * const,int *); 
TXATR bool tx_safe_atoui(const  char * const,unsigned int *);
TXATR bool tx_safe_atoul(const  char * const,unsigned long int *);
TXATR bool tx_safe_hextoul(const  char * const,unsigned long int *);
TXATR bool tx_safe_atol(const  char * const, long int *);
TXATR bool tx_safe_atoll(const  char * const, long long int *);
TXATR bool tx_safe_atoull(const  char * const,unsigned long long int *);
TXATR bool tx_safe_atob(const  char * const,bool *);

TXATR size_t sm(void * const, const size_t,const char);

/**
 * zero memory buffer
 * @param b    : memory buffer
 * @param bs   : size
 * @return     : size
 */
TX_INLINE_LIB
size_t zm(void * const b,const size_t bs)
{
   /* use memset_s when available */
   return ( b && bs && memset(b,0,bs) ? bs : 0 ); 
} 

/**
 * WITHIN_  range checker
 * @param a_min   : lower bound
 * @param a_max   : upper bound
 * @param a_v     : current
 * @return 0|1    : outside | inside the range
 */

#ifndef WITHIN_
   #ifndef __cplusplus

        TX_INLINE_LIB
        bool int8_WITHIN_( int8_t min_, int8_t max_, int8_t value_ )
        {
            return (!((value_<min_) || (max_<value_)));
        }

        TX_INLINE_LIB
        bool uint8_WITHIN_( uint8_t min_, uint8_t max_, uint8_t value_ )
        {
            return (!((value_<min_) || (max_<value_)));
        }

        TX_INLINE_LIB
        bool int32_WITHIN_( int32_t min_, int32_t max_, int32_t value_ )
        {
            return (!((value_<min_) || (max_<value_)));
        }

        TX_INLINE_LIB
        bool uint32_WITHIN_( uint32_t min_, uint32_t max_, uint32_t value_ )
        {
            return (!((value_<min_) || (max_<value_)));
        }

        TX_INLINE_LIB
        bool int64_WITHIN_( int64_t min_, int64_t max_, int64_t value_ )
        {
            return (!((value_<min_) || (max_<value_)));
        }

        TX_INLINE_LIB
        bool uint64_WITHIN_( uint64_t min_, uint64_t max_, uint64_t value_ )
        {
            return (!((value_<min_) || (max_<value_)));
        }

        TX_INLINE_LIB
        bool ll_WITHIN_( long long min_, long long max_, long long value_ )
        {
            return (!((value_<min_) || (max_<value_)));
        }

        TX_INLINE_LIB
        bool ull_WITHIN_( unsigned long long min_, unsigned long long max_, unsigned long long value_ )
        {
            return (!((value_<min_) || (max_<value_)));
        }

      #define WITHIN_(a_min__,a_max__,a_v__) \
         _Generic( (a_v__),   \
            int8_t: int8_WITHIN_,  \
            char: int8_WITHIN_,  \
            const char: int8_WITHIN_,  \
            uint8_t: uint8_WITHIN_,  \
            int32_t: int32_WITHIN_,  \
            const int32_t: int32_WITHIN_,  \
            uint32_t: uint32_WITHIN_,  \
            const uint32_t: uint32_WITHIN_,  \
            int64_t: int64_WITHIN_,  \
            uint64_t: uint64_WITHIN_,  \
            const uint64_t: uint64_WITHIN_, \
            long long: ll_WITHIN_, \
            unsigned long long: ull_WITHIN_, \
            const unsigned long long: ull_WITHIN_ \
         )(a_min__,a_max__,a_v__)
   #else 

      #define WITHIN_(a_min__,a_max__,a_v__) titan_v3::tools::algorithms::cpp_WITHIN_( a_min__,a_max__,a_v__ )
   #endif

#endif

#ifndef UWITHIN_
   #ifndef __cplusplus

        TX_INLINE_LIB
        bool uint8_UWITHIN_( uint8_t max_, uint8_t value_ )
        {
            return (!((max_)<(value_)));
        }

        TX_INLINE_LIB
        bool uint32_UWITHIN_( uint32_t max_, uint32_t value_ )
        {
            return (!((max_)<(value_)));
        }

        TX_INLINE_LIB
        bool uint64_UWITHIN_( uint64_t max_, uint64_t value_ )
        {
            return (!((max_)<(value_)));
        }

        TX_INLINE_LIB
        bool ull_UWITHIN_( unsigned long long max_, unsigned long long value_ )
        {
            return (!((max_)<(value_)));
        }

      #define UWITHIN_(a_max__,a_v__) \
         _Generic( (a_v__),   \
            uint8_t: uint8_UWITHIN_,  \
            uint32_t: uint32_UWITHIN_,  \
            uint64_t: uint64_UWITHIN_,  \
            const uint64_t: uint64_UWITHIN_, \
            unsigned long long: ull_UWITHIN_, \
            const unsigned long long: ull_UWITHIN_ \
         )(a_max__,a_v__)
   #else 

      #define UWITHIN_(a_max__,a_v__) titan_v3::tools::algorithms::cpp_UWITHIN_( a_max__, a_v__ )
   #endif
#endif

TXATR t_data_buff * data_buff_new(const size_t);
TXATR bool data_buff_free(t_data_buff ** const);

TXATR bool data_buff_grow(t_data_buff * const,const size_t);

TXATR bool data_buff_zero(t_data_buff * const);

TXATR bool data_buff_write(t_data_buff * const,const char * const, const size_t);

TXATR ssize_t data_buff_read(t_data_buff * const,char * const,size_t);

/**
 * calc the ptr diff and report if it is a valid one (>0)
 * @param lptr
 * @param rptr
 * @param dout
 * @return 1/0
 */
TX_INLINE_LIB  bool ptr_diff( const char *const lptr,
                              const char * const rptr,
                              ptrdiff_t * const dout     )
{
   if ( lptr && rptr && dout ) {

      *dout = lptr - rptr;

      return !( *dout < 0 );
   }

   return false;
}


TXATR bool hexdump_hash(t_hash, char * const,const size_t);

TXATR bool hexdump_buff(const char * const, const size_t, char * const,const size_t);

////////////////////////////////////////////////////////////////////////////////
/**
 * @fn ttn_uuid_str2uuid_int
 * @param out[out]: t_uuid *
 * @param in[in] : const char *
 * @return true/false
 */
TXATR bool ttn_uuid_str2uuid_int( t_uuid * const,  const char * const );

/**
 * @fn ttn_uuid_int2str_uuid 
 * @param out[out] : char *
 * @param out_sz[in] : size_t
 * @param in[in] : t_uuid *
 * @note out_sz must be >= GUID_STR_SZ + 1 
 * @return true/false
 */
TXATR bool ttn_uuid_int2str_uuid( char * const, const size_t, t_uuid * const );


/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */

TXATR unsigned int get_DataBuff_active_instances(void);

TXATR int ttn_is_in6_addr( const struct in6_addr * const,
                           c_raw_ipaddr_t * const  );


TXATR int ttn_is_in6_addr_local( const struct in6_addr * const );

TXATR int ttn_is_ipaddr_local( const c_raw_ipaddr_t * const );

TXATR int ttn_is_ipaddr_any( const c_raw_ipaddr_t * const );

/* expose the tsa interface */
#include "ttn_tsa.h"

#endif /* TITAN_GLOBAL_H */
