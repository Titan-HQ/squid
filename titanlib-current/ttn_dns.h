/**
 * $Id$
 */

#ifndef TTN_DNS_H
#define TTN_DNS_H

#include "global.h"
#include <sys/stat.h>

#define MD_SUFFIX       "wtc"
#define MD_MIN_OUT_SZ   DNSMD_MIN_RAW_SZ

/**
 * @method : ttn_dns_md_make
 * @abstract : make raw metadata 
 * @param data[in/out] : data used to compose the raw metadata
 * @return : t/f
 */
TXATR bool ttn_dns_md_make(t_metadata_handler * const);
/**
 * @method : ttn_dns_md_parse
 * @abstract : parse raw meta data into t_meta_data struct/buffer
 * @param meta_data : raw meta data
 * @param out : output t_meta_data
 * @return : t/f
 * @note : we use only one bit-flag per label/type hence we don't have to check for the presence of others on the same byte (order independent)
 */
TXATR bool ttn_dns_md_parse(const char * const, t_meta_data * const);
/**
 * @method : ttn_dns_qname_decode
 * @abstract : decode raw query name to human-readable form (fqdn)
 * @param qname_ : raw query
 * @param out_ : output buffer
 * @param outbsz_ : output buffer size
 * @param outsz_ : decoded size
 * @return : t/f
 */
TXATR bool ttn_dns_qname_decode(const char * const,char * const, const  size_t, size_t * const);
/**
 * @method : ttn_dns_qname_encode
 * @abstract : encode human-readable query (domain) as series of labels (dns)
 * @note https://tools.ietf.org/html/rfc1035#section-3.3
 * @param qname_ : query
 * @param qsz_ : query size
 * @param out_ : output buffer
 * @param osz_ : output buffer size 
 * @return : t/f
 */
TXATR  bool ttn_dns_qname_encode(const char * const, const size_t, char * const, const size_t);
/**
 * @method : ttn_dns_is_fqdn_on_list
 * @abstract : check if given qname (fqdn) is present in the folder (path) (not thread safe)
 * @param path : [bl/wl]
 * @param qname : fqdn
 * @param len : size of fqdn
 * @return : t/f
 */
#ifndef ttn_dns_is_fqdn_on_list
   #define ttn_dns_is_fqdn_on_list( _PATH_, _QNAME_, _LEN_) \
      ttn_dns_is_fqdn_on_list_ex( _PATH_, _QNAME_, _LEN_, NULL)
#endif
TXATR bool ttn_dns_is_fqdn_on_list_ex(const char path[2], const char *, size_t, struct stat * );
/**
 * @method ttn_dns_qname_sz
 * @abstract calculates the size of the dns encoded query/fqdn  (in bytes)
 * @param query (dns encoded)
 * @param strict_mode (see RFC1035)
 * @return size or 0 on error
 */
TXATR size_t ttn_dns_qname_sz(const char *const,const bool);

/**
 * @method ttn_dns_qname_sz_raw
 * @abstract calculates the size of the dns encoded query including length octets
 * @note https://tools.ietf.org/html/rfc1035#section-4.1.2
 * @param query (dns encoded)
 * @return size or 0 on error
 * @note http://www.tcpipguide.com/free/t_DNSNameNotationandMessageCompressionTechnique.htm
 * 
 */
TX_INLINE_LIB
size_t ttn_dns_qname_sz_raw(const char *const query){
   if (query){
      const char * x=query;
      for(;*x;x += TTN_UNI_CAST(unsigned char,*x)+1)
         ;/* empty body */

      return TTN_UNI_CAST(uintptr_t,(x - query)+1);
   }
   return 0;
}

/**
 * @method ttn_dns_is_ip_on_list
 * @abstract check if given ip is present in the folder (path)
 * @param path two letter path e.g. ts/bl/wl
 * @param src_ip ip as c_raw_ipaddr_t (ipv4/ipv6)
 * @return t/f
 */
TXATR bool ttn_dns_is_ip_on_list(const char * const, c_raw_ipaddr_t);

/**
 *  @fn ttn_bin_ipaddr2raw_ipaddr_ex
 *  @abstract converts bin str into raw ipaddr struct (ipv4 or ipv6)
 *  @param bin[in] : (pass {.ptr_=X} 
 *  @param out[out] : raw_ipaddr_t ptr
 *  @return bool 
 */
TXATR bool ttn_bin_ipaddr2raw_ipaddr_ex( t_strptr bin, c_raw_ipaddr_t * const );

/**
 *  @fn ttn_bin_ipaddr2str_ipaddr_ex
 *  @abstract converts bin str into raw ipaddr struct (ipv4 or ipv6)
 *  @param bin[in] : (pass {.ptr_=X} 
 *  @param out[out] : char ptr
 *  @param osz[in] : size_t out size 
 *  @return bool 
 */
TXATR bool ttn_bin_ipaddr2str_ipaddr_ex( t_strptr bin, char * const out, const size_t osz );

#ifdef TTN_ATESTS
   TXATR const char * FSTAT_CMP_PATH;
#endif

#endif /* TTN_DNS_H */
