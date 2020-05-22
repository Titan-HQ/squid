/**
 * $Id$
 */


#include "ttn_dns.h"
#include "TAPE.h"
#include "edgelib.h"
#include "global.h"
#include "log.h"
#include "txbase16.h"
#include <assert.h>
#include <sys/ioctl.h>
#include <sys/types.h>

/* TODO:  MD_IP_SZ change for IPv6 as is now printed at 128 characters ratehr than %08X*/
#define MD_IP_SZ        0x0A
#define MD_OTHERS_SZ    0x12
#define MD_ORC_CRC_SZ   0x22
#define MD_SUFFIX_SZ    0x04

/**
 * @abstract encode human-readable query (domain) as series of labels (dns)
 * @note 
 * This encoder doesn't check if the input string contain valid charset
 * https://tools.ietf.org/html/rfc1034#section-3.1
 * https://tools.ietf.org/html/rfc1035#section-2.3.3
 * RFC1035_LABEL_LIMIT
 * todo: it could return the encoded strlen
 */
TX_INTERNAL_INLINE
bool qname_encode_(  const char * const restrict qname_, 
                     size_t qsz_, 
                     char * restrict out_, 
                     const size_t osz_                   )
{
   out_[0]='.';
   (void)strlcpy(out_+1,qname_,osz_-1);
   while(qsz_){
      const ssize_t dp=ttn_strncspn(out_+1,(qsz_<RFC1035_LABEL_LIMIT?qsz_:RFC1035_LABEL_LIMIT),".",1);
      if (INVALID_<dp){
         switch (out_[dp+1]){
            case '.':{
               *out_=(char)dp;
               out_+=dp+1;
               qsz_-=(size_t)dp+1;
               continue;
            }
            case 0:{
               *out_=(char)dp;
               /* finish */
               return true;
            }
            default: return false;
         }
      }
      return false;
   }
   /* finish */
   return true;
}

struct qname_sz_elems_t
{
   size_t c_;
   const char * const q_;
};

TX_INTERNAL_INLINE
size_t qname_sz_strict_(const char *const restrict query)
{
   struct qname_sz_elems_t e={.q_=query,};

   for (;e.c_<=RFC1035_MAX && (WITHIN_(1,RFC1035_LABEL_LIMIT,((uint8_t)e.q_[e.c_]))>0);e.c_+=((uint8_t)e.q_[e.c_])+1);
   return ((e.c_ &&  ((e.c_-1)<=RFC1035_MAX) && (!e.q_[e.c_] /*last*/  || WITHIN_(1,RFC1035_LABEL_LIMIT,((uint8_t)e.q_[e.c_]))>0))?e.c_-1:0);

}

TX_INTERNAL_INLINE
size_t qname_sz_not_strict_(const char *const restrict query)
{
   struct qname_sz_elems_t e={.q_=query,};
   for (;((uint8_t)e.q_[e.c_])>0;e.c_+=((uint8_t)e.q_[e.c_])+1);
   return (e.c_?e.c_-1:0);
}

/**
 * @name ttn_dns_md_make_with_orchid_crc_
 * @abstract INTERNAL
 * The orchid crc has very specific/historic needs in terms of the input data
 * so to be completely backward compatible with the older dnsp/wtc (pre 4.05)
 * the meta data must to be generated in two separate stages:
 * formating AND encoding
 * @todo: replace the tx_safe_snprintf
 */
TX_INTERNAL_INLINE
bool ttn_dns_md_make_with_orchid_crc_(t_metadata_handler * const restrict data)
{
   /* clear text meta data */
   char ctmd[RFC1035_MAX+1]={}; 
   char * out=ctmd;
   data->size=0;
   /* formating (include crc) */
   /* @TODO: finish adding the ipv6 support */
   BW_SWITCH_EX_(t_meta_types,mt_max_,data->labels,{
      case mt_ip:{
         if (!data->ip.v4 || (data->size+=MD_IP_SZ)+1>data->osz || MD_IP_SZ!=tx_safe_snprintf(out, MD_IP_SZ+1, "%c%08X.",DNSMD_RFB_ENC_IP,data->ip.v4)) return false;
         out+=MD_IP_SZ;
      }break;
      case mt_uid:{
         if ((data->size+=MD_OTHERS_SZ)+1>data->osz || MD_OTHERS_SZ!=tx_safe_snprintf(out, MD_OTHERS_SZ+1, "%c%08X.",DNSMD_RFB_ENC_USERID,data->uid)) return false;
         out+=MD_OTHERS_SZ;
      }break;
      case mt_lid:{
         if ((data->size+=MD_OTHERS_SZ)+1>data->osz || MD_OTHERS_SZ!=tx_safe_snprintf(out, MD_OTHERS_SZ+1, "%c%08X.",DNSMD_RFB_ENC_LOCATIONID,data->lid)) return false;
         out+=MD_OTHERS_SZ;
      }break;
      case mt_crc:{
         /* restored for backward compatibility and assumes orchid based crc */
         t_txhash_args *const hash=new_orchid_hash_from_str(data->crc_input,ctmd,false);
         bool err=true;
         const char * const hex_crc=txhash_gethex(hash);
         if (hex_crc)
            err=((data->size+=MD_ORC_CRC_SZ)+1>data->osz || MD_ORC_CRC_SZ!=tx_safe_snprintf(out, MD_ORC_CRC_SZ+1, "%c%s.",DNSMD_RFB_ENC_CRC,hex_crc));

         free_txhash_args (hash);
         if (err) return false;
         out+=MD_ORC_CRC_SZ;
      }break;
      default:break;
   })

   if (((data->size+=(MD_SUFFIX_SZ-1))+1>data->osz) || (MD_SUFFIX_SZ-1)!=tx_safe_snprintf(out, MD_SUFFIX_SZ, "%s",MD_SUFFIX)) {
      return false;
   }
   /* encoding */
   return qname_encode_(ctmd,data->size,data->output,data->osz);
}

/**
 * @name ttn_dns_md_make_nocrc_
 * @abstract INTERNAL single stage meta data generator
 * @note it is not strictly necessary to encode the meta data as a sequence of labels (dns enc)
 * so we could add one leading flag (prefix the md) and conditionally disable such encoding 
 * to speed up the meta data parsing on the receiving end
 * @todo: replace the tx_safe_snprintf
 */
TX_INTERNAL_INLINE
bool ttn_dns_md_make_nocrc_(t_metadata_handler * const restrict data)
{
   char * out=data->output;
   data->size=0;
    /* @TODO: finish adding the ipv6 support */ 
   BW_SWITCH_EX_(t_meta_types,mt_max_,data->labels,{
      case mt_ip:{
         if (!data->ip.v4 || (data->size+=MD_IP_SZ)+1>data->osz|| MD_IP_SZ!=tx_safe_snprintf(out, MD_IP_SZ+1, "%c%c%08X",(MD_IP_SZ-1),DNSMD_RFB_ENC_IP,htonl(data->ip.v4) )) return false;
         out+=MD_IP_SZ;
      }break;
      case mt_uid:{
         if ((data->size+=MD_IP_SZ)+1>data->osz || MD_IP_SZ!=tx_safe_snprintf(out, MD_IP_SZ+1, "%c%c%08X",(MD_IP_SZ-1),DNSMD_RFB_ENC_USERID,(uint32_t)data->uid)) return false;
         out+=MD_IP_SZ;
      }break;
      case mt_lid:{
         if ((data->size+=MD_IP_SZ)+1>data->osz || MD_IP_SZ!=tx_safe_snprintf(out, MD_IP_SZ+1, "%c%c%08X",(MD_IP_SZ-1),DNSMD_RFB_ENC_LOCATIONID,data->lid)) return false;
         out+=MD_IP_SZ;
      }break;
      case mt_crc:{
         /* mockup: for now it is just 8 zeros */
         size_t crc=0x0000000000000000;
         /* we can decide later what to use here if at all */
         if ((data->size+=MD_OTHERS_SZ)+1>data->osz || MD_OTHERS_SZ!=tx_safe_snprintf(out, MD_OTHERS_SZ+1, "%c%c%016" PRIX64,MD_OTHERS_SZ-1,DNSMD_RFB_ENC_CRC,crc)) return false;
         out+=MD_OTHERS_SZ;
      } break;
      default:break;
   })

   if (((data->size+=MD_SUFFIX_SZ)+1>data->osz) || MD_SUFFIX_SZ!=tx_safe_snprintf(out, MD_SUFFIX_SZ+1, "%c%s",MD_SUFFIX_SZ-1,MD_SUFFIX)) return false;
   return true;
}

/*******************************************************************************/

bool ttn_dns_md_make(t_metadata_handler * const restrict data)
{
   if (data && data->output && WITHIN_(MD_MIN_OUT_SZ,RFC1035_MAX,data->osz) && data->labels){
      /* preemptive check */
      return ((!(data->labels&mt_crc) || txhh_orchid!=data->crc_type)?ttn_dns_md_make_nocrc_(data):ttn_dns_md_make_with_orchid_crc_(data));
   }
   return false;
}

size_t ttn_dns_qname_sz(   const char *const restrict query,
                           const bool strict_mode              )
{
   if (query && *query)
      return (size_t)(strict_mode?qname_sz_strict_(query):qname_sz_not_strict_(query));
   return 0;
}

/**
 * @warning don't clear the raw_ptr,
 * it will cause a memleak
 */
#define DMDP_EXIT_ON_ERROR(){             \
   out_->iip.v6=(out_->iip_valid=false);  \
   out_->ilid=(out_->ilid_valid=false);   \
   out_->iuid=(out_->iuid_valid=false);   \
   out_->crc[0]=0;                        \
   return false;                          \
}

bool ttn_dns_md_parse(  const char * const restrict meta_data_,
                        t_meta_data * const restrict out_         )
{
   size_t md_sz=0;
   if (  out_ && 
         meta_data_ && 
         *meta_data_ && 
         ( md_sz=qname_sz_strict_( meta_data_ ) ) ){

            const char * mdp=(const char *)meta_data_;
            u_char c_=0;
            size_t p_sz=0;
            out_->ilid=out_->iuid=out_->iip.v6=0;

            while (  ( c_ =( u_char )( *mdp++ ) ) && 
                     c_>=( sizeof( MD_SUFFIX )-1 ) && 
                     ( p_sz+=c_ )<=md_sz /* <- probably it is unnecessary test */){

                     if (  (MD_SUFFIX_SZ-1)==c_ && 
                           !memcmp( MD_SUFFIX, mdp, (sizeof(MD_SUFFIX)-1) )) return (true); /* OK */

                     if ((*mdp)>DNSMD_MASK_OFFSET){

                        switch(*mdp){
                           /* read'n'convert */
                           case DNSMD_RFB_ENC_USERID:       out_->iuid_valid=ttn_base16_decode_uint32(mdp+1,c_-1,&out_->iuid);      break;

                           case DNSMD_RFB_ENC_LOCATIONID:   out_->ilid_valid =ttn_base16_decode_uint32(mdp+1,c_-1,&out_->ilid);     break;

                           case DNSMD_RFB_ENC_IP:{
                              out_->iip.v6=0;
                              if ( (out_->iip_valid=ttn_base16_decode_uint32(mdp+1,c_-1,&out_->iip.v4)) ){
                                 out_->iip.v4=ntohl(out_->iip.v4);
                              }

                           }break;

                           case DNSMD_RFB_ENC_CRC:{

                              if ( UWITHIN_( (sizeof( out_->crc ) - 1 ), c_ ) ) {

                                 (void)tx_safe_memcpy(out_->crc,mdp+1,c_-1); 
                                 break;
                              }
                              /* problem */
                           }

                           /*TODO: Add laabel for ipv6 address */
                           default:{
#ifndef TTN_ATESTS
                              titax_log(LOG_ERROR,"Error: unknown label type %d \n",(*mdp));
#endif
                              DMDP_EXIT_ON_ERROR()
                           }
                        }

                        mdp += (uint8_t)c_;
                        continue;
                  }
#ifndef TTN_ATESTS
                  titax_log(LOG_ERROR,"Error: unknown label type %d \n",(*mdp));
#endif
                  DMDP_EXIT_ON_ERROR()
            }

#ifndef TTN_ATESTS
            titax_log(LOG_ERROR,"Error:domain label to small %d \n",c_);
#endif
            DMDP_EXIT_ON_ERROR()


   }
#ifndef TTN_ATESTS
   titax_log(LOG_ERROR,"Error: empty metadata \n");
#endif
   return (false); /* error */
}

bool ttn_dns_qname_decode(  const char * const restrict qname_,
                            char * const restrict out_,
                            const  size_t outbsz_,
                            size_t * const restrict outsz_ ){
   if (qname_ && *qname_){
      const size_t dsz=qname_sz_strict_(qname_);
      if (dsz){
         char decode_qname_buf[RFC1035_MAX+2];
         (void)strlcpy(decode_qname_buf,qname_,sizeof(decode_qname_buf));
         char * org=decode_qname_buf;
         char * q_=org;
         bool e_=false;
         while (!e_ && *q_>0){
            size_t lsz=(size_t)(*q_);
            char * p_=q_++;
            while (
                     (lsz && lsz<256)
                     && !(e_=!((*q_>32) && (*q_<=126)))
                     && (((*q_ >= 'A') && (*q_ <= 'Z') && (*q_+=32)) || *q_)
                     && (q_++)
                     && (--lsz)
                  );
            (void)(!e_ && (*p_='.'));
         }
         if (e_){
            *q_ = '?'; //broken name ?
            return (false);
         }

         if (out_ && outbsz_ && outsz_){
            *outsz_=(sizeof(decode_qname_buf)>outbsz_?outbsz_:dsz);
            (void)strlcpy(out_,decode_qname_buf+1,*outsz_+1);
            return (true);
         }
      }
   }
   if (out_ && outbsz_ && outsz_){
      *outsz_=1;
      (void)strlcpy(out_,".",*outsz_+1);
      return (true);
   }
   return (false);
}

bool ttn_dns_qname_encode( const char * const restrict qname_,
                           const size_t qsz_, 
                           char * const restrict out_, 
                           const size_t osz_                   )
{
   return ( qname_            && 
            *qname_           && 
            out_              && 
            qsz_              && 
            qsz_+2 <= osz_    && 
            qname_encode_( qname_, qsz_, out_, osz_ ) );
}

#ifdef TTN_ATESTS

   const char * FSTAT_CMP_PATH=NULL;

   #define FSTAT(a_fn_,a_sbp_) __extension__ ({(a_sbp_)->st_size=0;(bool)(strcmp(a_fn_, FSTAT_CMP_PATH));})   
#else

   #define FSTAT(a_fn_, a_sbp_)  ((bool)(stat(a_fn_, a_sbp_)))
#endif

bool ttn_dns_is_fqdn_on_list_ex( const char path[2], 
                                 const char * restrict qname, 
                                 size_t len,
                                 struct stat * out             ) 
{
   if ( qname && len>0 && FQDN_MAX>(len + 4) ) {

      if ( len == 1 && *qname == '.' ) {

         /* see the WTC-2240 and SVN 19459 for the details and the oryginal fix */
         return false;
      }

      static char fn[FQDN_MAX+1] = {}; 

      strlcpy( fn, (char[]){ path[0], path[1], '/' , 0 }, sizeof(fn) );

      bool c_ = true;

      struct stat st_ = {};

      const char* next_dot = NULL;

      ssize_t p_ = 0;

      ptrdiff_t d_ = 0;

      while (  len                                                                  && 

               UWITHIN_( sizeof(fn)-3,  strlcpy( fn + 3, qname,  sizeof(fn)-3 ) )   &&

               ( c_ = FSTAT( fn, &st_ ) )                                           &&

               ( p_ = ttn_strncspn( qname, len,".", 1) ) > 0                        &&

               *( next_dot = qname + p_ )                                           &&

               ptr_diff( next_dot + 1, qname, &d_ )                                 &&

               d_ > 0                                                               &&

               ( (size_t)d_ < len )                                                    ) {


                  len -= (size_t)d_;

                  qname  = next_dot + 1;
      }

      if ( out )  {

         memcpy( out, &st_, sizeof ( st_ ) );
      }

      return (!c_);
   }

   return false;
}

bool ttn_dns_is_ip_on_list(const char path[2], c_raw_ipaddr_t src_ip)
{
    char str[INET6_ADDRSTRLEN]={};

    #define _MAXFN_ 64
         
    tx_static_assert_true(    _MAXFN_ > sizeof(str) + 3,
                              "Unable to compile MAXFN is too short"  );

    if ( ttn_raw_ipaddr2str_ipaddr_ex( &src_ip, str, sizeof(str) ) ) {

        char fn[_MAXFN_]={path[0],path[1],'/'}; /* padded */
        /* the strlcat much is better but it trips the analyzer */
        (void)strncat(fn,str,strlen(str));

        struct stat st;
        return ((0==FSTAT(fn, &st)));
    }

    #undef _MAXFN_
    return false;
}

