/**
 * $Id$
 * 
 */

#ifndef TX_LOG_ITEM_HXX
#define TX_LOG_ITEM_HXX
#include <idna.h>
#include <streambuf>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <array>
#include "global.h"
#include "txhash.h"
#include "log.h"
#include "edgelib.h"
#include "sock_rw.h"
#include "ttn_tools.hxx"
#include "ttn_eops.hxx"


namespace titan_v3 {
   template <typename THASH,typename TFIELDS>
   class raw_header
   {
   public:
      THASH    crc={};
      TFIELDS   size={};
      char     raw[sizeof(THASH)]{};
      raw_header() noexcept = default;

      static constexpr size_t raw_size{sizeof(THASH)};
      bool raw_write() noexcept {
         THASH crc_=this->crc;
         if (TFIELDS * const fields=reinterpret_cast<TFIELDS * const>(&crc_)){
            fields[1]=this->size;
         }
         crc_=htobe64(crc_);
         return (tx_safe_memcpy(raw,&crc_,raw_size)!=nullptr);
      }

      bool raw_read() noexcept {
         THASH crc_{};
         if (tx_safe_memcpy(&crc_,raw,raw_size)!=nullptr){
            crc_=be64toh(crc_);
            if (const TFIELDS * const fields=reinterpret_cast<const TFIELDS * const>(&crc_)){
               this->size=fields[1];
               this->crc=fields[0];
               return true;
            }
         }
         return false;
      }

      friend std::ostream& operator<<(std::ostream& out, raw_header & obj) noexcept {
         using namespace tools::eop;
         out <<obj.crc<<" : "<<obj.size<<" : "<<raw_header::raw_size<<"\n"<<tools::functors::hexdump{obj.raw,raw_header::raw_size,(tools::functors::hexdump_cfg::hdc_default | tools::functors::hexdump_cfg::hdc_print_size)};
         return (out);
      } 
   }; /* raw_header */

   using hash_hdr=raw_header<t_hash,uint32_t>;

   class tx_mprovider
   {
      public:
         tools::SBuff       raw_url_;
         tools::SBuff       raw_user_;
         tools::SBuff       raw_domain_;
         tools::SBuff       myMsg_;
         explicit tx_mprovider(const size_t s) noexcept :   raw_url_(s),
                                                            raw_user_(s),
                                                            raw_domain_(s),
                                                            myMsg_(s){}
   }; /* tx_mprovider */

   class tx_log_item;
   
   class tx_log_parser
   {
   protected:
      static void parse_extra_fields__( const char *,
                                        tx_log_item & ) noexcept; 

   public:
      static constexpr bool raw_header_new( const char * const payload,
                                            const size_t payloadsz,
                                            const uint32_t rawsz,
                                            hash_hdr & out_) noexcept {

         if (payload && payloadsz && payloadsz<=rawsz){
            out_.crc=str2crc32(payload,payloadsz);
            out_.size=rawsz;
            return out_.raw_write();
         }
         return false;
      }

      static constexpr bool raw_header_read(    const char * const buffer,
                                                const size_t bsz,
                                                hash_hdr & out_) noexcept {

         return (   buffer && 
                    bsz>=hash_hdr::raw_size && 
                    tx_safe_memcpy(out_.raw,buffer,hash_hdr::raw_size)!=nullptr && 
                    out_.raw_read()
                );
      }

      /**
       * validate header of the message 
       * @param buffer  :  data buffer
       * @param rh_     :  hash_hdr
       * @return        :  t/f
       */
      static constexpr bool validate_ex(    const char * const buffer,
                                            const size_t prefix_offset,
                                            hash_hdr & rh_) noexcept {
         if (buffer){
            //offset data by the size of the prefix+1
            return  (str2crc32((buffer+prefix_offset+1),rh_.size-(prefix_offset+1))==rh_.crc);
         }
         return (false);
      }

      /**
       * validate header of the message 
       * @param buffer  :  data buffer
       * @return        : -1 (error/INVALID) or size of message
       */
      //TODO: rename to read_and_validate()
      static constexpr ssize_t validate(const char * const buffer) noexcept
      {
         if (buffer)
         {
            hash_hdr rh_;
            if (raw_header_read(buffer,hash_hdr::raw_size,rh_))
            {
               const char * const data=buffer+hash_hdr::raw_size;
               return( validate_ex(data,(::strnlen(data,rh_.size)),rh_) ? 
                                static_cast<ssize_t>(rh_.size) : INVALID_ );
            }
         }
         return INVALID_;
      }

#ifndef TTN_ATESTS
      /**
       * validate a message and read it
       * @param fd      : file handler
       * @param out_msg : out msg buffer
       * @param out_sz  : out msg size (without header)
       * @return        : t/f
       */
      static constexpr bool validate(   const int fd,
                                        tools::SBuff & out_msg,
                                        size_t & out_sz           ) noexcept {
#else
      /**
       * validate a message and read it (mocked version)
       * @param fd_mock : raw buffer
       * @param out_msg : out msg buffer
       * @param out_sz  : out msg size (without header)
       * @return        : t/f
       */
      static constexpr bool validate(   const char * const fd_mock,
                                        tools::SBuff & out_msg,
                                        size_t & out_sz              ) noexcept
      {
#endif
         std::array<char,hash_hdr::raw_size> raw_header{};

#ifndef TTN_ATESTS

         if (  INVALID_ < fd && 

               titan_v3::hash_hdr::raw_size == ::read(   fd, 
                                                         raw_header.data(),
                                                         raw_header.max_size() ) ) {
#else 

            if (  fd_mock &&

                  nullptr != ::tx_safe_memcpy(  raw_header.data(),
                                                fd_mock,
                                                raw_header.max_size() ) ) {
#endif
               hash_hdr rh_{};

               return ( tx_log_parser::raw_header_read(  raw_header.data(),
                                                         raw_header.max_size(),
                                                         rh_                     ) && 

                        rh_.size &&

#ifndef TTN_ATESTS
                        rh_.size == ::readn( fd,
                                             out_msg.buf( rh_.size + 1, true ),
                                             rh_.size                            ) &&
#else

                        nullptr != ::tx_safe_memcpy(  out_msg.buf( rh_.size + 1, true ),
                                                      fd_mock + sizeof( raw_header ),
                                                      rh_.size                            )  &&
#endif
                        /*
                         * non zero 
                         * this value gives length of the prefix e.g. LOG
                         */
                        out_msg.data_size() &&

                        tx_log_parser::validate_ex(   out_msg.c_str(),
                                                      out_msg.data_size(),
                                                      rh_                  ) &&

                        ( out_sz = rh_.size ) ); /* return */
         }

         return false;
      }

      /**
       * parse logger's message
       * @param msg        : msg buffer
       * @param msz        : size
       * @param mp         : memory provider
       * @param out_item   : log item 
       * @return           : t/f
       */
      static constexpr bool parse(  const char * const msg,
                                    const size_t msz,
                                    tx_mprovider & mp,
                                    tx_log_item & out_item) noexcept;  //forward declararion
   }; /* tx_log_parser */

   using hex_raw_ipaddr_t=std::array<char,IPV6_RAW_HEX_SZ+1>;
   using hex_value_t=std::array<char,16>;

   class tx_log_item
   {
      friend class tx_log_parser;
      friend std::ostream& operator<<(std::ostream& out, tx_log_item & obj){
         out << "item dump:\n"\
            << "Reason:["<<obj.Reason<<"]\n"\
            << "CloudKey:["<<obj.CloudKey<<"]\n"\
            << "Location:["<<obj.Location<<"]\n"\
            << "UrlProtocol:["<<(obj.mUrlProtocol[0]?obj.mUrlProtocol.data():"")<<"]\n"\
            << "UrlDomain:["<<((obj.mUrlDomain && *obj.mUrlDomain.get())?obj.mUrlDomain.get():"")<<"]\n"\
            << "UrlPort:["<<(obj.mUrlPort[0]?obj.mUrlPort.data():"")<<"]\n"\
            << "UrlPath:["<<obj.UrlPath<<"]\n"\
            << "UrlQuery:["<<obj.UrlQuery<<"]\n"\
            << "UserName:["<<obj.UserName<<"]\n"\
            << "Ip:["<<obj.mIp<<"]\n"\
            << "Duration:["<<obj.Duration<<"]\n"\
            << "Size:["<<obj.Size<<"]\n"\
            << "Cached:["<<obj.Cached<<"]\n"\
            << "UnixTime:["<<obj.UnixTime<<"]\n"\
            << "InternalIp:["<<obj.mInternalIp<<"]\n"\
            << "InternalUser:["<<obj.InternalUser<<"]\n"\
            << "CustomerId:["<<obj.CustomerId<<"]\n"\
            << "PolicyName:["<<obj.PolicyName<<"]\n"\
            << "Groups:["<<tools::functors::citer_ols{obj.Groups,{','}}<<"]\n"\
            << "Categories:["<<tools::functors::citer_ols{obj.Categories,{','}}<<"]\n"\
            << "Emails:["<<tools::functors::citer_ols{obj.Emails,{','}}<<"]\n"\
            << "OrgMsg:["<<obj.OrgMsg<<"]\n";
         return (out);
      }

   public:
      time_t                  UnixTime{};
      std::string             UserName{};
      std::string             UrlPath{};
      std::string             UrlQuery{};
      int                     Status{};
      std::string             Reason{};
      std::string             CloudKey{};
      std::string             Location{};
      size_t                  Size{};
      uint32_t                Duration{};
      bool                    Cached{};
      std::string             OrgMsg{};
      std::string             CustomerId{};
      globals::strings_t      Groups{};
      globals::strings_t      Categories{};
      globals::strings_t      Emails{};
      std::string             FullURL{};
      std::string             InternalUser{};
      std::string             PolicyName{};
      tx_log_item(){}

      const hex_value_t & getUrlProtocol() const noexcept       { return mUrlProtocol; }
      const hex_value_t & getUrlPort() const noexcept           { return mUrlPort; }

      const std::string getUrlProtocol_string() const noexcept { 
        return std::string( mUrlProtocol.data() ); 
      }

      const std::string getUrlPort_string() const noexcept { 
        return std::string( mUrlPort.data() ); 
      }

      const char* getUrlDomain() const noexcept                 { return mUrlDomain.get(); }
      const std::string & getInternalIp() const noexcept        { return mInternalIp; }
      const std::string & getExternalIp() const noexcept        { return mIp;}

      const std::string & getUserNameForsyslog() const noexcept {
         if (!InternalUser.size()) return UserName;
         return InternalUser;
      }

      virtual ~tx_log_item(){}

   #ifdef TTN_ATESTS
      void clear(){
         UnixTime={};
         mIp=std::string{};
         Cached={};
         Status={};
         Size={};
         Duration={};
         mUrlProtocol.fill(0);
         mUrlPort.fill(0);
         mUrlDomain.reset();
         UserName.clear();
         UrlPath.clear();
         UrlQuery.clear();
         CloudKey.clear();
         Location.clear();
         Reason.clear();
         Groups.clear();
         Categories.clear();
         Emails.clear();
         OrgMsg.clear();
         mInternalIp=std::string{};
         InternalUser.clear();
         CustomerId.clear();
         FullURL.clear();
         PolicyName.clear();
      }


      public:
   #else 
      protected:
   #endif
      hex_value_t                      mUrlProtocol{};
      hex_value_t                      mUrlPort{};
      std::string                      mInternalIp{};
      std::string                      mIp{};
      /* idna_to_unicode_8z8z */
      tools::t_cbuffer_uniq            mUrlDomain{};

   }; /* tx_log_item */

   /* definition */
   constexpr bool tx_log_parser::parse(   const char* const msg, 
                                          const size_t msz, 
                                          tx_mprovider & mp, 
                                          tx_log_item  & out_item ) noexcept
   {

      if ( msg && msz ) {

         // make a copy of the original message useful when we externally log
         size_t buf_size = msz;
         out_item.OrgMsg = std::string{ msg, buf_size };

         //make sure buffers are at least size of the buffer;
         if (  ! mp.raw_url_.grow( buf_size + 2, true ) || 

               ! mp.raw_user_.grow( buf_size + 2, true )   ) {

            ::titax_log(LOG_ERROR, "tx_log_parser::parse - malloc issue 1\n");
            return false;
         }

         uint_fast32_t cached {};

         hex_raw_ipaddr_t empty_buff{};/* backward copmatibility */

         /* We could use the sscanf_s (or equivalent) if and when the FreeBSD adds support for it. */
         if (  8 != sscanf(   msg, /* input */
                              "%ld %" SCNu64 " %u %s %u %u %s %[^\n]\n", /* format */
                              static_cast<long int*>(&out_item.UnixTime), 
                              &out_item.Size, 
                              &out_item.Duration, 
                              empty_buff.data(), /* str */
                              &cached, 
                              &out_item.Status,
                              mp.raw_url_.buf(), /* str */
                              mp.raw_user_.buf() /* str */ )  ) {


            ::titax_log(LOG_ERROR, "tx_log_parser::parse - Error in the first line\n");

            return false;
         }

         if ( !::url_decode_ex( mp.raw_url_.buf(), mp.raw_url_.data_size(), nullptr, false ) ) {

            ::titax_log(LOG_ERROR, "tx_log_parser::parse - decoding url failed !\n");
            return false; 
         }

         if ( !( out_item.UserName = mp.raw_user_ ).size() ) {

            ::titax_log(LOG_ERROR, "tx_log_parser::parse - UserName is empty or invalid \n");
            return false;
         }

         //XXX: redundant ? - why we have to limit mDuration to INT_MAX
         if ( out_item.Duration >= INT_MAX ) {

            out_item.Duration = INT_MAX;
         }

         out_item.Cached = ( cached != 0 );

         // Split up URL
         const char * current_part_of_raw_url{};

         if ( ! ( current_part_of_raw_url = ::strnstr( mp.raw_url_.c_str(), "://", buf_size ) )  ) {

            ::titax_log(LOG_ERROR, "tx_log_parser::parse - Bad protocol in URL\n");
            return false; 
         }

         out_item.FullURL = mp.raw_url_;

         ptrdiff_t d_{};

         if ( !::ptr_diff( current_part_of_raw_url, mp.raw_url_.c_str(), &d_ ) ){

            d_ = 0;
         }

         buf_size = static_cast<size_t>(d_);

         if (  mp.raw_url_.empty()                                                              || 

               ! current_part_of_raw_url                                                        || 

               ( out_item.mUrlProtocol.max_size() -1 < buf_size)                                || 

               ! tx_safe_memcpy( out_item.mUrlProtocol.data(), mp.raw_url_.c_str(), buf_size )     ) {

            ::titax_log(LOG_ERROR, "tx_log_parser::parse - UrlProtocol is empty\n");
            return false; 
         }

         if (  ( buf_size = ::strcspn( (current_part_of_raw_url+=3), ":/?" ) )  && 

               ! mp.raw_domain_.grow( buf_size + 2, true )                          ) {

            ::titax_log(LOG_ERROR, "tx_log_parser::parse - malloc issue 5\n");
            return false; 
         }

         if (  ! buf_size                                                                    || 

               ! current_part_of_raw_url                                                     || 

               ! tx_safe_memcpy( mp.raw_domain_.buf(), current_part_of_raw_url, buf_size )      ) {

            ::titax_log(LOG_ERROR, "tx_log_parser::parse - parsing domainname error\n");
            return false;
         }

         char * tmp{};

         if ( ! tools::is_idna_punycode( mp.raw_domain_ ) ) {

            size_t l_{mp.raw_domain_.data_size()};
            tmp = ::str_dup_ex(mp.raw_domain_.c_str(),&l_);
         } 
         else {

            if ( ::idna_to_unicode_8z8z(mp.raw_domain_.c_str(), &tmp, 0) != IDNA_SUCCESS || !tmp ) {

               ::titax_log(LOG_ERROR, "tx_log_parser::parse - idna_to_unicode_8z8z error\n");
               return false;
            }
         }

         out_item.mUrlDomain.reset( tmp );
         current_part_of_raw_url += buf_size;

         // Does a port number follow?
         if (  ! (   current_part_of_raw_url                                                          &&  

                     *current_part_of_raw_url == ':'                                                  && 

                     ( buf_size = ::strcspn( current_part_of_raw_url, "/?" ) )                        &&

                     (  (  ( current_part_of_raw_url + buf_size ) - current_part_of_raw_url > 1 )     || 

                        (  ++current_part_of_raw_url && false )                                    )  &&

                     ( out_item.mUrlPort.max_size() - 1 >= buf_size )                                 && 

                     tx_safe_memcpy( out_item.mUrlPort.data(), current_part_of_raw_url, buf_size )    && 

                     ( current_part_of_raw_url += buf_size )                                             )  )  {

            out_item.mUrlPort[0] = 0;
         }

         // Separate rest of URL into path and query
         if (  current_part_of_raw_url                                     &&

               *current_part_of_raw_url                                    && 

               ( buf_size = ::strcspn( current_part_of_raw_url, "?" )   )     ) {

            out_item.UrlPath=std::string{current_part_of_raw_url,buf_size};
            current_part_of_raw_url+=buf_size;
         }

         if (  current_part_of_raw_url                   &&

               *current_part_of_raw_url == '/'           && 

               *( current_part_of_raw_url + 1 ) == '?'      ) {

            ++current_part_of_raw_url;
         }

         if (  current_part_of_raw_url                         &&

               *current_part_of_raw_url                        && 

               ( buf_size = strlen( current_part_of_raw_url ) )   ) {

            out_item.UrlQuery=std::string{current_part_of_raw_url,buf_size};
         }

         // Done splitting up URL
         tx_log_parser::parse_extra_fields__( msg, out_item );

         if (   LOGGER_REASON_ALLOWED == out_item.Status    && 
                out_item.Reason.size()                          ) {

            titax_log(  LOG_WARNING, 
                        "%s : contradicting data detected :"\
                        "the status msg is not empty [%s] : resolving\n",
                        __func__,
                        out_item.Reason.c_str()                             );

            out_item.Reason.clear();
         }

         int cid{};

         if (  out_item.CustomerId.empty()                           || 

               ! tx_safe_atoi( out_item.CustomerId.c_str(), &cid  )  || 

               0 >= cid                                                 ) {

            titax_log(  LOG_WARNING, 
                        "%s : Got invalid customer id (missing or -1)"\
                        " : Drop log request. \n",
                        __func__                                        );

            return false;
         }

         return true;
      }

      return false;
   }

};/* namespace */

#endif /* TX_LOG_ITEM_HXX */

