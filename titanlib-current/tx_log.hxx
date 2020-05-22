/*
 * $Id$
 */

#ifndef TXLOG_H_
#define TXLOG_H_

#include <streambuf>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>
#include <cassert>
#include <mutex>
#include "global.h"
#include "txip.h"
#include "txhash.h"
#include "ttn_sbuff.hxx"
#include "tx_log_item.hxx"
#include "ttn_cidr.hxx"

namespace titan_v3 {

#define STD_INIT_ERR_(a_msg_){                              \
   std::stringstream v_exmsg_("ERROR:");                    \
   v_exmsg_<<__FILE__<<":"<<__LINE__<<":"<<a_msg_;          \
   throw std::runtime_error(v_exmsg_.str());                \
}

#define MK_LOG_TCP_CALL_(a_var_,a_ip_,a_port_){             \
   a_var_.port=a_port_;                                     \
   a_var_.backlog_sz=0;                                     \
   a_var_.op_so_stream=true;                                \
   a_var_.op_so_reuse_addr=true;                            \
   a_var_.op_so_keep_alive=false;                           \
   a_var_.op_tcp_no_delay=false;                            \
   a_var_.op_io_no_block=false;                             \
   a_var_.type=TXST_CLIENT;                                 \
   (void)strlcpy(a_var_.ip, a_ip_,sizeof(a_var_.ip));       \
};

typedef struct{
   bool *               isopen;
   int *                outfd;
   t_txip_socket_ex *   sock;
   const char *         path;
   t_txpe_output_type   type;
   bool                 ftrim;
}t_tx_log_open_call;


typedef struct{
   t_tx_log_open_call   open_call;
   const char *         buf;
   size_t               len;
   unsigned             ntry;
   unsigned             max;
   bool                 use_locks;
}t_tx_log_log_call;

bool fd_open(t_tx_log_open_call * const) noexcept ;
bool fd_log(t_tx_log_log_call *const ) noexcept;

class txsbuf : public std::streambuf {
   public:
      using std::streambuf::pbase;
      using std::streambuf::pptr;
      using std::streambuf::epptr;
};

class tx_flog;
class tx_slog;
class tx_log;
/*
[tx_alog]
-add the append methods (helper methods eq to << op)
*/
class tx_alog
{
   friend class tx_flog;
   friend class tx_slog;
   friend class tx_log;
protected:
   txsbuf              *sb{};
   std::stringstream    ss{};
   bool                 active_{};
   std::mutex           lock_{};
   bool                 processing_prepare_data{};
   bool                 data_prepared{};
   t_txpe_output_type   type{};

   bool init_() noexcept  {
      this->clear();
      this->sb=reinterpret_cast<txsbuf*>(this->ss.rdbuf());
      this->active_=false;
      this->data_prepared=false;
      this->processing_prepare_data=false;
      this->type=ot_cout;
      return (true);
   }

   virtual bool prepare_data_() noexcept {
      if(!this->processing_prepare_data){
         this->processing_prepare_data=true;//mocking
         /*
         * ops
         */
      }
      return (!(this->processing_prepare_data=false));
   }
   
public:
   tx_alog() : sb(nullptr),type(ot_none){
      if (!this->init_())STD_INIT_ERR_("init failed")
      this->open();
   }

   virtual ~tx_alog(){
      if (this->active_) this->close();
      //this->clear();
      this->sb=nullptr;
   }

   bool active() const noexcept {
      return this->active_;
   }

   bool open() noexcept {
      return ((this->active_=true));
   }

   void close() noexcept {
      this->active_=false;
   }

   bool clear() noexcept {
      this->ss.clear();
      this->ss.str(std::string());
      this->ss.str().reserve( 256 );    /* To minimize growing the storage */
      this->ss.seekp(0,std::ios::beg);
      return (true);
   }

   bool rewind() noexcept {
      this->ss.seekp(0,std::ios::beg);
      return (true);
   }

   size_t length() noexcept {
      return titan_v3::tools::functors::stream_size{this->ss};
   }

   /* replace lock and unlock with c++11 locking */
   bool lock() noexcept {
      this->lock_.lock();
      return true;
   }

   bool unlock() noexcept {
      this->lock_.unlock();
      return true;
   }

   bool log() noexcept {
      if (this->active_){
         std::cout<<*this;
         return (true);
      }
      return (false);
   }

   bool log(tx_alog & what) const noexcept {
      if(this->active_){
         std::cout<<what;
         return (true);
      }
      return (false);
   }
   
   static bool log_to_out(tx_alog & what) noexcept {
      std::cout<<what;
      return (true);
   }

   template <typename TVAL>
   typename std::enable_if<!std::is_pointer<TVAL>::value,std::ostream&>::type
   operator<< (const TVAL & v) noexcept {return ((this->ss<<v));}

   template <typename TVAL>
   typename std::enable_if<(std::is_pointer<TVAL>::value && (std::is_same<TVAL,char*>::value||std::is_same<TVAL,const char*>::value)),std::ostream&>::type
   operator<< (TVAL v) noexcept  {return ((this->ss<<v));}

   template<std::size_t N> std::ostream&
   operator<< (const char(&ar)[N]) noexcept {return ((this->ss<<ar));}

   operator char *() noexcept {
      if (this->prepare_data_()) return this->sb->pbase();
      return nullptr;
   }

   operator const char *() noexcept {
      if (this->prepare_data_()) {
         return this->sb->pbase();
      }
      return nullptr;
   }

   const char * c_str() noexcept {
      if (this->prepare_data_()) return this->sb->pbase();
      return nullptr;
   }

   friend std::ostream& operator<<(std::ostream& out, tx_alog & obj){
      if (obj.prepare_data_() && obj.length()){
         out << obj.sb;
      }
      return (out);
   }

   static bool open(const char * const){/*NOT IMPLEMENTED*/assert(false);return (false);}
   static bool open(const char * const,const size_t){/*NOT IMPLEMENTED*/assert(false);return (false);}
   static bool open(const std::string &){/*NOT IMPLEMENTED*/assert(false);return (false);}

   static bool log(const char *const){/*NOT IMPLEMENTED*/assert(false);return (false);}
   static bool log(const std::string &){/*NOT IMPLEMENTED*/assert(false);return (false);}
   static bool log(const char *const,const size_t){/*NOT IMPLEMENTED*/assert(false);return (false);}

   void append(const char *const b, const size_t s) noexcept {
      this->ss.write(b,static_cast<std::streamsize>(s));
   }
   
   std::streamsize fill(const char c) noexcept {
      return (this->ss.fill(c));
   }
   
   std::streamsize width(const int s) noexcept {
      return (this->ss.width(s));
   }
   
   bool prepare() noexcept {
      return (this->prepare_data_());
   }

}; /* tx_alog */

class tx_flog:public tx_alog  
{
protected:
   int               logger_fd;
   std::string       path;
   bool             auto_lock;
   bool             f_trim;
   using tx_alog::init_;

   inline 
   bool init_(const bool use_auto_locks, const bool trim_file,const char* const path_=nullptr) noexcept {
      this->type=ot_file;
      if (this->init_()){
         this->auto_lock=use_auto_locks;
         this->path=((path_ && path_[0])?std::string{path_}:std::string{});
         this->f_trim=trim_file;
         if (this->path.length()>0 && !this->open()){
            return (false);
         }
         return (true);
      }
      return (false);
   }

public:
   tx_flog(const bool use_auto_locks,const bool trim_file,const std::string & pPath) : logger_fd(-1),auto_lock(false),f_trim(false){
      if (!this->init_(use_auto_locks,trim_file,pPath.c_str()))STD_INIT_ERR_("init failed")
   }

   tx_flog(const bool use_auto_locks,const std::string & pPath) : logger_fd(-1),auto_lock(false),f_trim(false){
      if (!this->init_(use_auto_locks,false,pPath.c_str()))STD_INIT_ERR_("init failed")
   }

   explicit tx_flog(const std::string & pPath) : logger_fd(-1),auto_lock(false),f_trim(false){
      if(!this->init_(false,false,pPath.c_str()))STD_INIT_ERR_("init failed")
   }

   explicit tx_flog(const char * const pPath) : logger_fd(-1),auto_lock(false),f_trim(false){
      if (!this->init_(false,false,pPath))STD_INIT_ERR_("init failed")
   }

   tx_flog(const bool use_auto_locks,const char * const pPath) : logger_fd(-1),auto_lock(false),f_trim(false){
      if (!this->init_(use_auto_locks,false,pPath))STD_INIT_ERR_("init failed")
   }

   explicit tx_flog(const bool use_auto_locks) : logger_fd(-1),auto_lock(false),f_trim(false){
      if(!this->init_(use_auto_locks,false))STD_INIT_ERR_("init failed")
   }

   tx_flog() : logger_fd(-1),auto_lock(false),f_trim(false){
      if(!this->init_(false,false,""))STD_INIT_ERR_("init failed")
   }

   ~tx_flog() noexcept {
      if (this->active_) this->close();
      this->clear();
      this->sb=nullptr;
   }

   bool open() noexcept ;

   bool open(const char * const ppath) noexcept {
      assert(ppath && "open failed");
      return (this->open(ppath,strlen(ppath)));
   }

   bool open(const char * const ppath, const size_t sz) noexcept {
      if (!this->active_ && ppath && sz>0){
         this->path=std::string{ppath,sz};
         return (this->open());
      }
      return (false);
   }

   bool open_file(const char * const ppath, const size_t sz) noexcept {
      return (this->open(ppath,sz));
   }

   bool open(const bool use_auto_locks,const char * const ppath) noexcept {
      if(!this->active_){
         this->auto_lock=use_auto_locks;
         assert(ppath && "open failed");
         return (this->open(ppath,strlen(ppath)));
      }
      return (false);
   }

   bool open(const bool use_auto_locks,const bool trim_file,const char * const ppath) noexcept {
      if(!this->active_){
         this->auto_lock=use_auto_locks;
         this->f_trim=trim_file;
         assert(ppath && "open failed");
         return (this->open(ppath,strlen(ppath)));
      }
      return (false);
   }

   bool open(const std::string & ppath) noexcept {
      if(!this->active_){
         this->path=ppath;
         return (this->open());
      }
      return (false);
   }

   bool open(const bool use_auto_locks,const std::string & ppath) noexcept {
      if (!this->active_){
         this->path=ppath;
         this->auto_lock=use_auto_locks;
         return (this->open());
      }
      return (false);
   }

   bool open(const bool use_auto_locks,const bool trim_file,const std::string & ppath) noexcept {
      if(!this->active_){
         this->path=ppath;
         this->auto_lock=use_auto_locks;
         this->f_trim=trim_file;
         return (this->open());
      }
      return (false);
   }

   void close() noexcept {
      if(this->active_){
         switch(this->logger_fd){
            case -1:break;
            default:
               (void)::close(this->logger_fd);
            break;
         }
         this->auto_lock && this->unlock();
         this->active_=false;
      }
   }

   bool rewind() noexcept {
      if (this->active_){
         lseek(this->logger_fd,0,SEEK_SET);
         tx_alog::rewind();
         return true;
      }
      return (false);
   }

   bool log() noexcept ;

   bool log(tx_alog &) noexcept ;

   static bool log_to_file(tx_alog &,const char * const )noexcept ;

   static bool log_to_file(tx_alog & what,const std::string & path) noexcept {
      return (tx_flog::log_to_file(what,path.c_str()));
   }

   inline
   bool log_to_file(const std::string & path_) noexcept {
      return (tx_flog::log_to_file(*this,path_));
   }

   inline
   bool log_to_file(const char * const path_) noexcept {
      return (tx_flog::log_to_file(*this,path_));
   }

   using tx_alog::clear;

};/* tx_flog */

class tx_slog: public tx_flog 
{
protected:
   /* it is always local */
   t_txip_socket_ex  txsocket;

   bool init_() noexcept {
      (void)zm(&this->txsocket,sizeof(t_txip_socket_ex));
      this->txsocket.port=0;
      this->txsocket.backlog_sz=0;
      this->txsocket.op_so_stream=true;
      this->txsocket.op_so_reuse_addr=true;
      this->txsocket.op_so_keep_alive=false;
      this->txsocket.op_tcp_no_delay=false;
      this->txsocket.op_io_no_block=false;
      this->txsocket.type=TXST_CLIENT;
      return (true);
   }
   using tx_flog::log_to_file;
   using tx_flog::rewind; //there is no much use for this on socket
   bool open() noexcept ;
public:
   tx_slog() : tx_flog(){
      if (!this->init_()) STD_INIT_ERR_("init failed")
   }

   explicit tx_slog(const bool use_auto_locks) : tx_flog(use_auto_locks){
      if(!this->init_())STD_INIT_ERR_("init failed")     
   }

   bool open_tcp(const bool use_auto_locks, t_txip_socket_ex* const call ) noexcept {
      this->type=ot_tcp;
      this->auto_lock=use_auto_locks;
      this->txsocket=*call;
      return (this->open());
   }

   bool open_tcp(const std::string & ip, const uint16_t port) noexcept {
      this->type=ot_tcp;
      this->txsocket.port=port;
      (void)strlcpy(this->txsocket.ip, ip.c_str(),sizeof(this->txsocket.ip));
      return (this->open());
   }

   bool open_tcp(const char * const ip, const uint16_t port) noexcept {
      this->type=ot_tcp;
      this->txsocket.port=port;
      (void)strlcpy(this->txsocket.ip, ip,sizeof(this->txsocket.ip));
      return (this->open());
   }

   bool open_uds(const bool use_auto_locks, const std::string & UDSPath ) noexcept {
      this->type=ot_uds;
      this->path=UDSPath;
      this->auto_lock=use_auto_locks;
      return (this->open());
   }

   bool open_uds(const std::string & UDSPath ) noexcept {
      this->type=ot_uds;
      this->path=UDSPath;
      return (this->open());
   }

   bool open_uds(const char * const UDSPath ) noexcept {
      this->type=ot_uds;
      this->path=UDSPath;
      return (this->open());
   }

   bool log() noexcept ;

   bool log(tx_alog &) noexcept ;

   inline
   bool log_to_tcp(const std::string & ip, const uint16_t port) noexcept {
      if (ip.length() && port){
         t_txip_socket_ex sock{};
         MK_LOG_TCP_CALL_(sock,ip.c_str(),port)
         return (tx_slog::log_to_tcp(*this,&sock));
      }
      return (false);
   }

   inline
   bool log_to_tcp(const char * const ip,const uint16_t port) noexcept {
      if (ip && ip[0] && port){
         t_txip_socket_ex sock{};
         MK_LOG_TCP_CALL_(sock,ip,port)
         return (tx_slog::log_to_tcp(*this,&sock));
      }
      return (false);
   }

   inline
   bool log_to_uds(const std::string & udspath) noexcept {
      return (this->log_to_uds(udspath.c_str()));
   }

   inline
   bool log_to_uds(const char * const udspath) noexcept {
      return (tx_slog::log_to_uds(*this,udspath));
   }

   static bool log_to_tcp(tx_alog &, t_txip_socket_ex* const ) noexcept ;

   static bool log_to_uds(tx_alog &, const char * const ) noexcept ;

   static bool log_to_tcp(tx_alog & what, const char * const ip, const uint16_t port) noexcept {
      if (ip && port){
         t_txip_socket_ex sock{};
         MK_LOG_TCP_CALL_(sock,ip,port)
         return (tx_slog::log_to_tcp(what,&sock));
      }
      return (false);
   }

   static bool log_to_tcp(tx_alog & what, const std::string & ip, const uint16_t port) noexcept {
      if (port){
         t_txip_socket_ex sock{};
         MK_LOG_TCP_CALL_(sock,ip.c_str(),port)
         return (tx_slog::log_to_tcp(what,&sock));
      }
      return (false);
   }

   static bool log_to_uds(tx_alog & what, const std::string & udspath) noexcept {
      return (tx_slog::log_to_uds(what,udspath.c_str()));
   }
   using tx_flog::clear;

};/* tx_slog */

class tx_log:public tx_slog 
{
protected:
   tools::SBuff            prefix;
   tools::SBuff            encoded_{4096};
   hash_hdr                raw_h_;
   using tx_slog::log_to_tcp;
   using tx_slog::log_to_uds;

   inline
   bool init_() noexcept {
      this->clear();
      this->prefix.fill('0',8);
      this->prefix+="LOG0";
      return (true);//it will never fail
   }

   bool prepare_data_() noexcept  override;

   inline
   bool init_(const char * const ip, const uint16_t port, const char * const udspath) noexcept {
      if(this->init_()){
         if (udspath && udspath[0]){
            this->path=udspath;
            if (this->open()){
               return (true);
            }
            return (false);
         }
         if (ip && ip[0] && port){
            this->txsocket.port=port;
            (void)strlcpy(this->txsocket.ip, ip,sizeof(this->txsocket.ip));
            if (this->open()){
               return (true);
            }
            return (false);
         }
         return (true);

      }
      return (false);
   }

   inline
   void assure_sizes_() noexcept {
      if (this->groups.capacity()<=32){
         this->groups.reserve(32);
      }
      if (this->categories.capacity()<=32){
         this->categories.reserve(32);
      }
      if (this->notifications.capacity()<=32){
         this->notifications.reserve(32);
      }
      if (this->url.capacity()<=1024){
         this->url.reserve(1024);
      }
      if (this->uname.capacity()<=256){
         this->uname.reserve(256);
      }
      if (this->reason.capacity()<=512){
         this->reason.reserve(512);
      }
      if (this->cloud_key.capacity()<=128){
         this->cloud_key.reserve(128);
      }
      if (this->location.capacity()<=512){
         this->location.reserve(512);
      }
      if (this->meta_uname.capacity()<=256){
         this->meta_uname.reserve(256);
      }
   }

   using tx_slog::open_uds;
   using tx_slog::open_tcp;

public:
   cidr::raw_ipaddr_t            ip_addr{};
   size_t                        duration{};
   size_t                        object_size{};
   size_t                        blocking_source{};
   bool                          cached{};
   std::string                   uname{};
   std::string                   url{};
   std::string                   reason{};
   std::string                   cloud_key{};
   std::string                   location{};
   std::string                   policy_name{};
   globals::strings_t            groups{};
   globals::strings_t            categories{};
   globals::strings_t            notifications{};
   ssize_t                       parent_id{-1};
   cidr::raw_ipaddr_t            meta_internal_ip_addr{};
   std::string                   meta_uname{};

   tx_log() noexcept :tx_slog(){
      (void)this->init_();//it will never fail
   }

   explicit tx_log(const bool use_auto_locks) noexcept :tx_slog(use_auto_locks){
      (void)this->init_();//it will never fail
   }

   tx_log(const bool use_auto_locks, const char * const ip, const uint16_t port) : tx_slog(use_auto_locks){
      if(!this->init_(ip,port,nullptr))STD_INIT_ERR_("init failed")
   }

   tx_log(const bool use_auto_locks, const std::string & ip, const uint16_t port) : tx_slog(use_auto_locks){
      if(!this->init_(ip.c_str(),port,nullptr))STD_INIT_ERR_("init failed")
   }

   tx_log(const bool use_auto_locks, const char * const udspath) : tx_slog(use_auto_locks){
      if(!this->init_(nullptr,0,udspath))STD_INIT_ERR_("init failed")
   }

   tx_log(const bool use_auto_locks, const std::string & udspath) : tx_slog(use_auto_locks){
      if(!this->init_(nullptr,0,udspath.c_str()))STD_INIT_ERR_("init failed")
   }

   bool clear() noexcept {

      if(!this->processing_prepare_data){
         this->processing_prepare_data=true;
         this->assure_sizes_();
         this->ip_addr.v6=0;
         this->duration=0;
         this->object_size=0;
         this->blocking_source=0;
         this->cached=false;
         this->uname.clear();
         this->url.clear();
         this->reason.clear();
         this->cloud_key.clear();
         this->location.clear();
         this->policy_name.clear();
         this->groups.clear();
         this->categories.clear();
         this->notifications.clear();
         this->parent_id=-1;
         this->meta_internal_ip_addr.v6=0;
         this->meta_uname.clear();
         this->data_prepared=false;
         tx_slog::clear();
      }
      return (!(this->processing_prepare_data=false));
   }

   bool get_url_normalized(std::string & out) noexcept ;

   inline
   bool open_default() noexcept {
      return (this->open_uds(DEF_LOGGER_UDS_PATH));
   }

   inline
   bool open_default(const bool use_auto_locks) noexcept {
      return (this->open_uds(use_auto_locks,DEF_LOGGER_UDS_PATH));
   }

};/* tx_log */

} //namespace

#endif /* TXLOG_H_ */
