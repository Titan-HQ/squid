/* 
 * $Id$
 * Titan Tools
 */
#include <deque>
#include <exception>
#include <iostream>
#include <regex>
#include <stdexcept>
#include <streambuf>
#include <uuid.h>

#include "ttn_tools.hxx"
#include "TitaxConf.h"

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */

static unsigned int g_SBuff_instances_c = 0;
static unsigned int g_SBuff_instances_d = 0;
unsigned int get_Sbuff_active_instances()
{
    return(g_SBuff_instances_c - g_SBuff_instances_d);
}

////////////////////////////////////////////////////////////////////////////////

TX_INTERNAL_INLINE
bool str2uuid_(   t_uuid * const __restrict out_int,
                  const char * const __restrict in_str  ){


   if (  out_int && 
         in_str && 
         in_str[0]   ){

            alignas( t_uuid ) uuid_t uuid{};
            //(void)zm(&u,sizeof(uuid_t));
            uint32_t status{};
            uuid_from_string( in_str,
                              &uuid,
                              &status  );

            if ( uuid_s_ok==status ){

               //fix misaligned cpy & cast-align
               (void)tx_safe_memcpy(   out_int,
                                       &uuid,
                                       sizeof( t_uuid )  );

               return (true);
            }
   }

   return (false);
}

TX_INTERNAL_INLINE
bool uuid2str_uuid_( char * const __restrict out_str,
                     const size_t out_str_sz,
                     const t_uuid * const __restrict in     ){

   if (  in &&
         out_str &&
         out_str_sz >= GUID_STR_SZ + 1 ){

            alignas( t_uuid ) uuid_t uuid{};

            //fix misaligned cpy & cast-align
            (void)tx_safe_memcpy(   &uuid,
                                    in,
                                    sizeof( t_uuid )  );

            const size_t r = tx_safe_snprintf(  out_str,
                                                out_str_sz,
                                                "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                                                uuid.time_low,
                                                uuid.time_mid,
                                                uuid.time_hi_and_version,
                                                uuid.clock_seq_hi_and_reserved,
                                                uuid.clock_seq_low,
                                                uuid.node[0],
                                                uuid.node[1],
                                                uuid.node[2],
                                                uuid.node[3],
                                                uuid.node[4],
                                                uuid.node[5]   );

            return ( r && r <=  ( GUID_STR_SZ + 1 ) );

   }

   return (false);
}
namespace titan_v3 {

   namespace tools{

         constexpr const char charsets_t::numeric[];

         constexpr const char charsets_t::alpha[];

         constexpr const char charsets_t::cap_alpha[];

         constexpr const char charsets_t::symbols[];

         constexpr const char charsets_t::dns_symbols[];

      SBuff::SBuff(const size_t sz):size(bufsz_){
         if (sz){
            const bool s_=this->grow(sz);
            assert(s_);
         }
         /* DI */
         g_SBuff_instances_c++;
      }
      //------------------------------------------------------------------------------   
      SBuff::SBuff(const std::string & r):size(bufsz_){
         (void)this->store_(r.c_str(),r.size(),true,true);
         /* DI */
         g_SBuff_instances_c++;
      } 
      //------------------------------------------------------------------------------   
      SBuff::SBuff(std::string && r):size(bufsz_){
         (void)this->move_str(std::move(r));
         /* DI */
         g_SBuff_instances_c++;

      }
      //------------------------------------------------------------------------------
      SBuff::SBuff(const char * const r, const size_t r_sz):size(bufsz_){
         (void)this->store_(r,r_sz,true,true);
         /* DI */
         g_SBuff_instances_c++;

      }
      //------------------------------------------------------------------------------
      SBuff::SBuff(const char * const r):size(bufsz_){
         if (r) (void)this->store_(r,strlen(r),true,true);
         /* DI */
         g_SBuff_instances_c++;

      }
      //------------------------------------------------------------------------------
      SBuff::SBuff(const SBuff & r):size(bufsz_){
         (void)this->store_(r.buf(),r.size,true,true);
         /* DI */
         g_SBuff_instances_c++;

      }   
      //------------------------------------------------------------------------------
      SBuff::SBuff(SBuff && r) :size(bufsz_){
         (void)this->move_sb(std::move(r));
         /* DI */
         g_SBuff_instances_c++;
      }
      //------------------------------------------------------------------------------   
      SBuff::~SBuff(){
         (void)this->release();
         /* DI */
         g_SBuff_instances_d++;
      }
      //------------------------------------------------------------------------------
      bool SBuff::fill(const u_char code,const size_t sz){
         size_t l=this->bufsz_;
         if (sz && (l>sz || this->grow_(sz,false)) ) l=sz;
         (void)(this->buf_ && l && ::memset(this->buf_,code,l));
         return true;
      }

      bool SBuff::release(){
         if (this->buf_){
            delete[] this->buf_;
            this->buf_=nullptr;
         }
         this->bufsz_=0;
         return true;
      }

      bool SBuff::clear(size_t sz){
         if (!sz) sz=this->bufsz_;
         return (this->buf_ && sz && zm(this->buf_,sz));
      }

      //------------------------------------------------------------------------------
      /*DO NOT REMOVE*/
      bool USE_PAGESIZE_ROUNDING=true;
      /*DO NOT REMOVE*/
      //------------------------------------------------------------------------------
      char * SBuff::realloc_(const char * const oldb, const size_t dsz,const size_t nsz){
         if (nsz) {
            if ( auto * newb = new char[nsz+1] {} ){
               (void)(oldb && dsz && std::copy_n(oldb, std::min(dsz, nsz), newb));
               if (oldb) delete[] oldb;
               return newb;
            }
         }
         return NULL;
      }
      //------------------------------------------------------------------------------
      bool SBuff::grow_(size_t nsz, const bool ac,const bool include_data,const bool cpy){
         char * nbuf=this->buf_;
         size_t dsz=0;
         if (!cpy && !include_data && bufsz_ && nsz)  nsz*=2;
         if (!cpy && include_data && ((dsz=data_size()) || (dsz=1)) && (nsz+dsz)>=bufsz_) (nsz*=2)+=dsz;
         //this will only grow
         if ((nsz>bufsz_) && ((USE_PAGESIZE_ROUNDING && ( (nsz=((nsz+1/mps_)+1)*mps_) || true) ) || true) && nsz && (nbuf=static_cast<char*>(this->realloc_(this->buf_,this->bufsz_,nsz)))){
             buf_=nbuf;
             bufsz_=nsz;
         }
         assert(nsz && nbuf); //this shouldn't happen, ever!!!
         if (ac) (void)this->clear(nsz+1<bufsz_?nsz+1:0);
         return (true);
      } 
      //------------------------------------------------------------------------------
      char * SBuff::store_(const char * const str,const size_t l,const bool ac, const bool cpy){
         if (this->grow_(l,ac,false,cpy) && this->buf_){
            std::copy_n(str,(this->size>l?l:this->size),this->buf_);
            this->buf_[(this->size>l?l:this->size)]=0;
            return this->buf_;
         }
         throw errors::sbuff_storage_error(); //this shouldn't happen, ever!!
      }
      //------------------------------------------------------------------------------
      bool SBuff::move_sb(SBuff && r){
         if (r.buf_ && r.bufsz_){
            this->release();
            std::swap(this->buf_,r.buf_);
            std::swap(this->bufsz_,r.bufsz_);
            return true;
         }
         if(!this->buf_ || this->clear()) return true;
         throw errors::sbuff_storage_error();
      }

      bool SBuff::move_str(std::string && r){
         if (size_t rsz=r.size()){
            if (this->grow_(rsz,true,false,true) && this->buf_){
               std::string tmp{std::move(r)};
               rsz=(this->size>rsz?rsz:this->size);
               if (tmp.copy(this->buf_,rsz)==rsz) return true; 
            }
         }
         throw errors::sbuff_storage_error();
      }

      //------------------------------------------------------------------------------
      char * SBuff::add_(const char * const str,const size_t l){
         const size_t o_=this->data_size();
         if (this->grow_(l,false,true) && this->buf_){
            std::copy_n(str,l,this->buf_+o_);
            this->buf_[o_+l]=0;
            return (this->buf_);
         }
         throw errors::sbuff_storage_error(); //this shouldn't happen, ever!!!
      }
      
////////////////////////////////////////////////////////////////////////////////

      std::string & ltrim(std::string & str) {
        auto it2 =  std::find_if( str.begin() , str.end() , [](char c_){ return !std::isspace<char>(c_, std::locale::classic() ) ; } );
        str.erase( str.begin() , it2);
        return str;
      }

      std::string & rtrim(std::string & str) {
        auto it1 =  std::find_if( str.rbegin() , str.rend() , [](char c_){ return !std::isspace<char>(c_ , std::locale::classic() ) ; } );
        str.erase( it1.base() , str.end() );
        return str;
      }

      bool isnumeric(std::string & str){
         return (std::find_if( str.begin() , str.end(),[](char c_) { return !std::isdigit(c_); })== str.end());
      }

      struct split_elems{size_t b_;size_t p_;size_t w_;const size_t sep_max;const char * const sep_str; globals::strings_t & out_;};

      size_t split(globals::strings_t & out,const std::string & str, const char * const sep,t_split_lamda lmbd){
         assert(sep && "split failed");
         struct split_elems e_{
            .w_=out.size(),
            .sep_max=strlen(sep),
            .sep_str=sep,
            .out_=out
         };
         #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
         // remove this "swiss-cheese" macro when we finally start building only on the FB11+
             (void)e_.out_.emplace(e_.out_.end());
             (void)std::find_if(str.begin(),str.end(),[lmbd,&e_](const char ch){
                if (ch!=e_.sep_str[e_.p_]){
                   if (!e_.p_){
                      std::string & str_=e_.out_.at(e_.w_);
                      str_+={ch};
                      ++e_.b_;
                      return false;
                   }
                   std::string & str_=e_.out_.at(e_.w_);
                   str_.reserve(str_.size()+e_.p_+1);
                   str_+=std::string{e_.sep_str,e_.p_};
                   str_+={ch};
                   ++e_.b_+=e_.p_;
                   e_.p_=0;
                   return false;
                }
                if (++e_.p_==e_.sep_max){
                   lmbd(e_.out_.at(e_.w_++));e_.p_=e_.b_=0;
                   (void)e_.out_.emplace(e_.out_.end());
                }
                return false; 
             });
         #endif
         if (e_.b_) lmbd(out.at(e_.w_));
         return (out.size());
      }

      bool is_idna_punycode(const std::string & s_){

         #ifndef __clang_analyzer__
         if (s_.size()){
            static std::regex e_{R"((^(xn\-\-)+.*)([[:alnum:]\.\-]+))"};
            return std::regex_match(s_,e_);
         }
         #endif
         return false;
      }

      t_uuid ttn_uuid_t::to_uuid( const char * const __restrict in ){

         if ( in && *in ){
            t_uuid out_;

            if (  ::str2uuid_(   &out_,
                                 in    ) ){
                  return out_;
            }

         }

         return {};
      }


      std::string ttn_uuid_t::to_str( const t_uuid & in ){
            
         char out_[GUID_STR_SZ + 1];

         if (   ::uuid2str_uuid_(  out_,
                                 sizeof( out_ ),
                                 &in               ) ) {

                return out_;
         }

         return {};
      }

   } // namespace tools

} // namespace titan_v3


////////////////////////////////////////////////////////////////////////////////
template <typename TV, size_t vsz=sizeof(t_hash)>
typename std::enable_if<(!std::is_pointer<TV>::value && std::is_arithmetic<TV>::value && vsz==8),bool>::type
capi_hexdump(TV v, char * const __restrict out,const size_t sz){   
   if (vsz<=sz && out){
      using namespace titan_v3;
      using namespace tools::eop;
      using namespace tools::functors;
      CTOR_(std::string,s,hexdump{v,(hexdump_cfg::hdc_print_hex|hexdump_cfg::hdc_swipe_bytes | hexdump_cfg::hdc_pad_with_zeros)});
      if (s.size()){
         (void)::strlcpy(out,s.c_str(),sz);
         return true;
      }
   }
   return false;
}

template <typename TV>
typename std::enable_if<std::is_pointer<TV>::value,bool>::type
capi_hexdump(TV v, const size_t vsz,char * const __restrict out,const size_t sz){   
   if (vsz<=sz && out){
      using namespace titan_v3;
      using namespace tools::eop;
      using namespace tools::functors;
      CTOR_(std::string,s,hexdump{v,vsz});
      if (s.size()){
         //round(vsz/16)*88 (char per line)
         (void)::strlcpy(out,s.c_str(),sz);
         return true;
      }
   }
   return false;
}

bool hexdump_hash(t_hash v, char * const __restrict out,const size_t sz){
   return capi_hexdump(v,out,sz);
}

bool hexdump_buff(const char * const raw, const size_t rsz, char * const __restrict out,const size_t osz){
   return capi_hexdump(raw,rsz,out,osz);
}
bool ttn_uuid_str2uuid_int(   t_uuid * const __restrict out_,
                              const char * const __restrict in_   ){

      return str2uuid_( out_, in_ );
}


bool ttn_uuid_int2str_uuid(   char * const __restrict out_,
                              const size_t out_sz_,
                              t_uuid * const __restrict in_ ){

      return uuid2str_uuid_(  out_, out_sz_, in_ );
}

