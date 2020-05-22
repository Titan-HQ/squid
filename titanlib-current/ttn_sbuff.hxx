/*
 * $Id$
 *
 */
#ifndef TTN_SBUFF_HXX
#define TTN_SBUFF_HXX
#include <sstream> 

#include "ttn_traits.hxx"
#include "ttn_errors.hxx"

namespace titan_v3 {

   namespace tools{ 

      extern bool USE_PAGESIZE_ROUNDING;
      /**
       * @class   SBuff
       * @abstract    data buffer 
       */
      class SBuff{
      protected:
         char * buf_{};
         size_t bufsz_{};
         const size_t mps_{static_cast<size_t>(::getpagesize())};
         bool grow_(size_t, const bool ac=true,const bool include_data=false,const bool cpy=false);
         char * store_(const char *const,const size_t,const bool ac=true, const bool cpy=false);
         bool move_sb(SBuff &&);
         bool move_str(std::string &&);
         char * add_(const char * const,const size_t);
         char * realloc_(const char * const, const size_t,const size_t);
      public:
         const size_t & size;
         explicit SBuff(const size_t sz=0);
         explicit SBuff(const char * const);
         explicit SBuff(const char * const, const size_t);
         explicit SBuff(const std::string &);
         explicit SBuff(std::string &&);
         SBuff(const SBuff &);
         SBuff(SBuff &&);
         virtual ~SBuff();
         char * buf() const{
            return (this->buf_);
         }
         inline const char *c_str() const { 
            return this->buf_;
         }
         char * buf(const size_t nsz,const bool ac=true){
            (void)this->grow_(nsz,ac);
            return (this->buf());
         }
         size_t data_size()const{
            return (!this->empty()?strnlen(this->buf_,this->bufsz_):0);
         }
         bool empty()const{
            return (!bufsz_ && !buf_);
         }
         bool clear(size_t sz=0);
         bool grow(size_t nsz, const bool ac=true){
            return (this->grow_(nsz,ac));
         }
         bool release();
         bool fill(const u_char code=0,const size_t sz=0);

         bool move(SBuff && r_){
            return (this->move_sb(std::move(r_)));
         }

         bool move(std::string && r_){
            return (this->move_str(std::move(r_)));
         }
//------------------------------------------------------------------------------

         template <typename TVAL>
         typename std::enable_if<(!std::is_pointer<TVAL>::value && std::is_same<typename std::remove_const<TVAL>::type,SBuff>::value),char*>::type
         store(TVAL & r,const bool cpy){
            return (this->store_(r.buf(),r.size,true,cpy));
         }

         template <typename TVAL>
         typename std::enable_if<(!std::is_pointer<TVAL>::value && std::is_same<typename std::remove_const<TVAL>::type,std::string>::value),char*>::type
         store(TVAL & r,const bool ac){
            return (this->store_(r.c_str(),r.size(),ac));
         }

         template <typename TVAL>
         typename std::enable_if<(std::is_pointer<TVAL>::value && (std::is_same<TVAL,SBuff*>::value || std::is_same<TVAL,const SBuff*>::value)),char*>::type
         store(TVAL r,const bool cpy){
            return (this->store_(r->buf(),r->size,true,cpy));
         }

         template <typename TVAL>
         typename std::enable_if<(std::is_pointer<TVAL>::value && (std::is_same<TVAL,char*>::value||std::is_same<TVAL,const char*>::value)),char*>::type
         store(TVAL r,const bool ac){
            assert(r && "store failed");
            return (this->store_(r,strlen(r),ac));
         }

//------------------------------------------------------------------------------
         template <typename TVAL>
         typename std::enable_if<(!std::is_pointer<TVAL>::value && std::is_same<typename std::remove_const<TVAL>::type,std::string>::value),int>::type
         compare(const TVAL & s)const{
            return this->compare(s.c_str());
         }

         template <typename TVAL>
         typename std::enable_if<(!std::is_pointer<TVAL>::value && std::is_same<typename std::remove_const<TVAL>::type,SBuff>::value),int>::type
         compare(const TVAL & s)const{
            if (s.c_str() && this->c_str())
               return strncmp(this->c_str(),s.c_str(),this->data_size());
            throw errors::nullptr_error();
         }

         template <typename TVAL>
         typename std::enable_if<(std::is_pointer<TVAL>::value && (std::is_same<TVAL,char*>::value||std::is_same<TVAL,const char*>::value)),int>::type
         compare(TVAL s)const{
            if (s && this->c_str())
               return strncmp(this->c_str(),s,this->data_size());
            throw errors::nullptr_error();
         }

//------------------------------------------------------------------------------
         template <typename TVAL>
         typename std::enable_if<(std::is_pointer<TVAL>::value && (std::is_same<TVAL,char*>::value||std::is_same<TVAL,const char*>::value)),char*>::type
         add(TVAL s, const size_t l){
            return (this->add_(s,l));
         }

         template <typename TVAL>
         typename std::enable_if<(std::is_pointer<TVAL>::value && (std::is_same<TVAL,char*>::value||std::is_same<TVAL,const char*>::value)),char*>::type
         add(TVAL s){
            assert(s && "add failed");
            return (this->add_(s,strlen(s)));
         }

         template <typename TVAL>
         typename std::enable_if<(!std::is_pointer<TVAL>::value && std::is_same<typename std::remove_const<TVAL>::type,std::string>::value),char*>::type
         add(const TVAL & s){
            return (this->add_(s.c_str(), s.size()));
         }

         template <typename TVAL>
         typename std::enable_if<(!std::is_pointer<TVAL>::value && std::is_same<typename std::remove_const<TVAL>::type,SBuff>::value),char*>::type
         add(const TVAL & s){
            return (this->add_(s.buf(),s.size));
         }

//------------------------------------------------------------------------------

         template <typename TVAL>
         SBuff & operator=(TVAL & str){
            (void)this->store(str,true);
            return (*this);
         }

         SBuff & operator= (const SBuff & r){
            (void)this->store(r,true);
            return (*this);
         }

         SBuff & operator=(SBuff&& r) {
            (void)this->move_sb(std::move(r));
            return *this;
         }

         SBuff & operator= (const std::string & r){
            (void)this->store(r,true);
            return (*this);
         }

         SBuff & operator=(std::string && r) {
            (void)this->move_str(std::move(r));
            return *this;
         }

         operator std::string () const {
            return std::string{this->buf_,this->data_size()};
         }

         explicit operator size_t () const {
            return (this->size);
         }

         template <typename TVAL>
         SBuff & operator+=(TVAL & str){
            (void)this->add(str);
            return (*this);
         }

         friend SBuff operator+(const SBuff& l, const SBuff& r){
            //accurate/precise fusion of two buffers
            SBuff n{l.size+r.size};
            n=l;
            n+=r;
            return (n);
         }

         template<typename TRIGHT>
         friend bool operator== (const SBuff &l,const TRIGHT & r){
            return (!l.compare(r));
         }

         template<typename TRIGHT> 
         friend bool operator!= (const SBuff &l,const  TRIGHT & r){
            return !(l==r);
         }

         template <typename TITEM>
         friend  typename std::enable_if<(!std::is_pointer<TITEM>::value && std::is_same<typename std::remove_const<TITEM>::type,SBuff>::value ),std::ostream & >::type
         operator<<(std::ostream & out, TITEM & sb){
            if (sb.buf()){
               out<<sb.buf();
            }
            return (out);
         }

         template <typename TITEM>
         friend  typename std::enable_if<(std::is_pointer<TITEM>::value && (std::is_same<TITEM,SBuff*>::value || std::is_same<TITEM,const SBuff*>::value)),std::ostream&>::type
         operator<<(std::ostream & out, TITEM sb){
            if (sb && sb->buf()){
               out<<sb->buf();
               return (out);
            }
            return (out);
         }
      };

   } /* tools namespace */
   
} /* titan_v3 namespace */

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */
unsigned int get_Sbuff_active_instances();

#endif /* TTN_SBUFF_HXX */

