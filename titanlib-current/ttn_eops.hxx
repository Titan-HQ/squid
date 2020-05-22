/*
 * $Id$
 *
 */
#ifndef TTN_EOPS_HXX
#define TTN_EOPS_HXX
#include "ttn_traits.hxx"
#include "ttn_functors_templates.hxx"

namespace titan_v3 {
   
   namespace tools{   
      /**
       * @namespace  enum operations
       * @abstract   usage e.g. using namespace ::eop;
       */
      namespace eop{

         /**
          * @template a function template underlying_type
          * @return underlying type
          */

         template <class TBASE,typename TUNDERL=typename std::underlying_type<TBASE>::type> 
         struct underlying_type {typedef TUNDERL type;};

         /**
          * @template function template to_underlying
          * @abstract returns value of v_ as a value of the underlying type 
          * @param v_ : enum based value
          * @return underlying type
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type>
         constexpr TUNDERL to_underlying(TBASE v_) noexcept {
            return static_cast<TUNDERL>(v_);
         }

         /**
          * @template function template to_enum 
          * @abstract type casting  
          * @param v_ : value based on the underlying type
          * @return : enum based value
          */
         template<typename TBASE, typename TVAL>
         constexpr TBASE to_enum(TVAL  v_) noexcept {
            return static_cast<TBASE>(static_cast<typename underlying_type<TBASE>::type>(v_));
         }

         /**
          * @template   operator template : less then
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : bool
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type >
         constexpr bool operator< (TBASE l_,TUNDERL r_) noexcept {
            return (l_<to_enum<TBASE>( r_ ));
         }

         /**
          * @template   operator template : greater then
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : bool
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type >
         constexpr bool operator> (TBASE l_,TUNDERL r_) noexcept {
            return (l_>to_enum<TBASE>(r_));
         }

         /**
          * @template   operator template : equal to
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : bool
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type >
         constexpr bool operator== (TBASE l_,TUNDERL r_) noexcept {
            return (l_==to_enum<TBASE>(r_));
         }

         /**
          * @template   operator template : not equal to
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : bool
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type >
         constexpr bool operator!= (TBASE l_,TUNDERL r_) noexcept {
            return (l_!=to_enum<TBASE>(r_));
         }  

         /**
          * @template   operator template : less or equal to 
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : bool
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type >
         constexpr bool operator<= (TBASE l_,TUNDERL r_) noexcept {
            return (l_<=to_enum<TBASE>(r_));
         }

         /**
          * @template   operator template : greater or equal to 
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : bool
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type >
         constexpr bool operator>= (TBASE l_,TUNDERL r_) noexcept {
            return (l_>=to_enum<TBASE>(r_));
         }

         /**
          * @template   operator template : bitwise OR 
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : enum based value
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type >
         constexpr typename std::enable_if<std::is_enum<TBASE>::value,TBASE>::type
         operator| (TBASE l_,TUNDERL r_) noexcept {
            return static_cast<TBASE>(static_cast<TUNDERL>(l_) | r_);
         }

         /**
          * @template   operator template : bitwise OR 
          * @param l_ : enum based value
          * @param r_ : enum based value
          * @return : enum based value
          */
         template<typename TBASE,typename TUNDERL=typename underlying_type<TBASE>::type >
         constexpr typename std::enable_if<std::is_enum<TBASE>::value,TBASE>::type
         operator |(TBASE l_,TBASE r_) noexcept {
            return static_cast<TBASE>(l_ | static_cast<TUNDERL>(r_));
         }

         /**
          * @template   operator template : bitwise AND
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : enum based value
          */
         template<typename TBASE,typename TUNDERL=typename std::underlying_type<TBASE>::type >
         constexpr typename std::enable_if<std::is_enum<TBASE>::value,TBASE>::type
         operator& (TBASE l_,TUNDERL r_) noexcept {
            return static_cast<TBASE>(static_cast<TUNDERL>(l_) & r_);
         }

         /**
          * @template   operator template : bitwise AND
          * @param l_ : enum based value
          * @param r_ : enum based value
          * @return  : enum based value
          */
         template<typename TBASE,typename TUNDERL=typename std::underlying_type<TBASE>::type >
         constexpr typename std::enable_if<std::is_enum<TBASE>::value,TBASE>::type
         operator &(TBASE l_, TBASE r_) noexcept {
            return static_cast<TBASE>(l_ & static_cast<TUNDERL>(r_));
         }
         
         /**
          * @template   operator template : bitwise XOR
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : enum based value
          */
         template<typename TBASE,typename TUNDERL=typename std::underlying_type<TBASE>::type >
         constexpr TBASE operator^ (TBASE l_,TUNDERL r_) noexcept {
            return static_cast<TBASE>(to_underlying(l_) ^ r_);
         }

         /**
          * @template   operator template : bitwise XOR
          * @param l_ : enum based value
          * @param r_ : enum based value
          * @return : enum based value
          */
         template<typename TBASE>
         constexpr TBASE operator ^(TBASE l_,TBASE r_) noexcept {
            return static_cast<TBASE>(l_ ^ to_underlying(r_));
         }

         /**
          * @template   operator template : bitwise assignment OR
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : enum based value
          */
         template<typename TBASE,typename TUNDERL=typename std::underlying_type<TBASE>::type >
         constexpr TBASE & operator |=(TBASE & l_,TUNDERL r_) noexcept {
            return (l_=(l_ | r_));
         }

         /**
          * @template   operator template : bitwise assignment OR
          * @param l_ : enum based value
          * @param r_ : enum based value
          * @return : enum based value
          */

         template<typename TBASE>
         constexpr TBASE & operator |=(TBASE & l_,TBASE r_) noexcept {
            return (l_=(l_ | r_));
         }

         /**
          * @template   operator template : bitwise assignment AND
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : enum based value
          */
         template<typename TBASE,typename TUNDERL=typename std::underlying_type<TBASE>::type >
         constexpr TBASE & operator &=(TBASE & l_,TUNDERL r_) noexcept {
            return (l_=(l_ & r_));
         }

         /**
          * @template   operator template : bitwise assignment AND
          * @param l_ : enum based value 
          * @param r_ : enum based value
          * @return : enum based value
          */
         template<typename TBASE>
         constexpr TBASE & operator &=(TBASE & l_,TBASE r_) noexcept {
            return (l_=(l_ & r_));
         }

         /**
          * @template   operator template : bitwise assignment XOR
          * @param l_ : enum based value
          * @param r_ : underlying type based value
          * @return : enum based value
          */
         template<typename TBASE,typename TUNDERL=typename std::underlying_type<TBASE>::type >
         constexpr TBASE & operator ^=(TBASE & l_,TUNDERL r_) noexcept {
            return (l_=(l_ ^ r_));
         } 

         /**
          * @template   operator template: bitwise assignment XOR
          * @param l_ : enum based value
          * @param r_ : enum based value
          * @return : enum based value
          */
         template<typename TBASE>
         constexpr TBASE & operator ^=(TBASE & l_,TBASE r_) noexcept {
            return (l_=(l_ & r_));
         }

         /**
          * @template   function template : to_string
          * @abstract   maps the enum based value to its textual representation (the enum labels) 
          * @param v_ : enum based value
          * @param f_ : functoR based or lambda based
          * @return 
          */
         template<typename TBASE, typename TMAP_FUNC>
         inline std::string to_string(TBASE v_,TMAP_FUNC f_) noexcept {
            return f_(v_);
         }

         /**
          * @template   function template : as_bool
          * @abstract    
          * @param v_ : enum based value
          * @param f_ : functoR based or lambda based
          * @return 
          */
         template<typename TBASE>
         constexpr typename std::enable_if<std::is_enum<TBASE>::value,bool>::type
         as_bool( TBASE r_) noexcept {
            return static_cast<bool>(r_);
         }

         /**
          * @template   operator template: formatted output
          * @param out_ : std::ostream (e.g. std::cout)
          * @param r_ : enum based value
          * @return : std::ostream
          */
         template<typename TBASE,typename std::enable_if<std::is_enum<TBASE>::value>::type* = nullptr>
         constexpr std::ostream &operator<<(std::ostream& out_, TBASE r_) noexcept {
            out_<<to_underlying(r_);
            return (out_);
         }

         /**
          * @template   functoR template : as_string 
          * @abstract   maps the enum based value to its textual representation (the enum labels) 
          * @param BASE : enum type
          * @param TSUBFUNCOR : subfunctor type for a function of f(enum v)->std::string
          * @return std::string
          */
         template<typename TBASE,class TSUBFUNCOR>
         class as_string{
            protected:
                TSUBFUNCOR f_;
            public:
               inline std::string operator()(TBASE v_) const noexcept {
                  return this->f_(v_);
               }
         };

      } /* eop namespace */

   } /* tools namespace */

} /* titan_v3 namespace */


#endif /* TTN_EOPS_HXX */

