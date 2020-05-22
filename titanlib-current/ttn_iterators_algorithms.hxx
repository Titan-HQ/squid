/*
 * $Id$
 *
 */
#ifndef TTN_ITERATORS_ALGORITHMS_HXX
#define TTN_ITERATORS_ALGORITHMS_HXX

#include "ttn_traits.hxx"

namespace titan_v3 {

   namespace tools{

      namespace iterators{

         namespace algorithms{

            template <typename TVAL, class TOUTBUFF>
            struct basic_iterator{
                  typedef  basic_iterator<TVAL,TOUTBUFF> self_type;
                  explicit basic_iterator(TOUTBUFF & o):out_{o}{}
                  template <typename T=TVAL>
                  typename std::enable_if<std::is_pointer<T>::value && !traits::is_pair<T>::value,self_type&>::type
                  operator=(const T value){(void)((value!=nullptr) && (this->out_<<value));return *this;}

                  template <typename T=TVAL>
                  typename std::enable_if<std::is_pointer<T>::value && traits::is_pair<T>::value,self_type&>::type
                  operator=(const T value){(void)((value!=nullptr) && (this->out_ << value->first <<" "<<value->second));return *this;}

                  template <typename T=TVAL>
                  typename std::enable_if<!std::is_pointer<T>::value && !traits::is_pair<T>::value,self_type&>::type
                  operator=(const T & value){this->out_<<value;return *this;}

                  template <typename T=TVAL>
                  typename std::enable_if<!std::is_pointer<T>::value && traits::is_pair<T>::value,self_type&>::type
                  operator=(const T & value){this->out_ << value->first <<" "<<value->second;return *this;}

               protected:
                  TOUTBUFF & out_;
            };

            template <typename TVAL,class TOUTBUFF>
            struct basic_seperated_iterator:public basic_iterator<TVAL,TOUTBUFF>{
                  typedef  basic_seperated_iterator<TVAL,TOUTBUFF> self_type;
                  basic_seperated_iterator(TOUTBUFF & o,const std::string & s):basic_iterator<TVAL,TOUTBUFF>{o},sep_{std::move(s)}{}

                  template <typename T=TVAL>
                  typename std::enable_if<std::is_pointer<T>::value && !traits::is_pair<T>::value,self_type >::type
                  operator=(const T value){(void)(value!=nullptr && (this->out_<<value));this->out_ << this->sep_;return *this;}

                  template <typename T=TVAL>
                  typename std::enable_if<std::is_pointer<T>::value && traits::is_pair<T>::value,self_type& >::type
                  operator=(const T value){(void)((value!=nullptr) && (this->out_ << value->first <<" "<<value->second));this->out_ << this->sep_;return *this;}

                  template <typename T=TVAL>
                  typename std::enable_if<!std::is_pointer<T>::value && !traits::is_pair<T>::value,self_type & >::type
                  operator=(const T & value){this->out_<<value;this->out_ << this->sep_;return *this;}

                  template <typename T=TVAL>
                  typename std::enable_if<!std::is_pointer<T>::value && traits::is_pair<T>::value,self_type & >::type
                  operator=(const T & value){this->out_ << value->first <<" "<<value->second;this->out_ << this->sep_;return *this;}

               protected:
                  const std::string  sep_{};
            };

            template <typename TVAL,class TOUTBUFF>
            struct basic_seperated_iterator_ols:public basic_seperated_iterator<TVAL,TOUTBUFF>{
               typedef  basic_seperated_iterator_ols<TVAL,TOUTBUFF> self_type;
               using basic_seperated_iterator<TVAL,TOUTBUFF>::basic_seperated_iterator;

               template <typename T=TVAL>
               typename std::enable_if<std::is_pointer<T>::value && !traits::is_pair<T>::value,self_type >::type
               operator=(const T value){(void)((this->added_ && (this->out_ << this->sep_)) || (this->added_=true));(void)(value!=nullptr && (this->out_<<value));return *this;}

               template <typename T=TVAL>
               typename std::enable_if<std::is_pointer<T>::value && traits::is_pair<T>::value,self_type& >::type
               operator=(const T value){(void)((this->added_ && (this->out_ << this->sep_)) || (this->added_=true));(void)((value!=nullptr) && (this->out_ << value->first <<" "<<value->second));return *this;}
               
               template <typename T=TVAL>
               typename std::enable_if<!std::is_pointer<T>::value && !traits::is_pair<T>::value,self_type & >::type
               operator=(const T & value){(void)((this->added_ && (this->out_ << this->sep_)) || (this->added_=true));this->out_<<value;return *this;}
               
               template <typename T=TVAL>
               typename std::enable_if<!std::is_pointer<T>::value && traits::is_pair<T>::value,self_type & >::type
               operator=(const T & value){(void)((this->added_ && (this->out_ << this->sep_)) || (this->added_=true));this->out_ << value->first <<" "<<value->second;return *this;}

            protected:
               bool added_{};
            };

         } /* algorithms namespace */

      } /* iterators namespace */

   } /* tools namespace */

}/* titan_v3 namespace */

#endif /* TTN_ITERATORS_ALGORITHMS_HXX */
