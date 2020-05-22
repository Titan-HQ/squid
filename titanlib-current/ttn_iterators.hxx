/*
 * $Id$
 *
 */
#ifndef TTN_ITERATORS_HXX
#define TTN_ITERATORS_HXX
#include <iterator>
#include "ttn_traits.hxx"
#include "ttn_iterators_algorithms.hxx"
namespace titan_v3 {

    namespace tools{

        namespace iterators{

            template <  typename TC,
                        class TOUT,
                        template<typename...> class TA=algorithms::basic_iterator,
                        class TChar = char,
                        class TTraits = std::char_traits<TChar>,
                        typename TALG = TA<typename TC::value_type,TOUT>            >
            struct basic_container_iterator : std::iterator<std::output_iterator_tag, void, void, void, void>, TALG {

                static_assert(  traits::is_container<TC>::value,
                                "basic_container_value_iterator requires an stl container type" );

                using TVal=typename TC::value_type;
                using char_type=TChar;
                using traits_type=TTraits;
                using TALG::operator=;
                template <typename... Args>
                explicit basic_container_iterator(Args&&... args) : TALG{std::forward<Args>(args)...}
                                                                    {}

                basic_container_iterator& operator*() noexcept      {return *this;}

                basic_container_iterator& operator++() noexcept     {return *this;}

                basic_container_iterator& operator++(int) noexcept  {return *this;}

            }; /* basic_container_iterator */

            template <typename B, typename E>
            struct sub_range_wrapper {

                B b;
                E e;

            }; /* sub_range_wrapper */
         
            template <typename B, typename E>
            constexpr 
            sub_range_wrapper<B,E> sub_range ( B && b, E && e) noexcept {

                return { std::forward<B>(b),  std::forward<E>(e) }; 
            }

            template < template<typename,typename> class W, typename B, typename E>
            constexpr
            typename std::enable_if<std::is_same< W<B,E>, sub_range_wrapper<B,E> >::value, B>::type
            begin ( W<B,E>  w) noexcept {

                return w.b;
            }

            template < template<typename,typename> class W, typename B, typename E>
            constexpr
            typename std::enable_if<std::is_same< W<B,E>, sub_range_wrapper<B,E> >::value, E>::type
            end ( W<B,E> w ) noexcept {

                return w.e;
            }

            template <typename T>
            struct const_range_t {

                T b;
                T e;

                constexpr
                const_range_t( T b_, T e_ ) noexcept :  b{ b_ },
                                                        e{ e_ }
                                                        {}

                constexpr
                const_range_t( T e_ ) noexcept :    b{ 0 },
                                                    e{ e_ }
                                                    {}

                struct const_iterator {

                   using iterator_category = std::forward_iterator_tag;
                   using value_type = T;
                   using difference_type = T;
                   using pointer = const T *;
                   using self_type = const const_iterator &;
                   using reference = const T&;

                   constexpr
                   const_iterator ( self_type i_ ) noexcept :   max{  i_.max   },
                                                                pos{  i_.pos   }
                                                                {}

                   constexpr 
                   const_iterator(   const T m_, 
                                     const T p_  ) noexcept :   max{ m_ },
                                                                pos{ p_ }
                                                                {} 

                   constexpr 
                   reference operator * () const noexcept {

                      return { pos };

                   }

                   inline 
                   self_type operator ++ () noexcept {

                      ++this->pos;

                      return { *this };

                   }


                   inline
                   self_type operator ++ (int) noexcept {

                      const_iterator t{ *this };

                      this->pos++;

                      return t;

                   }

                   constexpr 
                   bool operator == ( self_type rhs) const noexcept {

                      return  this->pos == rhs.pos;

                   }

                   constexpr 
                   bool operator != ( self_type rhs) const noexcept {

                      return !( *this == rhs );

                   }

                   protected:
                      const T max{};

                      T pos{}; 

                }; /* const_iterator */

                constexpr
                const_iterator begin() const noexcept {

                   return { e, b };

                }

                constexpr
                const_iterator end() const noexcept {

                   return { e, e };

                }

            }; /* const_range_t */

            template <typename T>
            constexpr
            const_range_t<T> const_range ( T c ) noexcept {

                return { c }; 

            }

            template <typename B, typename C >
            constexpr
            const_range_t<C> const_range ( B b, C c ) noexcept {

                return {    static_cast<C>(b),

                            static_cast<C>(b)+c };

            }

      } /* iterators namespace */

   } /* tools namespace */

} /* titan_v3 namespace */

#endif /* TTN_ITERATORS_HXX */

/* vim: set ts=4 sw=4 et : */
