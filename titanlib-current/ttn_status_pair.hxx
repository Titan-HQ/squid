/**
 * $Id$
 *
 */
#ifndef TTN_STATUS_PAIR_HXX
#define TTN_STATUS_PAIR_HXX
#include <utility>

namespace titan_v3{

   namespace tools{
     /**
      * @template status_pair
      * @abstract it is a syntactic sugar for the std::pair 
      * that is used to return  status of execution with value 
      * @return:
      *     - first : value
      *     - second : bool state
      *
      */
      template<class T>
      struct status_pair_t: std::pair<T,const bool>{

        /**
         * @abstract ctor
         */
         template <typename V>
         status_pair_t(V && v,const bool s ) noexcept :std::pair<T,const bool>{std::forward<V>(v),s}{}

        /**
         * @abstract ctor
         */
         template <typename V>
         explicit status_pair_t(V && v ) noexcept :std::pair<T,const bool>{std::forward<V>(v) }{}

        /**
         * @fn success
         * @abstract returns a status(second) with the given value (first)
         */
         template <typename V>
         static constexpr status_pair_t success(V&&v) noexcept {
            return {std::forward<V>(v),true};
         }

        /**
         * @fn failure
         * @abstract returns a status(second) with the given value (first)
         */
         template <typename V>
         static constexpr status_pair_t failure(V&&v) noexcept {
            return{std::forward<V>(v),false};
         }

        /**
         * @fn failure
         * @abstract returns a status(second) with the default/empty value (first)
         * @note this method might be disabled if T is of a reference type
         */
         template <typename V=T>
         static constexpr 
         typename std::enable_if<!std::is_reference<V>::value,status_pair_t>::type
         failure() noexcept {
            return{V{},false};
         }

      }; /* status_pair_t */

   } /* tools namespace */

}/* titan_v3 namespace */

#endif /* TTN_STATUS_PAIR_HXX */

