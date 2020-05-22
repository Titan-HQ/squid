
/*
 * $Id$
 *
 */
#pragma once 

#include "ttn_traits.hxx"

namespace titan_v3
{

    namespace tools
    {

        namespace algorithms
        {

            template <typename T>
            constexpr 
            bool cpp_WITHIN_( T min_, T max_, T value_ ) noexcept
            {
                return (!((value_<min_) || (max_<value_)));
            }

            template <typename T>
            constexpr 
            bool cpp_UWITHIN_( T max_, T value_ ) noexcept
            {
                return (!((max_)<(value_)));
            }

            /**
            * @template erase_if
            * @abstract applies a predicate (p) to all of the elements of a container (c)
            * and erases these elements that satisfy the predicate (p) 
            * @param c [in] a container e.g. std::map
            * @param p [in] a predicate e.g. lambda [](std::map<>::value_type & p)->bool{}
            * @note even though this method is similar to the remove_if it is not a 1-to-1 replacement
            */
            template< typename C, typename P >
            inline void erase_if( C& c, const P & p ) noexcept {
            for ( auto i = c.begin(); i != c.end(); (p(*i)?(i = c.erase(i)):++i))
                ; /*empty body*/
            }


            template <typename C, typename P >
            inline auto exec_if( C c, P p )
                        -> typename std::enable_if<! (std::is_same< decltype( c(nullptr) ), void>::value ), decltype( c(nullptr)  )>::type
            {
                auto pstat = p();

                if ( pstat.second ) {

                    return std::move(c( pstat.first ));
                }

                return {};
            }

            template <typename C, typename P >
            inline auto exec_if( C c, P p ) 
                        -> typename std::enable_if<std::is_same<decltype( c(nullptr)  ), void>::value, void>::type 

            {
                auto pstat = p();

                if ( pstat.second ) {

                    c( pstat.first );
                }
            }


            template <typename S>
            using is_in_status = tools::status_pair_t<S>;

            template <typename S, typename I, typename ret_type=is_in_status<I&> >
            constexpr ret_type is_in( const S & s, I & i) noexcept 
            {
                if ( s == i ) {

                    return ret_type::success(i);
                }

                return ret_type::failure(i);
            }

            template <typename S, typename I, typename ret_type=is_in_status<I&>, typename ... Is>
            constexpr ret_type is_in(const S & s, I & i, Is && ... is) noexcept 
            {
                /* potentialy could be replaced with the ... (fold expression) */
                auto st = is_in( s, i );

                if ( st.second ) {

                    return ret_type::success(st.first);
                }

                return is_in( s, std::forward<Is>(is)... );
            }

        } /* algorithms namespace */

    } /* tools namespace */

}/* titan_v3 namespace */


/* vim: set ts=4 sw=4 et : */

