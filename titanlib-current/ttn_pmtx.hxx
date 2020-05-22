/**
 * $Id$
 */
#ifndef TTN_PMTX
#define TTN_PMTX

#include <iostream>
#include <tuple>
#include <memory>
#include <pthread.h>
#include "global.h"
#include "ttn_errors.hxx"

#ifndef CONEXP
   #if (__clang_major__ >= 4 || __clang_minor__ > 4)
      #define CONEXP constexpr
   #else
      #define CONEXP
   #endif
#endif

namespace titan_v3 
{
    namespace tools 
    {

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wunknown-pragmas"
#pragma clang diagnostic ignored "-Wunused-member-function"
#pragma clang diagnostic ignored "-Wunused-template"

        namespace 
        {
            /* 
             *  The thread safety detector is unable to trace mutex/lock aliases
             *  hence the scoped guard is the only supported pattern 
             *  for the pthread wrappers 
             *  no std::lock_guard or deferred locks 
             *  Similar to the std::scoped_lock (c++17)
             */

            /**
             * @template scoped_wrapper_t 
             * @abstract abstract template 
             */
            template <typename PTMX, bool SH=false, bool TRY=false >
            struct scoped_wrapper_t;

            /**
             * @template base_wrapper_t
             * @abstract base template type for all the wrappers
             */
            template < typename T, bool SH=false, bool TRY=false >
            struct base_wrapper_t
            {
                using wrapper_type = T;

                constexpr static bool mode_shared{ SH };

                constexpr static bool mode_try{ TRY };

                CONEXP explicit 
                base_wrapper_t( T * const m )   noexcept
                                                :
                                                    mtx_{m}
                {
                        /* empty */
                }

                CONEXP explicit 
                base_wrapper_t( T & m ) noexcept
                                        :
                                           mtx_{&m}
                {
                        /* empty */
                }


                base_wrapper_t(const base_wrapper_t&)=delete;

                base_wrapper_t(base_wrapper_t &&) = delete;

                base_wrapper_t& operator=(const base_wrapper_t&)=delete;

                base_wrapper_t() = delete;

                protected:
                    T * const mtx_{};

            }; /* base_wrapper_t */

            /**
             * @struct base_lock_t
             * @abstract base type for all the locks
            */
            struct base_lock_t
            {
                base_lock_t() = default;

                base_lock_t( base_lock_t && ) = default ;

                virtual ~base_lock_t()
                {
                    /* empty */
                }

            }; /* base_lock_t */

        }; /* anonymous namespace */

        /**
         *  WRAPPERS 
         */

        /**
         * @template scoped_wrapper_t<pthread_rwlock_t,true,[false]>
         * @abstract template specialization for the pthread_rwlock_t in the shared and non-try mode
         */
        template <>
        struct TSA_CAP_SCOPED_MTX   scoped_wrapper_t<pthread_rwlock_t,true>
                                    :
                                        base_wrapper_t<pthread_rwlock_t,true>
        {

            CONEXP explicit 
            scoped_wrapper_t( pthread_rwlock_t & m )   noexcept
                                                       TSA_SH_AQ(m)
                                                       :
                                                            base_wrapper_t{m}
            {
                tsa_rd_lock(mtx_);
            }

            ~scoped_wrapper_t() TSA_RE_ALL()
            {
                tsa_rd_unlock(mtx_);
            }

        }; /* scoped_wrapper_t<pthread_rwlock_t,true,[false]> */

        /**
         * @type rd_scpped_wrapper_t 
         * @abstract acquires a shared read lock on the read-write lock
         */
        using rd_scoped_wrapper_t = scoped_wrapper_t<pthread_rwlock_t,true>;

        /**
         * @template scoped_wrapper_t<pthread_rwlock_t,[false],[false]>
         * @abstract template specialization for the pthread_rwlock_t in the exclusive and non-try mode
         */
        template <>
        struct TSA_CAP_SCOPED_MTX   scoped_wrapper_t<pthread_rwlock_t>
                                    :
                                        base_wrapper_t<pthread_rwlock_t>
        {

            CONEXP explicit 
            scoped_wrapper_t(   pthread_rwlock_t & m    )   noexcept 
                                                            TSA_AQ(m)
                                                            :
                                                                base_wrapper_t{m} 
            {
                tsa_wr_lock(mtx_);
            }

            ~scoped_wrapper_t() TSA_RE()
            {
                tsa_wr_unlock( mtx_ );
            }

        }; /* scoped_wrapper_t<pthread_rwlock_t,[false],[false]> */

        /**
         * @type wr_scoped_wrapper_t 
         * @abstract acquires an exclusive lock on the read-write lock
         */
        using wr_scoped_wrapper_t = scoped_wrapper_t<pthread_rwlock_t>;

        /**
         * @template scoped_wrapper_t<pthread_mutex_t,[false],[false]>
         * @abstract template specialization for the pthread_mutex_t in the exclusive and non-try mode
         */
        template <>
        struct TSA_CAP_SCOPED_MTX   scoped_wrapper_t<pthread_mutex_t>
                                    :
                                        base_wrapper_t<pthread_mutex_t>
        {

            CONEXP explicit 
            scoped_wrapper_t(   pthread_mutex_t & m )   noexcept 
                                                        TSA_AQ(m)
                                                        :
                                                            base_wrapper_t{m} 
            {
                tsa_lock( mtx_ );
            }

            ~scoped_wrapper_t() TSA_RE()
            {
                tsa_unlock( mtx_ );
            }

        }; /* scoped_wrapper_t<pthread_mutex_t,[false],[false]> */

        /**
         * @type mx_scoped_wrapper_t 
         * @abstract acquires an exclusive lock on the mutex
         */
        using mx_scoped_wrapper_t = scoped_wrapper_t<pthread_mutex_t>;

        /**
         * @template scoped_wrapper_t<pthread_mutex_t,false,true>
         * @abstract template specialization for the pthread_mutex_t in the exclusive and try mode
         * @warning on failure in acquiring the lock, it will throw an exception in the ctor
        */
        template <>
        struct TSA_CAP_SCOPED_MTX   scoped_wrapper_t<pthread_mutex_t,false,true>
                                    :
                                        base_wrapper_t<pthread_mutex_t,false,true>
        {

            CONEXP explicit 
            scoped_wrapper_t(   pthread_mutex_t & m )   noexcept(false) 
                                                        TSA_TRY_AQ(true,m)
                                                        :
                                                            base_wrapper_t{m} 
            {
                if ( ! tsa_try_lock( mtx_ ) ) {

                    throw errors::lock_error("failed locking scoped_wrapper_t<pthread_mutex_t,false,true>");
                }

                /* pthread_yield / std::this_thread::yield(); */
            }

            ~scoped_wrapper_t() TSA_TRY_RE()
            {
                tsa_try_unlock( mtx_ );
            }

        }; /* scoped_wrapper_t<pthread_mutex_t,false,true>  */

        /**
         * @template try_scoped_wrapper_t<T>
         * @abstract tries to acquire an exclusive lock on the T lock
         */
        template<typename T>
        using try_scoped_wrapper_t = scoped_wrapper_t<T,false,true>;

        /**
         * @template scoped_wrapper_t<pthread_rwlock_t,true,true>
         * @abstract template specialization for the pthread_rwlock_t in the shared and try mode
         * @warning on failure in acquiring the lock, it will throw an exception in the ctor
         */
        template <>
        struct TSA_CAP_SCOPED_MTX   scoped_wrapper_t<pthread_rwlock_t,true,true>
                                    :
                                        base_wrapper_t<pthread_rwlock_t,true,true>
        {

            CONEXP explicit 
            scoped_wrapper_t(   pthread_rwlock_t & m    )   noexcept(false) 
                                                            TSA_TRY_SH_AQ(true,m)
                                                            :
                                                                base_wrapper_t{m} 
            {
                if ( ! tsa_try_rd_lock( mtx_ ) ) {

                    throw errors::lock_error("failed locking scoped_wrapper_t<pthread_rwlock_t,true,true>");
                }

                /* pthread_yield / std::this_thread::yield(); */
            }

            ~scoped_wrapper_t() TSA_RE_ALL()
            {
                tsa_rd_unlock( mtx_ );
            }

        }; /* scoped_wrapper_t<pthread_mutex_t,false,true>  */

        /**
         * @template try_sh_scoped_wrapper_t<T>
         * @abstract tries to acquire a shared lock on the T lock
         */
        template<typename T>
        using try_sh_scoped_wrapper_t = scoped_wrapper_t<T,true,true>;

        /**
         *  LOCKS 
         */

        /**
         * @template base_managed_scoped_lock_t<bool,Ls...>
         * @abstract base template type for all managed and scoped locks in the exclusive mode
         * @warning on failure in acquiring the lock, it might throw an exception in the ctor
         * @note all specialized constructors could be replaced with a single templated constructor 
         * with param pack but unfortunately, currently, there is no way to unpack the param pack 
         * inside the language extensions (attr)
         */
        template<bool SHARED, typename ...Ls >
        struct TSA_CAP_SCOPED_MTX base_managed_scoped_lock_t final : base_lock_t
        {
            using locks_type = typename std::conditional<   SHARED, 
                                                            std::tuple< try_sh_scoped_wrapper_t<Ls>...>,
                                                            std::tuple< try_scoped_wrapper_t<Ls>... >
                                                        >::type;
            template <typename L1 >
            CONEXP
            base_managed_scoped_lock_t( L1 & l1 )   noexcept(false)
                                                    TSA_AQ( l1 ) 
                                                    :
                                                        locks{ l1 }
            {
                /* empty */
            }

            template <typename L1, typename L2 >
            CONEXP
            base_managed_scoped_lock_t( L1 & l1,
                                        L2 & l2 )   noexcept(false)
                                                    TSA_AQ( l1, l2 )
                                                    :
                                                        locks{ l1, l2 }
            {
                /* empty */
            }

            template <typename L1, typename L2, typename L3 >
            CONEXP
            base_managed_scoped_lock_t( L1 & l1,
                                        L2 & l2,
                                        L3 & l3 )   noexcept(false) 
                                                    TSA_AQ( l1, l2, l3)
                                                    :
                                                        locks{ l1, l2, l3 }
            {
                /* empty */
            }

            ~base_managed_scoped_lock_t() TSA_RE()
            {
                /* empty */
            }

            protected:
                locks_type locks;

        }; /* base_managed_scoped_lock_t<bool,Ls...> */

        /**
         * @template managed_scoped_lock_t
         * @abstract template for the managed_scoped_lock_t
         * @warning on failure in acquiring the lock, it might throw an exception in the ctor
         * @note all specialized constructors could be replaced with a single templated constructor 
         * with param pack but unfortunately, currently, there is no way to unpack the param pack 
         * inside the language extensions (attr)
         */
        template <bool SHARED>
        struct TSA_CAP_SCOPED_MTX managed_scoped_lock_t
        {

            template<typename ...Ls>
            using base_t = base_managed_scoped_lock_t<SHARED,Ls...>;


            template <typename L1, typename L2, typename L3 >
            CONEXP
            managed_scoped_lock_t(  L1 & l1, 
                                    L2 & l2, 
                                    L3 & l3 )   noexcept( false ) 
                                                TSA_AQ( l1, l2, l3 )
                                                : 
                                                    lock{ new base_t<L1,L2,L3>{ l1, l2, l3 }  }
            {
                /* empty */
            }

            template <typename L1, typename L2 >
            CONEXP
            managed_scoped_lock_t(  L1 & l1,
                                    L2 & l2 )   noexcept(false) 
                                                TSA_AQ( l1, l2 )
                                                :
                                                    lock{ new base_t<L1,L2>{ l1, l2 }  }
            {
                /* empty */
            }

            template <typename L1 >
            CONEXP
            managed_scoped_lock_t(  L1 & l1 )   noexcept(false) 
                                                TSA_AQ( l1 ) 
                                                : 
                                                    lock{ new base_t<L1>{ l1 } }
            {
                /* empty */
            }

            ~managed_scoped_lock_t() TSA_RE()
            {
                /* empty */
            }


            protected:
                std::unique_ptr<base_lock_t> lock{};

        }; /* managed_scoped_lock_t<bool> */

        /**
         * @type scoped_lock_t
         * @abstract tries to acquire an exclusive lock
         */
        using scoped_lock_t = managed_scoped_lock_t<false>;

        /**
         * @type sh_scoped_lock_t
         * @abstract tries to acquire an sh lock
         */
        using sh_scoped_lock_t = managed_scoped_lock_t<true>;

#pragma clang diagnostic pop

    }; /* namespace */

}; /* namespace */

#endif /* TTN_PMTX */
/* vim: set ts=4 sw=4 et : */
