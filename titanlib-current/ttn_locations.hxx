/**
 * $Id$
 */

#ifndef TTN_LOCATIONS_HXX
#define TTN_LOCATIONS_HXX

#include "db_pg.hxx"
#include "ttn_tools.hxx"
#include "ttn_eops.hxx"
#include "ttn_traits.hxx"
#include "ttn_crtps.hxx"
#include "ttn_cidr.hxx"
#include "ttn_cfg.hxx"
#include <utility>
#include <set>
#include <unordered_set>
#include <sys/param.h>

/* C++17 might simplify nested namespace definition */
namespace titan_v3{ namespace locations {

    using namespace titan_v3::tools;
    using namespace titan_v3::tools::crtps;
    using namespace titan_v3::cidr;

    constexpr unassigned_t   UNASSIGNED{};
    /**
    * @struct location_t
    * @abstract provides the data structure that represents 
    * the location with its association to the user
    */ 
    struct location_t
    {
        enum class types{
           none=    0x00, /* unasigned yet   */
           db=      0x02, /* loaded from db  */
           wada=    0x04, /* used with wada  */
           session= 0x08, /* ip sessions     */
           any=     0x80, /* any type */
        };

        const cidr_t &                  cidr{cidr_}; //const ???

        /**
         * Since this type is used with the std::set and since the std::set (c++11 and up) 
         * iterators returns the read-only objects (const_iterators : to preserve order)
         * had to make other members of the location_t type mutable.
         * If and when this bahaviour changes then we can remove this type specifier:
         * http://std.dkuug.dk/jtc1/sc22/wg21/docs/lwg-defects.html#103
         *
         */
        mutable std::string             name{};
        /* make ttn_uuid_t for wada */
        mutable titan_v3::tools::ttn_uuid_t  uuid{};

        mutable user_id_t               user_id{ UNASSIGNED };

        mutable policy_id_t             policy_id{ UNASSIGNED };
        /* use chrono */
        mutable time_t                  timestamp{};

        mutable std::string             tag{};

        mutable types                   type{};

        mutable bool                    terminal_server{};

        location_t() noexcept = default;

        location_t(const cidr_t & c) noexcept :cidr_{c}
        {
            /* empty */
        }

        location_t(const std::string & tg) noexcept :tag{tg}
        {
            /* empty */
        }

        template <typename U>
        constexpr
        location_t( cidr_t c,
                    const U u,
                    const types t = {},
                    const char * const n = {},
                    const policy_id_t p = UNASSIGNED,
                    const bool ts = {}                  ) : name{ ( n ?: "" ) },
                                                            user_id{ static_cast<user_id_t>( u ) },
                                                            policy_id{ p },
                                                            type{ t },
                                                            cidr_{ std::move( c ) }
         {

            switch ( type ) {

               /* only a db type can also be a terminal_server so we should throw an exception */
               case types::db:      terminal_server = ts;         break;

               case types::session: timestamp = time(nullptr);
               [[clang::fallthrough]];

               default:{
                     if ( ts ) {

                        throw errors::location_error{ "locations of the DB type only "
                                                      "can also be treated as terminal servers " };
                     }
               }break;
            }
         }

        template <typename TG, typename U, typename = typename std::enable_if< tools::traits::is_string<TG>::value >::type >
        constexpr
        location_t( TG && tg,
                    const U u,
                    const types t = {},
                    const char * const n = {},
                    const policy_id_t p = UNASSIGNED ) noexcept :   name{ ( n ?: "" ) },
                                                                    user_id{ static_cast<user_id_t>( u ) },
                                                                    policy_id{ p },
                                                                    tag{ std::forward<TG>(tg) },
                                                                    type{ t }
        {
            /* empty */
        }


        template <typename U>
        constexpr
        location_t( cidr_t c,
                    const U u,
                    const tools::ttn_uuid_t & uuid_,
                    const types t = {},
                    const char * const n = {},
                    const policy_id_t p = UNASSIGNED ) noexcept :   name{ ( n ?: "" ) },
                                                                    uuid{uuid_},
                                                                    user_id{ static_cast<user_id_t>( u ) },
                                                                    policy_id{ p },
                                                                    type{ t },
                                                                    cidr_{ std::move( c ) }
        {

           if (t==types::session)
               timestamp=time(nullptr);
        }

        /* move ctor */
        location_t(location_t && l) noexcept :  name{ std::move(l.name) },
                                                uuid{ std::move(l.uuid) },
                                                user_id{ std::move(l.user_id) },
                                                policy_id{ std::move(l.policy_id) },
                                                timestamp{ std::move(l.timestamp) },
                                                tag{ std::move(l.tag) },
                                                type{ std::move(l.type) },
                                                terminal_server{ std::move(l.terminal_server) },
                                                cidr_{ std::move(l.cidr_) }
        {
            /* empty */
        }

        /* cpy ctor */
        location_t(const location_t & l) noexcept : name{ l.name },
                                                    uuid{ l.uuid },
                                                    user_id{ l.user_id },
                                                    policy_id{ l.policy_id },
                                                    timestamp{ l.timestamp },
                                                    tag{ l.tag },
                                                    type{ l.type },
                                                    terminal_server{ l.terminal_server },
                                                    cidr_{ l.cidr_ }
        {
            /* empty */
        }

        /**
         * @operator mov assign 
         */
        inline location_t & operator=(location_t && l) noexcept 
        {
            #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 
            // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                this->name = std::move(l.name);
                this->uuid = std::move(l.uuid);
                this->user_id = std::move(l.user_id);
                this->policy_id = std::move(l.policy_id);
                this->timestamp = std::move(l.timestamp);
                this->tag = std::move(l.tag);
                this->type = std::move(l.type);
                this->terminal_server = std::move(l.terminal_server);
                this->cidr_ = std::move(l.cidr_);

             #endif
            return *this;
        }

        /**
         * @operator cpy assign 
         */
        inline location_t & operator=(const location_t & l) noexcept 
        {
            this->name = l.name;
            this->uuid = l.uuid;
            this->user_id = l.user_id;
            this->policy_id = l.policy_id;
            this->timestamp = l.timestamp;
            this->tag = l.tag;
            this->type = l.type;
            this->terminal_server = l.terminal_server;
            this->cidr_ = l.cidr_;
            return *this;
        }

        virtual ~location_t() = default;

        /**
         * @operator implicit typecast to const cidr_t&
         */
        inline operator const cidr_t&() const noexcept 
        {
            return this->cidr;
        }

        /**
         * @operator implicit typecast to const raw_ipaddr_t&
         */
        inline operator const raw_ipaddr_t&() const noexcept 
        {
            return this->cidr;
        }

        inline std::string& get_tag() const noexcept 
        {
            return this->tag;
        }

        /**
         * @fn reset_ttl
         * @abstract reset ttl
         * see above explanation about the std::set
         */
        inline void reset_ttl() const noexcept 
        {
            this->timestamp = 0;
            this->type = location_t::types::none;
        }

        inline void reset_uuid() const noexcept
        {
            this->uuid.zero();
        }

        /**
         * @fn reset
         * @abstract reset ttl and user id 
         * see above explanation about the std::set
         */
        inline void reset() const noexcept 
        {
            this->reset_ttl();
            this->user_id = UNASSIGNED;
            this->policy_id = UNASSIGNED;
            this->reset_uuid();
        }

        /**
         * @fn zero
         * @abstract zero the whole object
         * see above explanation about the std::set
         */
        inline void zero() noexcept
        {
            this->reset();
            this->name.clear();
            checks::reset(this->cidr_);
        }

        friend 
        std::ostream& operator<<(   std::ostream & out,
                                    const location_t & obj  ) noexcept 
        { 

            using namespace titan_v3::tools::eop;

            return (    out<<"name: " << obj.name
                        <<", addr: " << obj.cidr
                        <<std::dec
                        <<", usr: " << obj.user_id
                        <<", policy: " << obj.policy_id
                        <<", time: " << obj.timestamp
                        <<", type: " << obj.type 
                        <<", uuid: " << obj.uuid
                        <<", tag: " << obj.tag
                        <<", terminal server: " << obj.terminal_server
                    );
        }

        protected:
            cidr_t            cidr_{};

    }; /* location_t */

    inline 
    std::ostream& operator<<(   std::ostream & out,
                                const location_t::types & obj   ) noexcept 
    {
        return (out<<tools::eop::to_string(obj));
    }

    /**
     * @template compare_locations_fntor
     * @abstract implements the compare functor (less op) used e.g. with the std::set. 
     * It compares two location_t objects by comparing their cidr fields. 
     * - network to network
     * - host to network
     * - network to host
     * @Warning Currently this comparer assumes that all locations are non-overlapping / not nested
     * see the allow_nested arg
     */
    template<bool allow_nested=false>
    struct compare_locations_fntor{

        inline 
        bool operator() (   const location_t & lhs,
                            const location_t & rhs  ) const noexcept {

            using namespace std::rel_ops;

            const auto lhs_tag_empty = lhs.get_tag().empty();

            const auto rhs_tag_empty = rhs.get_tag().empty();

            if ( lhs_tag_empty && rhs_tag_empty ) {

               /* host 2 host */
               if (    static_cast<const cidr_t &>( lhs ) ==

                       static_cast<const cidr_t &>( rhs )      ){

                           return false;
               }

               if ( checks::is_host( rhs )  ||

                    checks::is_host( lhs )      ){

                    if ( checks::belongs_to( lhs, rhs ) ){

                        return allow_nested; //true if nested ??

                    } else {

                        if ( !checks::is_host( lhs ) ){

                            return  ( checks::get_broadcast( lhs ) < checks::get_network( rhs ) );

                        } else {

                            return  ( checks::get_network( lhs ) < checks::get_network( rhs ) );

                        }

                    }

               } else {

                    if ( checks::belongs_to( lhs, rhs ) ){

                        return allow_nested; //true if nested ??

                    } else {

                        return ( checks::get_broadcast( lhs ) < checks::get_network( rhs ) );

                    }

               }

               return false;

            }
            else if (lhs_tag_empty) {

                return true;

            }
            else if (rhs_tag_empty) {

                return false;

            }
            else {

                return (lhs.get_tag().compare(rhs.get_tag()) > 0);

            }

        }

    }; /* compare_locations_fntor */

    /* alias */
    using is_less=compare_locations_fntor</* default */>;

    /**
     * @abstract box type alias
     * todo: 
     * in future we could optimize it more by differencing between hosts and networks
     * for hosts lookups we can use the unordered_set / hashtable
     *
     */
    struct locations_type:flat_lock_box<std::set<location_t,is_less>>{

        const cfg::TCFGInfo & cfg;

        locations_type(const cfg::TCFGInfo & c) noexcept :cfg{c}{}

        /**
         * @fn count
         * @abstract it will count locations by type if a type is any then it is an eq call to the size()
         * @param t[in] location_t::types
         * @return count of locations by type 
         * @note Thread-Safe method
         */
        inline size_t count( const location_t::types t ) const noexcept {

            if ( location_t::types::any != t ) {

                std::lock_guard<std::mutex> mlock{lock_};

                const auto ctx =  std::count_if(    cbegin(), 
                                                    cend(), 
                                                    [t]( const location_t & l ) {

                                                        return ( t == l.type );

                                                });

                return (    ctx > 0                     ?   

                            static_cast<size_t>(ctx)    :

                            0                               );

            }

            return flat_lock_box::count(); /* will auto lock */
        }

        /**
         * @fn locate
         * @abstract it will locate a location by cidr, it will return even the invalid location
         * @param c [in] cidr
         * @return naked pointer to the location or nullptr
         * @warning this method is not thread safe, use find instead
         *
         */
        inline 
        location_t * locate(const cidr_t & c) noexcept {

            /* non locking find */
            const auto & l = box_.find(c);

            if ( l != box_.end() ){

                if ( !l->timestamp ){

                    return const_cast<location_t *>(&(*l));

                }

                /* we might need to call TITAX_CONF_LOCK(); here */
                if ( !cfg.ip_session        && 

                     !cfg.intercept_login       ){

                    l->reset();

                    return const_cast<location_t *>(&(*l));

                }

                /* use chrono & steady timers */
                const time_t current_time{ time(nullptr) };
                if ( l->timestamp < current_time - static_cast<time_t>(cfg.ip_session_ttl) ) {

                    l->reset();
                    /* expired */
                    return const_cast<location_t *>(&(*l));

                }

                if (cfg.ac_ttl_slide){

                    l->timestamp= current_time;

                }

                return const_cast<location_t *>(&(*l));

            }

            return {};
        }


        /**
         * @fn locate
         * @abstract it will locate a location by a string tag
         * @param c [in] tag
         * @return naked pointer to the location or nullptr
         * @warning this method is not thread safe, use find instead
         *
         */
        inline 
        location_t * locate(const std::string& tag) const noexcept {

            /* non locking find */
            const auto & l = box_.find(tag);

            if ( l != box_.end() ){

                return const_cast<location_t *>(&(*l));

            }

            return {};
        }


        /* reset ops:
         *   op  || one by type | one of any | all by type | all of any  |
         * ======||=============|============|=============|=============|
         * reset || reset/erase |    erase   | reset/erase | reset/erase |
         *       ||     1       |            |     1       |     2       |
         * ------||-------------|------------|-------------|-------------|
         *
         *  1) if entry is a network it has to be erased
         *  2) two stage reset : 
         *  if entry is set but not network then reset else erase
         */

        /**
         * @fn reset
         * @abstract reset one by type without locking
         * @warning non Thread-Safe
         */
        template <location_t::types t=location_t::types::any>
        inline
        bool reset_unlock(cidr_t r_loc){

            auto * l=locate(r_loc);

            if ( l ){

                if ( t == l->type ){

                    if ( ! checks::is_network(r_loc)) {

                        l->reset();

                    } else {

                        l=nullptr;

                        box_.erase(r_loc);

                    }

                    return true;

                }

            }

            return false;
        }

        /**
         * @fn reset
         * @abstract reset one by type
         * @note Thread-Safe method
         */
        template <location_t::types t=location_t::types::any>
        inline
        bool reset(cidr_t r_loc){

            std::lock_guard<std::mutex> mlock{lock_};

            auto * l=locate(r_loc);

            if ( l ){

                if ( t == l->type ){

                    if ( ! checks::is_network(r_loc)) {

                        l->reset();

                    } else {

                        l=nullptr;

                        box_.erase(r_loc);

                    }

                    return true;

                }

            }

            return false;
        }

        /** 
         * @fn reset
         * @abstract reset all by type 
         * @note Thread-Safe method
         */
        template <location_t::types t=location_t::types::any>
        inline 
        void reset()
        {
            std::lock_guard<std::mutex> mlock{lock_};

            tools::algorithms::erase_if(    box_,
                                            []( const value_type & p )
                                            {
                                                if ( t == p.type ){

                                                    if ( ! checks::is_network(p.cidr)) {

                                                        p.reset();

                                                        return false;

                                                    }

                                                    return true;

                                                }

                                                return false;

                                            }   );
        }

        /**
         * @fn reset
         * @abstract reset all by type
         * @note Thread-Safe method
         */
        template <location_t::types t=location_t::types::wada>
        inline
        void reset( raw_addr_uset_t & removed)
        {
            std::lock_guard<std::mutex> mlock{lock_};

            tools::algorithms::erase_if(    box_,
                                            [&removed]( const value_type & p )
                                            {
                                                if ( t == p.type ){

                                                    if ( ! checks::is_network(p.cidr)) {
                                                        removed.insert(p.cidr.addr);

                                                        p.reset();

                                                        return false;

                                                    }

                                                    return true;

                                                }

                                                return false;

                                            }   );
        }

    }; /* locations_type */

    /**
     * @fn reset_unlock
     * @abstract reset_unlock one of any type
     * @warning non Thread-Safe method
     */
    template<>
    inline
        bool locations_type::reset_unlock<location_t::types::any>(cidr_t r_loc){

        auto lb = box_.lower_bound(r_loc);

        if ( lb != box_.end() ){

            auto ub = box_.upper_bound(r_loc);

            box_.erase(lb,ub);

            return true;

        }

        return false;
    }

    /**
     * @fn reset
     * @abstract reset one of any type
     * @note Thread-Safe method
     */
    template<>
    inline
        bool locations_type::reset<location_t::types::any>(cidr_t r_loc){

        std::lock_guard<std::mutex> mlock{lock_};

        auto lb = box_.lower_bound(r_loc);

        if ( lb != box_.end() ){

            auto ub = box_.upper_bound(r_loc);

            box_.erase(lb,ub);

            return true;

        }

        return false;
    }

    /**
     * @fn reset
     * @abstract reset all of any type
     * @note Thread-Safe method
     */
    template <>
    inline 
    void locations_type::reset<location_t::types::any>()
    {
        std::lock_guard<std::mutex> mlock{lock_};

        tools::algorithms::erase_if(    box_,
                                        []( const value_type & p )
                                        {
                                            /* first stage */
                                            if (    p.type!=location_t::types::none     &&

                                                    ! checks::is_network(p.cidr)            ){

                                                p.reset();

                                                return false;

                                            }

                                            /* second stage */
                                            return true;

                                        }   );
    }


    /**
     * @template custom_print_op 
     * @abstract Thread-Safe custom_print_op functor
     */
    template<class CRTP>
    struct custom_out_op_type{
        using out_tag=custom_out_op_type;
        protected:
            template<typename D=CRTP>
            std::ostream& operator()(   std::ostream & out,
                                        const D & obj       ) const noexcept {

                auto & box = traits::selfie<D,out_tag>(obj).box;

                std::lock_guard<std::mutex> lock{box.lock_};

                out<<"locations:"<<std::endl;

                for ( const auto & l : box ) {

                    out<<">>"<<l<<"\n";

                }

                return (out);
            }

    }; /* custom_out_op_type */

    using add_pair_t=status_pair_t<location_t>;

    using update_or_add_pair_t=status_pair_t<location_t*>;

    /**
     * @template add_location_op 
     * @abstract Thread-Safe add_location_op functor
     */
    template<class CRTP>
    struct add_location_op_type{
        using add_tag = add_location_op_type;

        /**
         * @warning NON Thread-Safe method
         */
        template <typename D=CRTP>
        inline 
        update_or_add_pair_t update_or_add( location_t in_loc ) noexcept {

            auto & box = traits::selfie<D>(this)->box;

            if (!in_loc.get_tag().empty()) {
               auto s = box.box_.insert(std::move(in_loc));

               if (s.second)
                   return update_or_add_pair_t::success( const_cast<location_t *>(&(*s.first)) );
               else {
                   return update_or_add_pair_t::failure();
               }

            }


            if (   checks::is_valid(in_loc)                     &&

                   location_t::types::any > in_loc.type         &&


                   /* locations of session type 
                    * are allowed only if 
                    * cfg.ip_session is on 
                    * or cfg.intercept_login is on
                    */
                   ( location_t::types::session != in_loc.type  ||

                     box.cfg.ip_session                         ||

                     box.cfg.intercept_login                  ) &&

                    /* type of addr to location type
                     *
                     *   type  ||  Net  |  Host | INVALID | 
                     *  =======||=======|=======|=========|
                     *      D  ||   1   |   1   |    0    |
                     *  -------||-------|-------|---------|
                     *      W  ||   0   |   1   |    0    |
                     *  -------||-------|-------|---------|
                     *      S  ||   0   |   1   |    0    |
                     *  -------||-------|-------|---------|
                     *      N  ||   1   |   1   |    0    |
                     *  -------||-------|-------|---------|
                     */
                    (   location_t::types::db==in_loc.type      ||

                        checks::is_host(in_loc.cidr)                )  ){

                        if ( auto * loc = box.locate(in_loc.cidr) ){

                            /* update only if
                             *   op     || eq | gt | lt |
                             * ---------||----|----|----|
                             *  L and R ||  1 |  0 |  0 |
                             *
                             */ 

                            if ( loc->cidr == in_loc.cidr ){

                                /* precedence of location types (persistency wins) :
                                 *
                                 *  L << R ||  D  |  W  |  S  |  N  | 
                                 *  =======||=====|=====|=====|=====|
                                 *      D  ||  D  |  D  |  D  |  D  |
                                 *  -------||-----|-----|-----|-----|
                                 *      W  ||  D  |  W  |  W  |  W  |
                                 *  -------||-----|-----|-----|-----|
                                 *      S  ||  D  |  W  |  S  |  S  |
                                 *  -------||-----|-----|-----|-----|
                                 *      N  ||  D  |  W  |  S  |  N  |
                                 *  -------||-----|-----|-----|-----|
                                 */
                                if  (   loc->type == location_t::types::none        ||

                                        (   location_t::types::none < in_loc.type   &&

                                            /* assuming db type is smaller than wada type */
                                            loc->type >= in_loc.type                    ) ){

                                            //update 
                                            *loc = std::move(in_loc);
                                            return update_or_add_pair_t::success( loc );
                                }

                                /* override restrictions */
                                return update_or_add_pair_t::failure();

                            }

                            /* collision */
                            return update_or_add_pair_t::failure(loc);
                        }

                        // or add (insert)
                        auto s = box.box_.insert(std::move(in_loc));

                        if (s.second)
                            return update_or_add_pair_t::success( const_cast<location_t *>(&(*s.first)) );

                        /* this collision shouldn't occur */ 
                        return update_or_add_pair_t::failure( const_cast<location_t *>(&(*s.first)) ); 
            }

            /* general error */
            return update_or_add_pair_t::failure();
        }

        /**
         * @abstract first it will call the update_or_add method, 
         * but if unsuccessful it will try to resolve any conflicts with the pre existing entries
         * @warning NON Thread-Safe method
         */
        template<typename D=CRTP>
        inline 
        bool load( location_t r_loc ) noexcept {

            const auto & l_loc=this->update_or_add(r_loc);

            if ( l_loc.second ){

                return true;

            }

            if ( l_loc.first ){
                /* conflict resolution */
                auto & box = traits::selfie<D>(this)->box;

                return (    box.reset_unlock(r_loc)                    &&

                            this->update_or_add(r_loc).second       );
            }

            return false;

        }

        protected:
            /**
             * @fn add
             * @abstract this add operator is thread safe 
             * @return add_pair_t : second (status), first (value/copy)
             * @note Thread-Safe method
             */
            template<typename D=CRTP, class... Args >
            add_pair_t operator()( Args&&... args ) noexcept {

                auto & box = traits::selfie<D>(this)->box;

                std::lock_guard<std::mutex> mlock{box.lock_};

                const auto & loc = this->update_or_add( { std::forward<Args>(args)... } /* <- implicit constructor */  );

                if ( loc.second ){

                    return add_pair_t::success(*(loc.first)); //copy 

                }

                return add_pair_t::failure();

            }

    }; /* add_location_op */

    using find_pair_t=status_pair_t<location_t>;

    /**
     * @template find_location_op_type  
     * @abstract Thread-Safe find_location_op_type  functor
     */
    template <class CRTP>
    struct find_location_op_type{
        using find_tag=find_location_op_type;

        /**
         * @note Thread-Safe method
         */
        template<typename D=CRTP>
        inline 
        bool is_known(cidr_t c, std::string tag = "") noexcept {

            auto & box = traits::selfie<D>(this)->box;

            std::lock_guard<std::mutex> mlock{box.lock_};

            if  ( !tag.empty() ){

                bool known{};

                std::tie(known,std::ignore) = get_location(tag);

                if ( known ){

                    return true;

                }

            }

            bool known{};

            std::tie(known,std::ignore) = get_location(c);

            return known;

        }

        protected:
            using location_ret_t = std::tuple<const bool,const location_t *const>;
 
            /**
             * @warning NON Thread-Safe method
             */
            template <typename T, typename D=CRTP>
            location_ret_t get_location(T && t) noexcept {

                auto & box = traits::selfie<D>(this)->box;

                const auto * const l_ = box.locate(std::forward<T>(t));

                const bool k_{  l_                                              &&

                                (   l_->user_id                                 ||

                                    tools::ttn_uuid_t::is_valid( l_->uuid )     ||

                                    l_->terminal_server                             ) };
                return std::forward_as_tuple( k_, l_ );

            }

            /**
             * @fn find
             * @param c[in] cidr_t
             * @abstract this find operator is thread safe 
             * @return find_pair_t : second (status), first (value/copy)
             */
            template<typename D=CRTP>
            inline 
            find_pair_t operator()(const cidr_t & c) noexcept {

                auto & box = traits::selfie<D>(this)->box;

                std::lock_guard<std::mutex> mlock{box.lock_};

                const location_t * loc{};
            
                bool known{};

                std::tie( known, loc ) = get_location(c);

                return (    known                           ?

                            find_pair_t::success( *loc )    :

                            find_pair_t::failure()              );
            }

           /* @fn find
            * @param tag[in] Virtual location tag
            * @abstract this find operator is thread safe
            * @return find_pair_t : second (status), first (value/copy)
            */
           template<typename D=CRTP>
           inline 
           find_pair_t operator()(const std::string & tag) noexcept {

               auto & box = traits::selfie<D>(this)->box;

               std::lock_guard<std::mutex> mlock{box.lock_};

                const location_t * loc{};
            
                bool known{};

                std::tie( known, loc ) = get_location(tag);

                return (    known                           ?

                            find_pair_t::success( *loc )    :

                            find_pair_t::failure()              );

           }

    }; /* find_location_op_type */

    struct locations_box_type : box_type<   locations_type,
                                            add_location_op_type,
                                            clear_op_type,
                                            custom_out_op_type,
                                            find_location_op_type,
                                            size_op_type,
                                            count_op_type
                                        >{

        using box_type::box_type;
        //expose internal lock
        std::mutex & lock{box.lock_};

        /**
         * @warning NON Thread-Safe method
         */
        inline 
        location_t * locate( const cidr_t & c) noexcept { 

            return this->box.locate(c);

        }

        /**
         * @warning NON Thread-Safe method
         */
        inline 
        location_t * locate(const std::string & tag) const  noexcept {

            return this->box.locate(tag);

        }

        /**
         * @note Thread-Safe method
         */
        bool reload(PGconn* const) noexcept; 

        /**
         * @note Thread-Safe method
         */
        bool save4wada( const char * const,
                        const bool          ) noexcept ;

        /**
         * @note Thread-Safe method
         */
        template<location_t::types t=location_t::types::any,typename... Args> 
        auto reset(Args&&... args) -> decltype (box.reset<t>(args...)){

            return box.reset<t>(std::forward< Args >(args)...);

        }

        /**
         * @warning NON Thread-Safe method
         */
        template<typename... Args>
        inline 
        auto locate(Args&&... args) noexcept -> decltype (box.locate(args...)){

            return box.locate(std::forward< Args >(args)...);

        }

    }; /* locations_box_type */

}/* locations namespace */

} /* titan_v3 namespace */

#endif /* TTN_LOCATIONS_HXX */  
/* vim: set ts=4 sw=4 et : */


