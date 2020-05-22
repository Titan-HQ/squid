/**
 * $Id$
 */

#ifndef TTN_GENERATOR_HXX
#define TTN_GENERATOR_HXX

#include <random>
#include <tuple>
#include "ttn_iterators.hxx"

namespace titan_v3{

    namespace tools{


        struct charsets_t{
            /* todo add full asci table */
            enum class type{
                none        =   0x00,
                numeric     =   0x01,
                alpha       =   ( numeric << 1          ), 
                alp_num     =   ( numeric | alpha       ),
                cap_alpha   =   ( alpha << 1            ),
                cap_alp_num =   ( alp_num | cap_alpha   ),
                symbols     =   ( cap_alpha << 1        ),
                all         =   ( cap_alp_num | symbols ),

                /* full compliance with the rfc1035 & rfc2782 */
                rfc1035     =   ( symbols << 1          ),

                ascii       =   ( rfc1035 << 1          )

            };

            constexpr static  
            const char numeric[] =      "0123456789";

            constexpr static 
            const char alpha[] =        "abcdefghijklmnopqrstuvwxyz";

            constexpr static 
            const char cap_alpha[] =    "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

            constexpr static 
            const char symbols[] =      " <,>./?;:'\"\\|[{]}`~!@#$%^&*()_-=+";

            constexpr static
            const char dns_symbols[] =  "-_";

            constexpr static 
            size_t size( const charsets_t::type t ) noexcept {

                    using namespace titan_v3::tools::eop;

                    constexpr size_t cap_alp_num_sz {   sizeof(numeric)-1   +
                                                        sizeof(alpha)-1     +
                                                        sizeof(cap_alpha)-1     };

                    switch ( t ){

                        case charsets_t::type::none:        return 0;

                        case charsets_t::type::numeric:     return sizeof(numeric)-1;

                        case charsets_t::type::alpha:       return sizeof(alpha)-1;

                        case charsets_t::type::cap_alpha:   return sizeof(cap_alpha)-1;

                        case charsets_t::type::symbols:     return sizeof(symbols)-1;

                        case charsets_t::type::rfc1035:     return (    cap_alp_num_sz          +
                                                                        sizeof(dns_symbols)-1       );

                        default :                           return (    size( t & charsets_t::type::numeric     )   +
                                                                        size( t & charsets_t::type::alpha       )   +
                                                                        size( t & charsets_t::type::cap_alpha   )   +
                                                                        size( t & charsets_t::type::symbols     )       );
                    }

            }

            /* todo: this could be recursive */
            template< const charsets_t::type t, typename R=std::array< char,charsets_t::size(t) > >
            constexpr static
            R get() noexcept {

                R c{ };

                auto add_cap_alp_num=[ &c ]{

                    char * const cdata{c.data()};

                    strlcat( cdata, charsets_t::alpha, c.max_size() );

                    strlcat( cdata, charsets_t::cap_alpha, c.max_size() );

                    strlcat( cdata, charsets_t::numeric, c.max_size() );

                };

                char * const cdata{c.data()};

                switch ( t ){

                    case charsets_t::type::rfc1035:{

                        add_cap_alp_num();
                        strlcat(cdata,charsets_t::dns_symbols,c.max_size());

                    } break;

                    default: {

                        using namespace titan_v3::tools::eop;

                        if ( as_bool( t & charsets_t::type::numeric ) ) {

                            strlcat(cdata,charsets_t::numeric,c.max_size());
                        }

                        if ( as_bool( t & charsets_t::type::alpha ) ) {

                            strlcat(cdata,charsets_t::alpha,c.max_size());
                        }

                        if ( as_bool( t & charsets_t::type::cap_alpha ) ){

                            strlcat(cdata,charsets_t::cap_alpha,c.max_size());
                        }

                        if ( as_bool( t & charsets_t::type::symbols ) ){

                            strlcat(cdata,charsets_t::symbols,c.max_size());
                        }

                    }break;

                }

                return c;

            }

        }; /* charsets_t */


        template < typename C, typename R=std::string >
        struct gen_base_t{

            inline
            R operator()() const noexcept
            {

                const C * const o = static_cast<const C*const>(this);
                return o->generate_();
            }

            inline
            operator R () const noexcept 
            {

                const C * const o = static_cast<const C*const>(this);
                return o->generate_();
            }

            friend std::ostream &operator << (  std::ostream& o_,
                                                const gen_base_t<C> & b_  ) noexcept 
            {

                return o_<< b_();
            }

            friend std::ostream &operator << (  std::ostream& o_,
                                                gen_base_t<C> && b_ ) noexcept 
            {

                return o_<< b_();
            }

        };

        template <const charsets_t::type ctype = charsets_t::type::all>
        struct generator_fn:gen_base_t< generator_fn<ctype> >{

            using base_type = gen_base_t<generator_fn<ctype> >;

            using base_type::operator();

            friend base_type;

            mutable std::mt19937_64 rnd{ std::random_device{}() };

            constexpr explicit
            generator_fn( const size_t s=0 ) noexcept : size_{ s },
                                                        charset_( charsets_t::get<ctype>() ),
                                                        dist_{ 0, charsets_t::size(ctype)-2 }
                                                        {}
            inline
            std::string operator()(const size_t sz) noexcept {

                return this->generate_(sz);
            }

            protected:
                const size_t size_{};

                const decltype( charsets_t::get<ctype>() ) charset_;

                mutable std::uniform_int_distribution<size_t> dist_;

                inline 
                std::string generate_(const size_t sz_=0) const noexcept 
                {

                    const size_t sz{ (sz_?:this->size_) };

                    std::string s_( sz, 0 );

                    const auto & c_=this->charset_;

                    auto & d_=this->dist_;

                    auto & r_=this->rnd;

                    std::generate_n( s_.begin(), sz, [&]() -> char { 

                        return c_[ d_( r_ ) ];

                    } );

                    return s_;

                }

        }; /* generator_fn */ 

        template </*ascii*/>
        struct generator_fn<charsets_t::type::ascii>:gen_base_t< generator_fn<charsets_t::type::ascii> >{

            using base_type = gen_base_t<generator_fn<charsets_t::type::ascii> >;

            using base_type::operator();

            friend base_type;

            mutable std::mt19937_64 rnd{ std::random_device{}() };

            explicit
            generator_fn( const size_t s=0 ) noexcept : size_{ s },
                                                        dist_{ 0x00, 0xff }
                                                        {}
            inline
            std::string operator()(const size_t sz) noexcept {

                return this->generate_(sz);
            }

            protected:
                const size_t size_{};
                mutable std::uniform_int_distribution<size_t> dist_;

                inline 
                std::string generate_(const size_t sz_=0) const noexcept
                {

                    const size_t sz{ (sz_?:this->size_) };

                    std::string s_( sz , 0 );

                    auto & d_=this->dist_;

                    auto & r_=this->rnd;

                    std::generate_n( s_.begin(), sz, [&]() -> char { 

                        return  static_cast<char>( d_( r_ ) );

                    } );

                    return s_;

                }

        }; /* generator_fn/ascii */ 

        using garbage_gen_fn=generator_fn<>;

        using alpnum_gen_fn=generator_fn<charsets_t::type::alp_num>;

        using ascii_gen_fn=generator_fn<charsets_t::type::ascii>;

        using rfc1035_gen_fn=generator_fn<charsets_t::type::rfc1035>;

        enum class distr_t {
            constant    =   0x00,
            uniform     =   0x01,
            exponential =   0x02,
            //normal =        0x04,
        };

        using lblszs_t=std::vector<size_t>;

        constexpr distr_t distr_const{distr_t::constant};

        constexpr distr_t distr_unif{distr_t::uniform};

        constexpr distr_t distr_exp{distr_t::exponential};

        template <const distr_t d1=distr_const, const distr_t d2=distr_const>
        struct dns_gen_fn_t{};

        template< /* const / const */ >
        struct dns_gen_fn_t< distr_const,
                             distr_const > : gen_base_t< dns_gen_fn_t<  distr_const,
                                                                        distr_const >   >{

            using base_type = gen_base_t< dns_gen_fn_t< distr_const,
                                                        distr_const >   >;

            friend base_type;

            dns_gen_fn_t(   const size_t c,
                            const size_t l  ) noexcept :    count_{ c },
                                                            len_{ l },
                                                            gen_fn{ l }
                                                            {}
            protected:
                const size_t count_{};

                const size_t len_{};

                mutable rfc1035_gen_fn gen_fn{};

                inline 
                std::string generate_() const noexcept
                {

                    using namespace titan_v3::tools::iterators;

                    using d_type=std::string::iterator::difference_type;

                    std::string s_( count_ * len_ + count_ - 1 , '.' );

                    auto it = s_.begin();

                    for ( const auto i_ : const_range( count_ ) ){

                        if ( i_ ){

                            ++it;

                        }

                        copy_n( gen_fn().begin(), len_, it ); //potentially could throw an exception

                        it+=static_cast<d_type>(len_);

                    }

                    return s_;

                }

        }; /* tmpl dns_gen_fn_t< const / const > */

        template</* unif / const */>
        struct dns_gen_fn_t< distr_unif,
                             distr_const > : gen_base_t< dns_gen_fn_t<  distr_unif,
                                                                        distr_const >   >{

            using base_type = gen_base_t<   dns_gen_fn_t<   distr_unif,
                                                            distr_const >   >;

            friend base_type;

            dns_gen_fn_t(   const size_t c,
                            const size_t l  ) noexcept :    len_{ l },
                                                            gen_fn{ l },
                                                            dist_{ 1, c }
                                                            {}
            protected:
                const size_t len_{};

                mutable rfc1035_gen_fn gen_fn{};

                mutable std::uniform_int_distribution<size_t> dist_;

                inline 
                std::string generate_() const noexcept
                {

                    using namespace titan_v3::tools::iterators;

                    using d_type=std::string::iterator::difference_type;

                    const size_t c_{ dist_( gen_fn.rnd ) };

                    std::string s_( c_ * len_ + c_ - 1 , '.' );

                    auto it = s_.begin();

                    for ( const auto i_ : const_range( c_ ) ){

                        if ( i_ ){

                            ++it;

                        }

                        copy_n( gen_fn().begin(), len_, it ); //potentially could throw an exception

                        it += static_cast<d_type>(len_);

                    }

                    return s_;

                }
        }; /* tmpl dns_gen_fn_t< unif / const > */

        using uu_results_t=std::tuple< size_t, lblszs_t , std::string >;

        template</* unif / unif */>
        struct dns_gen_fn_t< distr_unif,
                             distr_unif > : gen_base_t< dns_gen_fn_t<   distr_unif,
                                                                        distr_unif  >,
                                                        uu_results_t                    >{

            using base_type = gen_base_t<   dns_gen_fn_t<   distr_unif,
                                                            distr_unif  >,
                                            uu_results_t                    >;

            friend base_type;

            dns_gen_fn_t(   const size_t c,
                            const size_t l    ) noexcept :  len_{ l },
                                                            dist_{ 1, c },
                                                            dist_lbl_{ 1, l }
                                                            {}
            protected:
                const uint_fast64_t len_{};

                mutable rfc1035_gen_fn gen_fn{};

                mutable std::uniform_int_distribution<uint_fast64_t> dist_;

                mutable std::uniform_int_distribution<uint_fast64_t> dist_lbl_;

                inline 
                uu_results_t generate_() const noexcept
                {

                    using namespace titan_v3::tools::iterators;

                    auto & g_ = this->gen_fn;

                    auto & d_ = this->dist_lbl_;

                    auto & r_ = this->gen_fn.rnd;

                    const uint_fast64_t c_{  dist_( r_ ) };

                    lblszs_t lbls{};

                    lbls.reserve(c_);

                    std::string s_{};

                    s_.reserve( c_ * len_ + c_ - 1 );

                    for ( const auto i_ : const_range( c_ ) ){

                        if ( i_ ){

                            s_ += '.';

                        }

                        const uint_fast64_t l_ = d_( r_ );

                        lbls.push_back( l_ );

                        s_ += g_( l_ );

                    }

                    return std::make_tuple( c_, lbls, s_ ); 

                }
        }; /* tmpl dns_gen_fn_t< unif / unif > */

        using ec_results_t=std::tuple< size_t,lblszs_t , std::string >;

        template</* expo / const */>
        struct dns_gen_fn_t< distr_exp,
                             distr_const > : gen_base_t<    dns_gen_fn_t<   distr_exp,
                                                                            distr_const >,
                                                            ec_results_t                    > {

            using base_type = gen_base_t<   dns_gen_fn_t<   distr_exp,
                                                            distr_const >,
                                            ec_results_t                    >;

            friend base_type;

            dns_gen_fn_t(   const size_t c,
                            const size_t l,
                            const double lamda=1.0  ) noexcept :    count_{ c },
                                                                    len_{ l },
                                                                    gen_fn{ l },
                                                                    dist_{ lamda }
                                                                    {}
            protected:
                const size_t count_{};

                const size_t len_{};

                mutable rfc1035_gen_fn gen_fn{};

                mutable std::exponential_distribution<> dist_;

                inline 
                ec_results_t generate_() const noexcept
                {

                    using namespace titan_v3::tools::iterators;

                    using d_type=std::string::iterator::difference_type;

                    size_t safety_c{ count_ << 1 };

                    size_t c_{};

                    auto & r_ = this->gen_fn.rnd;

                    auto & g_ = this->gen_fn;

                    auto & d_ = this->dist_;

                    while ( --safety_c                                                          &&

                            count_ < ( c_ = ( static_cast<size_t>(  ceil( d_( r_ ) ) ) ?: 1 ) )     );

                    (void)( safety_c ?: c_ = count_ );

                    std::string s_( c_ * len_ + c_ - 1 , '.' );

                    auto it=s_.begin();

                    lblszs_t lbls{};

                    for ( const auto i_ : const_range( c_ ) ){

                        if ( i_ ){

                            ++it;

                        }

                        copy_n( g_().begin(), len_, it ); //potentially could throw an exception

                        it += static_cast<d_type>(len_);

                        lbls.push_back( len_ ); 

                    }

                    return  std::make_tuple( c_, lbls, s_ );

                }

        };/* tmpl dns_gen_fn_t<  expo / const > */

        using eu_results_t=std::tuple< size_t,lblszs_t , std::string >;

        template</* expo / unif */>
        struct dns_gen_fn_t< distr_exp,
                             distr_unif > : gen_base_t< dns_gen_fn_t<   distr_exp,
                                                                        distr_unif  >,
                                                        eu_results_t                    > {

            using base_type = gen_base_t<   dns_gen_fn_t<   distr_exp,
                                                            distr_unif  >,
                                            eu_results_t                    >;

            friend base_type;

            dns_gen_fn_t(   const size_t c,
                            const size_t l,
                            const double lamda=1.0  ) noexcept :    count_{ c },
                                                                    len_{ l },
                                                                    dist_{ lamda },
                                                                    dist_lbl_{ 1, l }
                                                                    {}
            protected:
                const size_t count_{};

                const size_t len_{};

                mutable rfc1035_gen_fn gen_fn{};

                mutable std::exponential_distribution<> dist_;

                mutable std::uniform_int_distribution<size_t> dist_lbl_;

                inline 
                eu_results_t generate_() const noexcept
                {

                    using namespace titan_v3::tools::iterators;

                    size_t safety_c{ count_<<1 };

                    size_t c_{};

                    auto & r_ = this->gen_fn.rnd;

                    auto & g_ = this->gen_fn;

                    auto & d_ = this->dist_lbl_;

                    while ( --safety_c                                                              &&

                            count_ < ( c_ = ( static_cast<size_t>(  ceil( dist_( r_ ) ) ) ?: 1 ) )      );

                    (void)( safety_c ?: c_ = count_ );

                    lblszs_t lbls{};

                    lbls.reserve(c_);

                    std::string s_{};

                    s_.reserve( c_ * len_ + c_ - 1 );

                    for ( const auto i_ : const_range( c_ )){

                        if ( i_ ){

                            s_ += '.';

                        }

                        const size_t l_{ d_( r_ ) };

                        s_ += g_( l_ );

                        lbls.push_back( l_ );

                    }

                    return  std::make_tuple( c_, lbls, s_ );

                }

        }; /* tmpl dns_gen_fn_t< expo / unif > */

        using ee_results_t=std::tuple< size_t,lblszs_t , std::string >;
        
        template</* expo / expo */>
        struct dns_gen_fn_t< distr_exp,
                             distr_exp  > : gen_base_t< dns_gen_fn_t<   distr_exp,
                                                                        distr_exp   >,
                                                        ee_results_t                    > {
            
            using base_type = gen_base_t<   dns_gen_fn_t<   distr_exp,
                                                            distr_exp   >,
                                            ee_results_t                    >;

            friend base_type;

            dns_gen_fn_t(   const size_t c,
                            const size_t l,
                            const double lamda=1.0  ) noexcept :    count_{ c },
                                                                    len_{ l },
                                                                    dist_{ lamda },
                                                                    dist_lbl_{ lamda }
                                                                    {}
            protected:
                const size_t count_{};

                const size_t len_{};

                mutable std::ranlux48_base rnd{ std::random_device{}() };

                mutable rfc1035_gen_fn gen_fn{};

                mutable std::exponential_distribution<> dist_;

                mutable std::exponential_distribution<> dist_lbl_;

                inline 
                ee_results_t generate_() const noexcept
                {

                    using namespace titan_v3::tools::iterators;

                    size_t safety_c{ count_<<1 };

                    size_t c_{};

                    while ( --safety_c                                                                      &&

                            count_ < ( c_ = ( static_cast<size_t>( ceil( dist_( gen_fn.rnd ) ) ) ?: 1 ) )       );

                    (void)( safety_c ?: c_ = count_ );

                    lblszs_t lbls{};

                    lbls.reserve(c_);

                    std::string s_{};

                    s_.reserve( c_ * len_ + c_ - 1 );

                    gen_fn.rnd.discard(1);

                    for ( const auto i_ : const_range( c_ )){

                        size_t safety_l{ len_<<1 };

                        size_t l_{};

                        while ( --safety_l                                                                  &&

                                len_ < ( l_ = ( static_cast<size_t>( ceil( dist_lbl_( rnd ) ) ) ?: 1 ) )        );
 
                        (void)( safety_l ?: l_ = len_ );

                        lbls.push_back(l_);

                        if ( i_ ){

                            s_ += '.';

                        }
    
                        s_ += gen_fn(l_); //potentially could throw an exception

                    }

                    return  std::make_tuple( c_, lbls, s_ );

                }

        }; /* tmpl dns_gen_fn_t< expo / expo > */

        using dns_gen_cc_fn=dns_gen_fn_t<>;

        using dns_gen_uc_fn=dns_gen_fn_t<distr_unif>;

        using dns_gen_uu_fn=dns_gen_fn_t<distr_unif, distr_unif>;

        using dns_gen_ec_fn=dns_gen_fn_t<distr_exp>;

        using dns_gen_eu_fn=dns_gen_fn_t<distr_exp,distr_unif>;

        using dns_gen_ee_fn=dns_gen_fn_t<distr_exp,distr_exp>;

    } /* ns */

} /* ns */

#endif /* TTN_GENERATOR_HXX */

/* vim: set ts=4 sw=4 et : */

