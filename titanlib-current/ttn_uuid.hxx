/**
 * $Id$
 */
#ifndef TTN_UUID_HXX
#define TTN_UUID_HXX

namespace titan_v3
{

    namespace tools
    {
        /**
         * @struct ttn_uuid_t
         * @abstract basic cpp uuid/uint128_t wrapper 
         */
        struct ttn_uuid_t
        {

            ttn_uuid_t()=default;
            virtual ~ttn_uuid_t()=default;

            /**
             * ctor 
             */
            explicit ttn_uuid_t( t_uuid u ) noexcept :  uuid_{ u },
                                                        str_{ ttn_uuid_t::to_str( u ) } {}

            /**
             * conv/cpy ctor ( arrays )
             */
            template <typename T, size_t N>
            ttn_uuid_t( const T (&s)[N] ) noexcept :    uuid_{ ttn_uuid_t::to_uuid( s ) }, 
                                                        str_{ s, N } {}

            /**
             * conv/cpy ctor ( char ptr )
             */
            explicit ttn_uuid_t( const char * const __restrict s ) noexcept :  uuid_{ ttn_uuid_t::to_uuid( s ) } {
                if ( s ) {
                    str_=s;
                }
            }

            /**
             * conv/cpy ctor ( std::string &  )
             */
            ttn_uuid_t( const std::string & s ) noexcept :  uuid_{ ttn_uuid_t::to_uuid( s.c_str() ) }, 
                                                            str_{ s } { }

            /**
             * conv/mov ctor ( std::string && )
             */
            ttn_uuid_t( std::string && s ) noexcept :   uuid_{ ttn_uuid_t::to_uuid( s.c_str() ) }, 
                                                        str_{ std::move(s) } { }

            /**
             * cpy ctor ( ttn_uuid_t & )
             */
            ttn_uuid_t( const ttn_uuid_t & u ) noexcept :   uuid_{ u.uuid_ },
                                                            str_{ u.str_ } {}

            /**
            * @abstract mov ctor ( ttn_uuid_t && )
            */
            ttn_uuid_t( ttn_uuid_t && u ) noexcept :    uuid_{ std::move( u.uuid_ ) },
                                                        str_{ std::move( u.str_ ) } {}

            /**
             * @abstract cpy assign op (ttn_uuid_t &)
             */
            inline
            ttn_uuid_t & operator=( const ttn_uuid_t & u ) noexcept {
                uuid_ = u.uuid_;
                str_ = u.str_;
                return *this;
            }

            /**
             * @abstract mov assign op (ttn_uuid_t &)
             */
            inline 
            ttn_uuid_t & operator=( ttn_uuid_t && u ) noexcept {
                uuid_ = std::move( u.uuid_ );
                str_ = std::move( u.str_ );
                return *this;
            }

            /**
             * @abstract cpy assign op ( t_uuid )
             */
            inline 
            ttn_uuid_t & operator=( t_uuid  u ) noexcept {
                str_ = ttn_uuid_t::to_str( ( uuid_ = u ) );
                return *this;
            }

            /**
             * @abstract cpy assign op ( std::string )
             */
            inline 
            ttn_uuid_t & operator=( const std::string & s ) noexcept {
                uuid_ = ttn_uuid_t::to_uuid( ( str_ = s ) );
                return *this;
            }

            /**
             * @abstract move assign op ( std::string )
             */
            inline 
            ttn_uuid_t & operator=( std::string && s ) noexcept {
                uuid_ = ttn_uuid_t::to_uuid( ( str_ = std::move(s) ) );
                return *this;
            }

            /**
             * @abstract assign op ( array )
             */
            template <typename T, size_t N> inline 
            ttn_uuid_t & operator=( const T (&s)[N]  ) noexcept {
                uuid_ = ttn_uuid_t::to_uuid( ( str_ = s ) );
                return *this;
            }

            /**
             * @abstract assign op ( char ptr )
             */
            inline 
            ttn_uuid_t & operator=( const char * const s  ) noexcept {
                if ( s ){
                    uuid_ = ttn_uuid_t::to_uuid( ( str_ = s ) );
                }
                return *this;
            }

            /**
             * @abstract zero/clear
             */
            inline
            void zero() noexcept {
                uuid_=0;
                str_.clear();
            }

            /**
             * @abstract impl cast operator (bool)
             */
            inline
            operator bool() const noexcept {
                return !is_zero(*this);
            }

            /**
             * @abstract impl cast operator (t_uuid)
             */
            inline 
            operator const t_uuid & () const noexcept {
                return uuid_;
            }

            /**
            * @abstract impl cast operator (std::string)
            */
            inline 
            operator const std::string & () const noexcept {
                return str_;
            }

            /**
            * @abstract cmp operator
            */
            inline
            bool operator==(const ttn_uuid_t& rhs) const noexcept {
                return (uuid_==rhs.uuid_);
            }

            /**
            * @fn is_zero 
            */
            static bool is_zero( const ttn_uuid_t & u_ ){
                return !( u_.uuid_ && u_.str_.size() );
            }

            /**
             * @fn is_valid 
             */
            static bool is_valid( const ttn_uuid_t & l_ ){

                if ( ! ttn_uuid_t::is_zero( l_ ) ) {
                    t_uuid r_ = ttn_uuid_t::to_uuid( l_.str_ );
                    return ( l_.uuid_  == r_ );
                }

                return false;
            }

            /**
             * @fn to_uuid (char ptr) 
             */
            static t_uuid to_uuid(const char * const);

            /**
             * @fn to_uuid (std::string) 
             */
            static t_uuid to_uuid(const std::string & in){
                return to_uuid(in.c_str());
            }

            /**
             * @fn to_str (t_uuid) 
             */
            static std::string to_str( const t_uuid & );
            
            friend std::ostream& operator<<(std::ostream & out,const ttn_uuid_t& obj ) noexcept { 
                return out<<obj.str_;
            }

            protected:
                t_uuid      uuid_ {};
                std::string str_  {};

        }; /* ttn_uuid_t */

    } /* tools NS */

} /* titan_v3 NS */


#endif /* TTN_UUID_HXX */
/* vim: set ts=4 sw=4 et : */

