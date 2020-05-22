/**
 * $Id$
 */

#include "ttn_wada.hxx"
#include "ttn_tools.hxx"
#include <errno.h>
#include <sys/stat.h>
#include "log.h"

#ifdef TTN_ATESTS
static void cls_(void);

    stats_4test_t s4test={
        .cls=&cls_,
    };

    static 
    void cls_()
    {
        s4test.line_proc=s4test.read_file=0;
        (void)zm(&s4test.ips,sizeof(s4test.ips));
        (void)zm(&s4test.read,sizeof(s4test.read));
        (void)zm(&s4test.save,sizeof(s4test.save));
        (void)zm(&s4test.user,sizeof(s4test.user));
    }

#endif



namespace titan_v3
{

    constexpr ssize_t LINE_MAX_SZ           {0x400};

    constexpr ssize_t LINE_SHORT_MIN_SZ     {0x08};

    constexpr size_t  LINE_LONG_MIN_SZ      {0x2c};

    constexpr const char SYMBOLS[]          ="\r\n";

    constexpr uint32_t MSPOPCNT14b( cstr_t lp_,
                                    ssize_t lpsz,
                                    ssize_t pos     )
    {
        return  (
                    (
                        (  -(   SYMBOLS[ 0 ] == lp_[ pos ] ||

                                SYMBOLS[ 1 ] == lp_[ pos ]    )

                            & 

                            (
                                (
                                    -(  1 < ( lpsz - pos)                       &&

                                        (   SYMBOLS[ 1 ] == lp_[ 1 + pos ]      ||

                                            SYMBOLS[ 0 ] == lp_[ 1 + pos ]    )

                                     ) & 2 
                                ) | 1 
                            ) 
                        ) * 0x200040008001ULL & 0x111111111111111ULL

                    ) % 0xf 

               ); /* return */
    }
    

///////////////////////////////////////////////////////////////////////
    /* global */
    static wada_t * single_main_instance{};

//////////////////////////////////////////////////////////////////////////

    bool parse_ip_dell( line_t line,
                        csize_t, /* ignore */
                        cbool_t,  /* ignore */
                        wada_log_t * wada_log   )
    {

        ipv4_t ipv4{};

        /* We could use the sscanf_s (or equivalent) if and when the FreeBSD adds support for it. */
        if ( 1 == sscanf(   line,
                            "%8x\n",
                            &ipv4    ) ) {

                const auto & cidr_stat = cidr::factory::make_cidr( htonl(ipv4) );

                if ( cidr_stat.second ) {

                    const auto & cidr = cidr_stat.first;

                    //clear wada locations ??
                    wada_t::static_call([&]( wada_t * const self ) {

                        using namespace locations;

                        const bool reset_stat = self->locations.reset<location_t::types::wada>( cidr );

                        #ifdef TTN_ATESTS

                            if ( reset_stat ) {

                                s4test.ips.del++;

                            }

                            s4test.ips.lines++;

                            s4test.ips.internal_ctx = self->locations.size();

                        #endif

                        if ( reset_stat && wada_log ) {

                            wada_log->removed.insert( cidr.addr );
                        }


                    }); /* static_call */

                    return true;
                }
        }

        return false;
    }

    bool parse_ip_add(  line_t line,
                        csize_t line_sz,
                        cbool_t flush,
                        wada_log_t * wada_log    )
    {

        ipv4_t ipv4{};

        char guid[GUID_STR_SZ+1]={};

        if (    LINE_LONG_MIN_SZ <= line_sz &&
            /* We could use the sscanf_s (or equivalent) if and when the FreeBSD adds support for it. */

                2==sscanf(  line,
                            "%8x%36s",
                            &ipv4,
                            guid    )           ) {

                    if ( flush ) {

                        //flush all
                        wada_t::static_call([&wada_log]( wada_t * const self ){

                            if ( !self->cfg.keep_existing_entries ) {
                                using namespace titan_v3::locations;
                                if (wada_log) {
                                   self->locations.reset<location_t::types::wada>(wada_log->removed);
                                }
                                else {
                                    self->locations.reset<location_t::types::wada>();
                                }

                                #ifdef TTN_ATESTS
                                s4test.ips.flush++;
                                s4test.ips.internal_ctx = self->locations.size();
                                #endif
                            }

                        }); /* static_call */

                    }

                const auto & cidr_stat = cidr::factory::make_cidr( htonl(ipv4) );

                if ( cidr_stat.second ) {

                    const auto & cidr = cidr_stat.first;

                    //add ip
                    wada_t::static_call( [&]( wada_t * const self )  {

                                auto get_id = [ self, &guid ]() -> size_t {

                                    if (    self->cfg.users_file &&
                                            self->users_by_uuid.size()  ) {

                                                using namespace tools;
                                                const auto & f_=self->users_by_uuid.find( guid  );

                                                if ( f_ != self->users_by_uuid.end() ) {

                                                    return f_->second;
                                                }
                                    }

                                    return {};
                                };

                                using namespace locations;

                                const auto & result = self->locations.add(  cidr,
                                                                            get_id(),
                                                                            guid,
                                                                            location_t::types::wada );
                                #ifdef TTN_ATESTS 

                                    if ( result.second ) {

                                        s4test.ips.add++;
                                    }

                                    s4test.ips.lines++;
                                    s4test.ips.internal_ctx = self->locations.size();


                                #endif

                                if ( result.second && wada_log ) {

                                    const auto & element = wada_log->removed.find(cidr.addr);

                                    if ( element != wada_log->removed.end()) {

                                        wada_log->removed.erase(element);
                                    }
                                    else {

                                        wada_log->added[cidr.addr] = guid;
                                    }
                                }

                            }); /* static_call */

                    return true;

                }

        } /* if */
        return false;
    }

    bool parse_user_add(    line_t line,
                            csize_t line_sz,
                            cbool_t flush,
                            wada_log_t*     )
    {

        char guid[GUID_STR_SZ+1]={};
        uint32_t wtcid{}; //use 64bit

        if ( flush ) {
            //flush all
            wada_t::static_call([]( wada_t * const self ){

                self->users_by_uuid.clear();
                #ifdef TTN_ATESTS
                s4test.user.flush++;
                s4test.user.internal_ctx = self->users_by_uuid.size();
                #endif

            }); /* static_call */
        }

        /* use of sscanf is safe here */
        return  (   LINE_LONG_MIN_SZ<=line_sz               &&

                    2 <= sscanf(    line, 
                                    "%8x%36s",
                                    &wtcid, 
                                    guid        )           &&

                    /* process users data, ignore upn */
                    wada_t::static_call( [&]( wada_t * const self ) {

                        #ifdef TTN_ATESTS
                            const auto & stat=self->users_by_uuid.emplace(  guid,
                                                                            wtcid   );
                            if ( stat.second ){
                                s4test.user.add++;
                            }
                            s4test.user.lines++;
                            s4test.user.internal_ctx = self->users_by_uuid.size();
                        #else 
                            self->users_by_uuid.emplace(    guid,
                                                            wtcid   );

                        #endif

                        return true;
                    }) /* static_call */

                ); /* return */
    }

    /**
    * @name                line_proc
    * @abstract            line processor
    * @param line[in]      ptr to the buffer
    * @param line_sz[in]   buffer size
    * @param ops[in]       ptr to the lp operations
    * @return 
    */
    static 
    bool line_proc( line_t line,
                    csize_t line_sz,
                    lp_ops_arg_t ops,
                    wada_log_t* wada_log    )
    {

        if (    line && 
                LINE_SHORT_MIN_SZ < line_sz ) {

                const char * line_{line};
                bool flush{};
                /* offset */
                switch (*line_){
                    case '\n':
                    case '\r':
                    case 0: ++line_;
                }

                /* parse */
                switch (*line_){

                    case '-':{
                        if (    ops && 
                                ops->del && 
                                !ops->del(  ++line_,
                                            line_sz-1,
                                            false,
                                            wada_log       ) ) {

                            return false;
                        }

                        #ifdef TTN_ATESTS
                        ++s4test.line_proc;
                        #endif
                    }break;

                    case '*': flush=true;
                    [[clang::fallthrough]];

                    case '+':{

                        if (    ops && 
                                ops->add && 
                                !ops->add(  ++line_,
                                            line_sz-1,
                                            flush,
                                            wada_log    ) ) {

                            return false;
                        }

                        #ifdef TTN_ATESTS
                        ++s4test.line_proc;
                        #endif

                    }break;

                    default:break;
                }

            /* final op */
            if (    ops && 
                    ops->finally   ) {

                ops->finally();
            }

            return true;
        }

        return false;
    } /* fn */

#ifndef TTN_ATESTS

        /**
         * @name             read_lines
         * @abstract         read lines from a buffer
         * @note             production ready 
         * @param lp[in]     ptr to the buffer
         * @param lpsz[in]   buffer size
         * @param lpcfg[in]  ptr to the cfg for the line processor 
         * @return           leftover (the unparsed rest of the input buffer)
         */
        TX_INTERNAL_INLINE
        ssize_t read_lines( lines_t lp, 
                            ssize_t lpsz, 
                            const lp_cfg_t & lpcfg  )
        {

#else

        TX_INTERNAL_INLINE
        ssize_t read_lines_(    lines_t lp,
                                ssize_t lpsz,
                                const lp_cfg_t & lpcfg  );

        /**
         * @name             read_lines
         * @abstract         it is a 4test wrapper (see read_lines production ready)
         */
        TX_INTERNAL_INLINE
        ssize_t read_lines( lines_t lp, 
                            ssize_t lpsz, 
                            const lp_cfg_t & lpcfg  )
        {

                const ssize_t r_=read_lines_( lp, lpsz, lpcfg);
                s4test.read.left+=r_;

                return r_;
        }

        /**
         * @name             read_lines_
         * @abstract         internal use with 4test wrapper (see read_lines production ready)
         */      
        ssize_t read_lines_(    lines_t lp,
                                ssize_t lpsz,
                                const lp_cfg_t & lpcfg  )
        {

#endif  /* TTN_ATESTS */ 

            if ( lp && lpsz ) {

                errno=0;
                cstr_t lp_{lp};
                ssize_t pos{};
                uint32_t bc{};
                wada_log_t wada_log{};

                /* start processing */
                while ( !( pos = 0 ) &&

                        LINE_SHORT_MIN_SZ < lpsz                                                    &&

                        LINE_SHORT_MIN_SZ < (   pos=ttn_strncspn(   lp_,
                                                                    static_cast<size_t>(lpsz),
                                                                    SYMBOLS,
                                                                    ( sizeof( SYMBOLS )-1 )    ) )  && 

                        pos<lpsz                                                                    &&

                        ( bc = MSPOPCNT14b( lp_,
                                            lpsz,
                                            pos     ) )  /* check Multi Symbol ending */
                ){

                    if ( LINE_MAX_SZ > pos ) {

                        /* line processing */
                        #ifdef TTN_ATESTS

                            if ( lpcfg.proc(    lp_,
                                                static_cast<size_t>(pos),
                                                &lpcfg.ops,
                                                &wada_log                   ) ) {

                                ++s4test.read.lines;
                            } 
                            else { 

                                return INVALID_; /* error */
                            }

                        #else

                            lpcfg.proc( lp_,
                                        static_cast<size_t>(pos),
                                        &lpcfg.ops,
                                        &wada_log                   );

                        #endif
                    }

                    /* forward ptr*/
                    if ( INVALID_ < ( lpsz -= ( static_cast<ssize_t>( bc+pos ) ) ) ) {

                        lp_ += static_cast<ssize_t>( bc + pos );

                    }
                    else {

                        /* calc error add assert ? */
                        errno=EINVAL;
                        return INVALID_;
                    }

                } /* while */

                using namespace titan_v3::cidr;

                if (!wada_log.removed.empty()) {

                    #ifndef TTN_ATESTS

                        titax_log(LOG_NOTICE, "WADA Updates. Removed : \n");
                    #else 

                        std::cout<<std::endl;
                    #endif

                    for (const auto & ip: wada_log.removed) {

                        #ifndef TTN_ATESTS

                           titax_log(   LOG_NOTICE,
                                        "     %s(%s)",
                                        factory::to_hex(ip).c_str(),
                                        factory::to_string(ip).c_str()   );
                        #else

                            printf( "     %s(%s)\n",
                                    factory::to_hex(ip).c_str(),
                                    factory::to_string(ip).c_str()   );
                        #endif
                   }
                }

                if (!wada_log.added.empty()) {

                    #ifndef TTN_ATESTS

                        titax_log(LOG_NOTICE, "WADA Updates. Added : \n");
                    #else 

                        std::cout<<std::endl;
                    #endif

                   for (const auto & elem: wada_log.added) {

                        const std::string & suud = elem.second;

                        #ifndef TTN_ATESTS

                           titax_log(   LOG_NOTICE,
                                        " %s(%s) %s",
                                        factory::to_hex(elem.first).c_str(),
                                        factory::to_string(elem.first).c_str(),
                                        suud.c_str()                            );
                        #else 

                            printf( " %s(%s) %s\n",
                                    factory::to_hex(elem.first).c_str(),
                                    factory::to_string(elem.first).c_str(),
                                    suud.c_str()                            );
                        #endif
                   }
                }


                /* ignore leftover data */
                return (lpsz);
            }

            errno=EINVAL;
            return INVALID_;

        } /* fn */

    /**
    * @name             read_file
    * @abstract         read the optimal chunks of data from a file
    * @param lp[in]     ptr to the filename
    * @param lpcfg[in]  ptr to the cfg for the line processor 
    * @return           t/f
    */
    TX_INTERNAL_INLINE
    bool read_file( file_t file,
                    const lp_cfg_t & lpcfg /* cpy eli ? */ )
    {

        if ( file && *file ) {

            errno=0;

            const int fd{   open(   file,
                                    O_RDONLY,
                                    DEFFILEMODE )   };

            if ( INVALID_<fd ) {

                struct stat st={};

                csize_t blksz{ (    !fstat(fd, &st) ?
                                    static_cast<size_t>(st.st_blksize) :
                                    BUFSIZ   ) };

                size_t bsz{ blksz };

                std::unique_ptr< char[] > buf { new char[ bsz+1 ]{} };

                if ( buf ) {

                    ssize_t rlsz{ INVALID_ };
                    ssize_t rsz{ static_cast<ssize_t>( bsz ) };

                    char * lp{ buf.get() };

                    while ( 0<( rsz = read( fd, 
                                            lp, 
                                            static_cast<size_t>(rsz) ) ) ){

                            #ifdef TTN_ATESTS
                                s4test.read_file += rsz;
                            #endif

                            /* 
                             * reset size and buffer
                             * todo: use ptr diff
                             */
                            rsz += static_cast<ssize_t>( lp - buf.get() );

                            lp=buf.get();

                            /* process lines */
                            if ( INVALID_ < ( rlsz = read_lines( lp ,rsz, lpcfg ) ) ) {

                                /* todo:test <0 */
                                (void)(( rsz - rlsz ) ?: ( rlsz = 0 ));

                                /* buffer mgm */
                                if ( 0 < rlsz ) {

                                    /* forward buffer (todo: test <0) */
                                    lp += rsz - rlsz;

                                    /* cpy */
                                    static_cast<char*>( memcpy( buf.get(),
                                                                lp,
                                                                static_cast<size_t>( rlsz ) ) )[rlsz]=0;

                                    /* a possibility to grow the buffer */
                                }

                                /* setup buffer & size */
                                lp = buf.get() + rlsz;

                                /* todo: test <0 */
                                rsz = ( ( static_cast<ssize_t>( bsz ) - rlsz  ) ?: static_cast<ssize_t>( bsz ) );

                            } 
                            else {

                                /* errno is already set */
                                close( fd );
                                return false;
                            }

                    } /* while */

                    /*
                    *  0: eof
                    * -1: err
                    */
                    close(fd);

                    return (    INVALID_ < rsz &&
                                INVALID_ < rlsz     );

                } else 
                    errno=ENOMEM;

            } /* if | errno is already set */

        } else  
            errno=EINVAL;

        return false;

    } /* fn */

    TX_INTERNAL_INLINE
    bool PARSE_IPS_FILE_( file_t FILE_ )
    {

        return read_file(   FILE_,
                            lp_cfg_t{

                                .proc = &line_proc,
                                .ops={
                                    .add = &parse_ip_add,
                                    .del = &parse_ip_dell
                                }
                            }
                        ); /* read_file & return */

    }

    TX_INTERNAL_INLINE
    bool PARSE_USERS_FILE_( file_t FILE_ )
    {

        return read_file(   FILE_,
                            lp_cfg_t{

                                .proc = &line_proc,
                                .ops={
                                    .add = &parse_user_add
                                }
                            }
                        ); // read_file & return 
    };

    TX_INTERNAL_INLINE
    ssize_t PARSE_IP_LINES_(    lines_t LINES,
                                csize_t LSZ    )
    {

        return read_lines(  LINES,
                            static_cast<ssize_t>( LSZ ),
                            lp_cfg_t{

                                .proc=&line_proc,
                                .ops={
                                    .add = &parse_ip_add,
                                    .del = &parse_ip_dell
                                }
                            }
                        ); /* read_file & return */
    }

#ifdef TTN_ATESTS

    static
    bool parse_ip_dell_4test(   line_t line,
                                csize_t, /* ignore */
                                cbool_t,   /* ignore */
                                wada_log_t* /* ignore */ )
    {

        uint32_t ipv4{}; //replacde type
        /* We could use the sscanf_s (or equivalent) if and when the FreeBSD adds support for it. */
        if (    1 == sscanf(    line, 
                                "%8x\n", 
                                &ipv4   ) ) {

            ++s4test.ips.del;
            return true;
        }

        return false;
    }

    static
    bool parse_ip_add_4test(    line_t line,
                                csize_t line_sz,
                                cbool_t flush,   /* ignore */
                                wada_log_t* /* ignore */     )
    {

        uint32_t ipv4{}; //replce type
        char guid[GUID_STR_SZ+1];

        if (    LINE_LONG_MIN_SZ <= line_sz     && 

            /* We could use the sscanf_s (or equivalent) if and when the FreeBSD adds support for it. */
                2 == sscanf(    line, 
                                "%8x%36s", 
                                &ipv4, 
                                guid        )       ) {

            if ( flush ) {

                ++s4test.ips.flush;
                s4test.ips.del=s4test.ips.add=0;
            }

            s4test.ips.add+=(guid[0]!=0);
            return true;
        }

        return false;
    }


    static
    bool parse_user_add_4test(  line_t line,
                                csize_t line_sz,
                                cbool_t,    /* ignore */
                                wada_log_t* /* ignore */)
    {

        char guid[GUID_STR_SZ+1]={};
        uint32_t wtcid{};
        int read_sz{};

        /* use of sscanf is safe here */
        return (    LINE_LONG_MIN_SZ <= line_sz && 

                    2 <= sscanf(    line, 
                                    "%8x%36s%n", 
                                    &wtcid,
                                    guid,
                                    &read_sz )  &&

                    ( s4test.user.add += (  guid[0] && 
                                            ( line+LINE_LONG_MIN_SZ )[0] && 
                                            ( line_sz - static_cast<csize_t>( read_sz-1) ) 
                                         ) )
                ); /* return */
    }

    TX_INTERNAL_INLINE
    ssize_t PARSE_USERS_LINES_4TESTS_(  lines_t LINES,
                                        csize_t LSZ    )
    {

        return read_lines(  LINES,
                            static_cast<ssize_t>(LSZ),
                            lp_cfg_t{

                                .proc=&line_proc,
                                .ops={
                                    .add = &parse_user_add_4test
                                }
                            }
                        ); /* retunr */
    }

    TX_INTERNAL_INLINE
    bool PARSE_USERS_FILE_4TESTS_( file_t FILE_ )
    {

        return read_file(   FILE_,
                            lp_cfg_t{

                                .proc = &line_proc,
                                .ops={
                                    .add = &parse_user_add_4test
                                }
                            }
                        ); /* return */
    }

    TX_INTERNAL_INLINE
    bool PARSE_IP_FILE_4TESTS_( file_t FILE_ )
    {

        return read_file(   FILE_,
                            lp_cfg_t{

                                .proc = &line_proc,
                                .ops={
                                    .add = &parse_ip_add_4test,
                                    .del = &parse_ip_dell_4test,
                                    //.finally = &parse_ip_finally_4test
                                }
                            }
                        ); /* return */
    }

#endif


///////////////////////////////////////////////////////////////////////////////

    bool wada_t::configure( wada_cfg_arg_t c ) noexcept 
    {

        if ( single_main_instance != this ) {

            titax_log(LOG_ERROR, "Secondary WADA instance detected\n");

            return false;
        }

        if (    ! c                     ||

                ! c->wada_cache_file    ||

                ! *c->wada_cache_file      )  {

            return false;
        }

        memmove( &this->cfg_, c, sizeof( wada_cfg_t ) );

        return true; 
    }

    bool wada_t::reload_from_files() noexcept 
    {

        #ifdef TTN_ATESTS 
        //flush all users
        users_by_uuid.clear();
        #endif

        if ( single_main_instance != this ) {

            titax_log(LOG_ERROR, "Secondary WADA instance detected\n");

            return false;
        }

        if ( cfg.users_file &&
             *cfg.users_file &&
             ! PARSE_USERS_FILE_( cfg.users_file ) ) {

            return false;
        }

        //flush all ips
        if ( ! cfg.keep_existing_entries ) {

            using namespace titan_v3::locations;

            locations.reset<location_t::types::wada>();
        }

        if (    ! cfg.wada_cache_file                     ||

                ! *cfg.wada_cache_file                    ||

                ! PARSE_IPS_FILE_( cfg.wada_cache_file )     ) {

            return false;
        }

        return true;

    }

    bool wada_t::reload_from_http(  lines_t body,
                                    csize_t size    ) noexcept 
    {

        return (    INVALID_ < PARSE_IP_LINES_( body,
                                                size    ));
    }

    bool wada_t::user_find_by_ip(   c_raw_ipaddr_t ip,
                                    user_details_arg_t out ) const noexcept 
    {

        const auto & cidr_stat = cidr::factory::make_cidr(ip);

        if ( cidr_stat.second ) {

            const auto & stat = this->locations.find( cidr_stat.first );

            if ( stat.second ) {

                if ( out ) {

                    out->wtcid=stat.first.user_id;
                }

                return true;
            }

        }

        return false;

    }

    bool wada_t::save_to_file( cbool_t append ) noexcept 
    {

        if ( single_main_instance != this ) {

            titax_log(LOG_ERROR, "Secondary WADA instance detected\n");

            return false;
        }

        return this->locations.save4wada(cfg.wada_cache_file,append);
    }

    size_t wada_t::count() const noexcept 
    {
        return this->locations.count(locations::location_t::types::wada);
    }

////////////////////////////////////////////////////////////////////////////

    wada_t::pred_status_t wada_t::is_not_null() noexcept
    {

        if ( single_main_instance ) {

            return pred_status_t::success( single_main_instance ); 
        }

        return pred_status_t::failure();

    }

    wada_api_t * wada_t::as_api() noexcept 
    {

        return (    single_main_instance                                ?

                    static_cast<wada_api_t*>( single_main_instance )    :

                    nullptr                                                 );
    }

    void wada_t::init_api() 
    {

        if ( !single_main_instance ) {

            wada_api_t::configure = []( wada_cfg_arg_t c ) {

                return  wada_t::static_call( [ c ]( wada_t * const self ) {

                            return self->configure( c );

                        }); /* static_call & return */
            };

            wada_api_t::reload_from_files = [] {

                return  wada_t::static_call([]( wada_t * const self ) {

                        return self->reload_from_files() ;

                        }); /* static_call & return */

            };

            wada_api_t::reload_from_http = []( lines_t b, csize_t s ) {

                return  wada_t::static_call([=]( wada_t * const self ) {

                            return self->reload_from_http( b, s );    

                        }); /* static_call & return */
            };

            wada_api_t::user_find_by_ip = []( c_raw_ipaddr_t ip , user_details_arg_t out ) {

                return  wada_t::static_call([=]( wada_t * const self ) {

                            return self->user_find_by_ip( ip, out );

                        }); /* static_call & return */ 
            };

            wada_api_t::save_to_file = []( cbool_t b ) {

                return  wada_t::static_call([=]( wada_t * const self ) {

                            return self->save_to_file( b );

                        }); /* static_call & return */
            };

            wada_api_t::count = [] {

                return  wada_t::static_call([]( wada_t * const self ) {

                            return self->count();

                        }); /* static_call & return */
            };

            #ifdef TTN_ATESTS
                wada_api_t::reload_users_from_file_4test = []( file_t filename ) {

                    return PARSE_USERS_FILE_4TESTS_( filename );
                };

                wada_api_t::reload_users_from_buffer_4test = []( lines_t body, csize_t size ) {

                    return ( INVALID_ < PARSE_USERS_LINES_4TESTS_( body, size ));
                };

                wada_api_t::reload_ips_from_file_4test = []( file_t filename ) {

                    return PARSE_IP_FILE_4TESTS_( filename );
                };

                wada_api_t::save_to_file_4test = []( file_t filename, cbool_t append) {

                    return  wada_t::static_call([ filename, append ]( wada_t * const self ) {

                                return self->locations.save4wada(filename,append);

                            }); /* static_call & return */
                };

                wada_api_t::raw_count_4test = [] {

                    return  wada_t::static_call([]( wada_t * const self ) {

                                return self->locations.size();
                            }); /* static_call & return */
                };

                wada_api_t::clear_config_4test = [] {

                    wada_t::static_call([]( wada_t * const self ) {

                        zm( &self->cfg_, sizeof( wada_cfg_t ) );

                        //self->configured = false;

                    }); /* static_call & return */
                };

            #endif

            single_main_instance = this;

        } else {

            using namespace titan_v3::tools;

            throw errors::wada_init_error();
        }

   }

    void wada_t::fini_api() noexcept 
    {

        if ( single_main_instance == this ){

            single_main_instance = {};
        }
    }

} /* ns */

#ifdef TTN_ATESTS
std::ostream &operator<<(std::ostream& out , stats_4test_t in)
{

    return out<<std::dec

            <<"stats:[ ip:{ "   << in.ips.add << "|" 
                                << in.ips.del << "|"
                                << in.ips.flush << "|"
                                << in.ips.internal_ctx << "|" 
                                << in.ips.lines <<" } "

            << std::dec 
            << "| usr:{ "   << in.user.add << " | "
                            << in.user.del << " | "
                            << in.user.flush <<" | "
                            << in.user.internal_ctx <<" | "
                            << in.user.lines << " } "

            << "| read:{ "  << in.read.lines << " | "
                            << in.read.left << "} " 

            << "| save:{ "  << in.save.lines << " | "
                            << in.save.ctx << " | "
                            << in.save.bytes << "} " 

            << "| line_proc:{ " << in.line_proc  << " } " 

            << "| read_file:{ " << in.read_file  << " } ]"; 

}

#endif

/* vim: set ts=4 sw=4 et : */

