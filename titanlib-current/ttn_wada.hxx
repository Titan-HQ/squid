/**
 * $Id$
 */
#pragma once
#include "global.h"
#include "log.h"
#include "ttn_tools.hxx"
#include "ttn_locations.hxx"
#include "ttn_cidr.hxx"
#include "wada_api.h"

namespace titan_v3 
{

    /**
     * @abstract Base struct to hold wada updates log info
     */
    struct wada_log_t
    {
       cidr::raw_addr_uset_t removed;
       cidr::raw_addr_map_uuid_t added;
    };

    /**
     * @abstract processing operation
     */
    typedef bool (*parser_op_t)(line_t ,csize_t, cbool_t, wada_log_t*);

    /* line processing operations */
    struct lp_ops_t
    {
        /* add operator */
        parser_op_t     add;
        /* dell operator */
        parser_op_t     del;
        /* finally operator */
        void (*finally)(void);

    };
    /**
     * @abstract alias for: const lp_ops_t * const restrict
     */
    typedef const lp_ops_t * const lp_ops_arg_t;

    /**
     * @abstract line processor
     */
    typedef bool ( *lproc_t )( line_t, csize_t, lp_ops_arg_t, wada_log_t*);

    /**
     * @abstract line processor configuration
     */
    struct lp_cfg_t
    {
        /* processor */
        lproc_t     proc;
        /* processing operations */
        lp_ops_t    ops;
    };

    struct wada_t : private wada_api_t 
    {

        const wada_cfg_t & cfg{ cfg_ };

        std::unordered_map<tools::ttn_uuid_t, size_t> users_by_uuid{};

        locations::locations_box_type & locations;

        explicit wada_t( locations::locations_box_type & l ) noexcept : locations{ l }
        {

            try{ 

                init_api();

            } catch ( std::exception & e ) {

                titax_log(  LOG_ERROR,
                            "%s:%d: exception [%s] - dying!\n",
                            __func__,
                            __LINE__,
                            e.what()                            );

                /* dying */
                throw;

            } catch ( ... ) {

                titax_log(  LOG_ERROR,
                            "%s:%d: unkwnown exception - dying!\n",
                            __func__,
                            __LINE__                                );

                /* dying */
                throw;
            }
        }

        ~wada_t()
        {
            fini_api();
        }

        bool configure( wada_cfg_arg_t  )                                 noexcept;
        bool reload_from_files()                                          noexcept;
        bool reload_from_http( lines_t , csize_t )                        noexcept;
        bool user_find_by_ip( c_raw_ipaddr_t, user_details_arg_t )  const noexcept;
        bool save_to_file( cbool_t )                                      noexcept; 
        size_t count()                                              const noexcept;
        /* not thread safe */
        wada_api_t * as_api()                                             noexcept;

        protected:

            wada_cfg_t cfg_ = {};

            //bool configured{};

            wada_t()=delete;

            /* not thread safe */
            void init_api();

            /* not thread safe */
            void fini_api() noexcept;

            using pred_status_t=tools::status_pair_t<wada_t * const>;

            /* not thread safe */
            static pred_status_t is_not_null() noexcept;

            template <typename CODE>
            static auto static_call( CODE c ) -> decltype( c(nullptr) )
            {
                return tools::algorithms::exec_if( c, is_not_null );
            }


            friend bool parse_ip_dell( line_t, csize_t, cbool_t, wada_log_t* );
            friend bool parse_ip_add( line_t, csize_t, cbool_t, wada_log_t*  );
            friend bool parse_user_add( line_t, csize_t, cbool_t, wada_log_t*  );

    }; /* wada_t struct */

};/* titan_v3 namespace */

#ifdef TTN_ATESTS
extern std::ostream &operator<<(std::ostream&, stats_4test_t);
#endif


/* vim: set ts=4 sw=4 et : */

