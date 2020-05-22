/*
 * $Id$
 */
#include "DbListener.hxx"
#include "DbUserRequestTask.hxx"
#include "TitanScheduler.hxx"
#include "TitanSchedulerAPI.hxx"
#include "TitanUser.hxx"
#include "TitaxConf.h"
#include "db_pg.hxx"
#include "edgepq.h"
#include "log.h"
#include "titaxlib.h"
#include "ttn_groups.hxx"
#include <atomic>
#include <cstdlib>
#include <iostream>
#include <list>
#include <thread>

using namespace titan_v3::globals;
using namespace titan_v3::tools;


static DbListener    db_listener{};
static std::thread   listener{};

tx_static_assert_type(  decltype( std::declval<ids_t>().ids ),
                        policy_id_t,
                        "Unable to compile, the base type of the t_group_policy->ids "\
                        "differs from the expected (policy_id_t)\n"                       );

static 
void updateUserPoliciesAndGroups(   PGconn * const __restrict db,
                                    id_list_t id_list             )
{

    if (!db || id_list.empty()) {
        return;
    }

    std::string list_query{};

    for (const size_t id: id_list) {

        if ( list_query.size() ) {

             list_query+={','};

             list_query+=std::to_string(id);

             continue;
        }

        list_query="in (";

        list_query+=std::to_string(id);
    }

    list_query+={')'};

    auto sql = std::string{ UserContext::policies_query + list_query };
    pgresult_uniq_t rset{ pq_get_rset(  db,
                                        sql.c_str() ) };

    if ( rset ){

        const auto & stat = load_ids_for_policies_and_groups( rset.get() ) ;

        if ( stat.second && users_cache ) {

            users_cache->updateUsers( stat.first );

            return;
        }
    }

    titax_log(  LOG_ERROR,
                "%s:%d::loading IDs for the policies and groups has failed\n",
                __func__,
                __LINE__                                                       );
}

static
void processList(   std::string& command,
                    const std::size_t start, 
                    std::function<void(size_t)> actions ) 
{

    std::size_t begin_pos{start};
    std::size_t end_pos{};

    //Extract the ids from the command. They come in the form: 1,2,3,4 ...
    while ( end_pos < std::string::npos ) {

        end_pos = command.find(',', begin_pos);

        actions(stoul(command.substr(begin_pos, end_pos - begin_pos)));

        begin_pos = end_pos + 1;
    }
}

void DbListener::processNotify(const PGnotify * const __restrict notify) 
{
    /*
    * this will only work assuming that pgnotifications are triggered only on one node (aka master)
    * otherwise we will endup with two masters.
    */

    size_t esz{};

    if ( notify->extra && (esz=strlen(notify->extra)) > 12 ) {

        std::string command{notify->extra,esz};

        if ( !command.compare(0, 5, "users") ) {

            if ( !command.compare(6, 6, "UPDATE") ) {

                //Store ids of loaded users in a list to create and SQL query.
                id_list_t id_list;
                auto create_list = [&](size_t id) {

                    if ( users_cache && users_cache->isUserLoaded(id)) {

                        id_list.emplace_back(id);
                    }
                }; /* lambda */

                processList(command, 13, create_list);
                /* how about cpyeli? */
                updateUserPoliciesAndGroups(context.getDbConnection(),id_list);
            }
            else if ( !command.compare(6, 6, "DELETE") ) {

                //Remove the ids from the users cache
                auto remove_user = [](size_t id) {

                    if ( users_cache ) {

                        users_cache->removeUserById(id);
                    }
                }; /* lambda */

                processList(command, 13, remove_user);
            }
        }
        else if ( !command.compare(0, 6, "groups") ) {

            if (PGconn * const db=context.getDbConnection()){

                /* locking scope */
                mx_scoped_wrapper_t grw_wrp{sGroupMutex};
                titax_load_groups(db);
            }
        }
        else if ( !command.compare(0, 6, "RELOAD") ) {

            if ( PGconn * const db = context.getDbConnection() ) {

                if ( users_cache ) {

                    users_cache->cleanUsers();
                }

                titax_load_user_dic(db);

                /* locking scope */
                mx_scoped_wrapper_t grw_wrp{sGroupMutex};
                titax_load_groups(db);
            }
        }
    }
}


void DbListener::mainLoop()
{
    constexpr char listen_command[]{"LISTEN policy_change"};

    int pg_fd{ INVALID_ }, pg_pid{ INVALID_ };

    size_t try_ctx{};

    bool master_set{};

    auto invalidate_=[&]()
    {
        pg_pid = INVALID_;

        pg_fd = INVALID_;
    }; /* lambda */

    auto close_db_=[&]()
    {
        context.closeDbConnection();

        invalidate_();

        std::this_thread::sleep_for(std::chrono::seconds{DEF_DB_CON_TTL});
    }; /* lambda */

    PGconn * old_conn_{ context.getDbConnection() };

    constexpr size_t try_max{32};

    constexpr int max_sec{300};

    while ( !shutdown && old_conn_ ) {

        PGconn * const conn_{ context.getDbConnection() };

        if ( conn_ && !shutdown ) {

            if ( old_conn_ != conn_ ) {

                old_conn_ = conn_;

                invalidate_();
            }

            try_ctx = 0;

            bool ok_pid{}, ok_fd{};

            /* process */
            if (    ( ok_pid = ( pg_pid == PQbackendPID( conn_ ) && pg_pid != INVALID_ ) )  &&

                    ( ok_fd = ( pg_fd == PQsocket( conn_ ) && pg_fd != INVALID_ ) )             ) {

                /* process notifications */
                fd_set input_mask;

                FD_ZERO(&input_mask);

                FD_SET(pg_fd, &input_mask);

                /*
                 * Sleep until something happens on the connection or timeout.  We use select(2)
                 * to wait for input, but you could also use poll() or similar
                 * facilities.
                 */
                struct timeval timeout={ .tv_sec=max_sec };

                errno = 0 ;

                const int s_{  select(  pg_fd + 1, 
                                        &input_mask, 
                                        nullptr,
                                        nullptr,
                                        static_cast<struct timeval *const>(&timeout) ) };
                if ( !shutdown ) {

                   switch ( s_ ) {

                      case INVALID_:

                         if ( errno && errno!=EINTR ) {

                            const char * const cerr{ strerror(errno) };

                            titax_log(  LOG_WARNING,
                                        "%s:%d::select failed: (%d) %s[%d|%d|%s], "
                                        "waiting for %d sec\n",
                                        __FILE__,
                                        __LINE__,
                                        errno,
                                        (cerr?:"<NULL>"),
                                        pg_fd,
                                        pg_pid,
                                        PQerrorMessage(conn_),
                                        DEF_DB_CON_TTL                                  );

                            close_db_();
                         }

                      [[clang::fallthrough]];

                      case 0: continue;

                      default:

                         if ( !master_set ) {

                            titax_conf_set_master(true, true);
                         }

                         if ( PQconsumeInput(conn_) ) {

                            /* Now check for input */
                            while ( PGnotify   * const notify = PQnotifies(conn_) ) {

                               processNotify(notify);

                               PQfreemem(notify);
                            }

                         } 
                         else {

                            titax_log(  LOG_WARNING,
                                        "%s:%d::DB:PQconsumeInput problem:%s\n",
                                        __FILE__,
                                        __LINE__,
                                        PQerrorMessage(conn_)                        );

                            close_db_();
                         }

                      continue;
                   } /* switch */
                }
                else
                    break; /* the main loop */

            } /* ok pid & fd fi */

            /* subscribe */
            if ( !ok_pid || INVALID_ == pg_pid ) {

                using namespace titan_v3::tools;

                pgresult_uniq_t rset{ pq_get_rset( conn_, listen_command ) };

                if ( rset ){

                    pg_fd=INVALID_;

                    ok_fd=false;

                    pg_pid = PQbackendPID(conn_);

                } 
                else  {

                    titax_log(  LOG_WARNING, 
                                "%s:%d::DB::unable to register for notifications [%s],"
                                "waiting for %d sec\n",
                                __FILE__,
                                __LINE__,
                                PQerrorMessage(conn_),
                                DEF_DB_CON_TTL                                              );

                    close_db_();
                }
            } /* subscribe fi */

            /* get new fd */
            if (    pg_pid != INVALID_                  &&

                    ( !ok_fd || INVALID_ == pg_fd )     && 

                    ( pg_fd = PQsocket(conn_) ) < 0         ) {

                /* highly unlikely */
                titax_log(  LOG_WARNING, 
                            "%s:%d::DB::unable to open notification socket [%s],"
                            "waiting for %d sec\n",
                            __FILE__,
                            __LINE__,
                            PQerrorMessage(conn_),
                            DEF_DB_CON_TTL                                           );

                close_db_();
            } /* new fd fi */

            continue;

        } /* conn_ fi */

        if ( try_ctx++ < try_max ) {

            titax_log(  LOG_WARNING, 
                        "%s:%d::DB::unable to connect to the DB, "
                        "waiting for %d sec\n",
                        __FILE__,
                        __LINE__,
                        DEF_DB_CON_TTL                                  );

            close_db_();

            continue;
        } /* try_ctx fi */

        /* cleanup */
        close_db_();

        old_conn_ = nullptr;

        break; /* the main loop */

    } /* main loop */

    if ( shutdown ) {

        titax_log(  LOG_WARNING, 
                    "%s:%d::shutdown detected \n",
                    __FILE__,
                    __LINE__                         );
        return;
    }

    if ( !old_conn_ ) {

        titax_log(  LOG_ERROR, 
                    "%s:%d::DB::unable to connect to the DB, "
                    "shutting down NOW!\n",
                    __FILE__,
                    __LINE__                                        );
    }
    else {

        titax_log(  LOG_ERROR, 
                    "%s:%d:UNKNOWN ERROR DETECTED, "
                    "shutting down NOW!\n",
                    __FILE__,
                    __LINE__                                        );
    }

    shutdown = true;

    /* should teardown the whole process */
    std::exit(INVALID_);

}

void DbListener::orderShutdown()
{ 
    shutdown = true;

    context.closeDbConnection();
}

void startDbListenerThread()
{
    listener = std::thread(&DbListener::runNow, &db_listener);
}

void orderDbListenerShutdown()
{
    db_listener.orderShutdown();

    if ( listener.joinable() ) {

        listener.join();
    }
}

/* vim: set ts=4 sw=4 et : */
