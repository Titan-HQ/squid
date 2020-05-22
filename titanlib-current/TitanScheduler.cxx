/*
 * $Id$
 */

#include "TitanScheduler.hxx"
#include "log.h"
#include "log.h"
#include "titaxlib.h"
#include <chrono>
#include <iostream>
#include <thread>

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */
static unsigned int g_TitanSCheduler_exceptions = 0;
static unsigned int g_count_TitanSCheduler_tasks_scheduled = 0;
static unsigned int g_count_TitanSCheduler_tasks_done = 0;
static unsigned int g_Scheduler_Context_instances_c = 0;
static unsigned int g_Scheduler_Context_instances_d = 0;
unsigned int get_Scheduler_Context_active_instances()
{
    return( g_Scheduler_Context_instances_c - g_Scheduler_Context_instances_d );
}
SchedulerContext::SchedulerContext()
{
    g_Scheduler_Context_instances_c++;
}

unsigned int get_count_TitanSCheduler_exceptions()
{
    return( g_TitanSCheduler_exceptions );
}
unsigned int get_count_TitanSCheduler_tasks_scheduled()
{
    return g_count_TitanSCheduler_tasks_scheduled;
}
unsigned int get_count_TitanSCheduler_tasks_done()
{
    return( g_count_TitanSCheduler_tasks_done );
}
////////////////////////////////////////////////////////////////////////////////



SchedulerContext::~SchedulerContext()
{
    closeDbConnection();

    /* DI */
    g_Scheduler_Context_instances_d++;
}

PGconn* SchedulerContext::getDbConnection()
{
    return (    check_raw_dbconn( &conn, 16, &db_config_connect )   ?

                conn                                                :

                nullptr                                                 );
}

void SchedulerContext::closeDbConnection()
{
    if ( conn ) {

        pq_conn_close(conn);

        conn=nullptr;
    }
}

void TitanScheduler::scheduleTask( RequestTask* const __restrict task )
{
    std::lock_guard<std::mutex> lg(pending_lock);

    if ( !shutdown ) { 

        if ( pending_head == nullptr ) {

            pending_head = pending_tail = task;

            task->next = nullptr;
        }
        else {

            pending_tail->next = task;

            pending_tail = task;

            task->next = nullptr;
        }

        /* DI */
        g_count_TitanSCheduler_tasks_scheduled++;

        pending_cv.notify_one();
    }
}

void TitanScheduler::mainLoop() 
{
    /* 
    * Connect early to avoid double penalty for the first request (latency) or die.
    */

    constexpr int max_sec{300};

    PGconn * conn_{ context.getDbConnection() };

    while ( !shutdown && conn_ ) {

        RequestTask * task{};

        {
            //Get the requests from pending list
            std::unique_lock<std::mutex> ul(pending_lock);

            while ( !shutdown && 

                    pending_head == nullptr &&

                    std::cv_status::timeout == pending_cv.wait_for(ul,std::chrono::seconds(max_sec)) ) {

            } /* wait loop */

            /* relock */

            if ( !shutdown && pending_head!=nullptr ) {

                /* cut of the queue */
                task = pending_head;

                pending_head = pending_tail = nullptr;
            } 
            else if ( shutdown )  {

                break; /* the main loop */
            } 
            else 
                continue;

        } /* unlock on exit from the block */

        /* make sure we have life DB connection */
        conn_ = context.getDbConnection();

        /* tasks processing loop */
        while ( task && conn_ && !shutdown ) {

            RequestTask* const done_task{task};

            /* take next task */
            task = task->next;

            done_task->next = nullptr;

            try { 

                /* execute the task */

                done_task->execute(context);

                if ( Receiver * const resciver = done_task->getReceiver() ) {

                    resciver->addDoneTask(done_task);

                    /* DI */
                    g_count_TitanSCheduler_tasks_done++;
                }
                else {

                    if ( !shutdown ) {

                        delete done_task;
                    }
                    else 
                        break; /* the processing loop */
                }

            }catch ( const std::exception & e ) {

                titax_log(  LOG_WARNING,
                            "%s:%d::exception [%s]\n",
                            __FILE__,
                            __LINE__,
                            e.what()                    );
                /* DI */
                g_TitanSCheduler_exceptions++;
            }

        } /* processing loop */

    } /* main loop */

    if ( shutdown ) {

        titax_log(  LOG_WARNING,
                    "%s:%d::shutdown detected \n",
                    __FILE__,
                    __LINE__                            );
        return;
    }

    if ( !conn_ ) {

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

    std::exit(INVALID_);
}

void TitanScheduler::orderShutdown()
{
    std::lock_guard<std::mutex> lg(pending_lock);

    if ( !shutdown ) { 

        shutdown = true; 

        pending_cv.notify_all();//unlock
    }
}

/* vim: set ts=4 sw=4 et : */
