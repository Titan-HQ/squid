/*
 * $Id$
 */

#ifndef TITANSCHEDULER_H_
#define TITANSCHEDULER_H_

#include "RequestTask.hxx"
#include "edgepq.h"
#include "ttn_errors.hxx"
#include <atomic>
#include <mutex>
#include <condition_variable>

/**
 * @class SchedulerContext
 * @abstract basic db context
 */
class SchedulerContext {
   PGconn* conn{};
public:
   SchedulerContext();
   virtual ~SchedulerContext();
   PGconn* getDbConnection();
   void closeDbConnection();
};

/**
 * @template ttn_runner_t
 * @abstract CRTP based template, provides polymorphism without the runtime overhead
 * 
 */
template<class D,class C>
struct ttn_runner_t{
   /**
    * @method shutdownNow
    * @abstract will call the orderShutdown method
    */
   void shutdownNow(){
      if (D* const obj=static_cast<D*>(this))
         obj->orderShutdown();
      else /* impossible */
         throw titan_v3::tools::errors::nullptr_error();
   }
   /**
    * @method runNow
    * @abstract will call the mainloop method
    */
   void runNow(){
      if (D* const obj=static_cast<D*>(this))
         obj->mainLoop();
      else /* impossible */
         throw titan_v3::tools::errors::nullptr_error();
   }

   protected:
      C context{}; /* the context is pinned - will never change */
      std::atomic<bool> shutdown{};
};


/**
 * @template ttn_scheduler_runner_t
 * @based ttn_runner_t
 * @abstract partial specialization of ttn_runner_t
 */
template<class D>
struct ttn_scheduler_runner_t:ttn_runner_t<D,SchedulerContext>{};


/**
 * @class TitanScheduler
 * @based ttn_scheduler_runner_t
 */
class TitanScheduler:public ttn_scheduler_runner_t<TitanScheduler> {
   std::mutex              pending_lock{};
   std::condition_variable pending_cv{};
   RequestTask*            pending_head{};
   RequestTask*            pending_tail{};
public:

   TitanScheduler()=default;

   void scheduleTask(RequestTask* const task);
   /**
    * @method orderShutdown
    * @abstract don't call it directly it is an implementation of the base interface
    */   
   void orderShutdown();
   /**
    * @method mainLoop
    * @abstract don't call it directly it is an implementation of the base interface
    */
   void mainLoop();
};

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */
unsigned int get_count_TitanSCheduler_exceptions();
unsigned int get_count_TitanSCheduler_tasks_scheduled();
unsigned int get_count_TitanSCheduler_tasks_done();
unsigned int get_Scheduler_Context_active_instances();
#endif /* TITANSCHEDULER_H_ */
