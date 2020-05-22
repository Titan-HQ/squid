/*
 * $Id$
 */

#ifndef REQUESTTASK_H_
#define REQUESTTASK_H_

#include <mutex>
#include <memory>
#include <string>

#include "titan_instance_tracker.hxx"


class RequestTask;

typedef void callback_type_t(RequestTask&);

class Receiver;

class SchedulerContext;

class RequestContext {
public:
   enum class ResultCode {
      Success,
      DbError,
      UserNotFound
   };

protected:
   ResultCode result{ResultCode::Success};
public:
   virtual ~RequestContext()=default;

   virtual void execute(SchedulerContext & sch_context) = 0;

   inline
   ResultCode getResult() const noexcept { return result; }

   inline
   bool isSuccess() const noexcept { return ( result == ResultCode::Success ); }
};

using RequestContext_uptr_t=std::unique_ptr<RequestContext>;

class RequestTask {
protected:
   /* relased on destroy */
   callback_type_t* const   callback{};
   /* relased on destroy */ 
   void * const             callback_data{};
   /* relased on destroy */
   Receiver  * const        receiver{};
   /* if not empty the context will be deleted on destroy */
   RequestContext_uptr_t   context{};

public:
   RequestTask*             next{};

   explicit RequestTask( RequestContext_uptr_t ) noexcept;

   RequestTask( callback_type_t* cb,
                void* cb_data,
                Receiver* rcv,
                RequestContext_uptr_t  ctx /* pass the ownership */) noexcept :  callback{cb}, 
                                                                                 callback_data{cb_data}, 
                                                                                 receiver{rcv}, 
                                                                                 /* move the ownership of the ctx */ 
                                                                                 context{std::move(ctx)}
                                                                                 {}

   virtual ~RequestTask();

   virtual void execute(SchedulerContext &);

   inline Receiver * getReceiver() const noexcept { 
       return receiver; 
   }

   inline void * getCallback_data() const noexcept {
       return callback_data; 
   }

   inline RequestContext_uptr_t getRequestContext() noexcept { 
      return std::move(context);
   }

   inline void makeCallback(){
      callback(*this);
   }
   
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros
 */

   inline
   void dump_info( std::ostream & a_os )const noexcept {
       a_os << "callback [" << this->callback << "] receiver [" << this->receiver <<std::endl;
   }
};

class Receiver {
   std::mutex done_lock;
   RequestTask* done_head{};
   RequestTask* done_tail{};

public:
   Receiver()=default;
   virtual ~Receiver()=default;
   void addDoneTask(RequestTask* done_task)noexcept {
      
      std::lock_guard<std::mutex> lg{done_lock};
      if (!done_head) {
         done_head = done_tail = done_task;
      }
      else {
         done_tail->next = done_task;
         done_tail = done_task;
      }
   }

   RequestTask* getDoneTasks() noexcept {

      std::lock_guard<std::mutex> lg{done_lock};
      RequestTask* done_tasks{done_head};
      done_head = done_tail = nullptr;

      return done_tasks;
   }
};


////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */

titan_instance_tracker *get_titan_instance_tracker_RequestTask();
void print_tracked_RequestTask( void *a_p, std::ostream & a_s );
void Check_tracker_RequestTask( std::ostream & a_os, uint32_t a_older_than_secs);
#endif /* REQUESTTASK_H_ */
