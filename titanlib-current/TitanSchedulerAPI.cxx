/*
 * $Id$
 */

#include "TitanSchedulerAPI.hxx"
#include "DbUserRequestTask.hxx"
#include "TitanScheduler.hxx"
#include <functional>
#include <iostream>
#include <string>
#include <thread>

static TitanScheduler   ttn_scheduler{};
static std::thread      scheduler;

void fetchUserFromDb(RequestContext_uptr_t ctx, callback_type_t* cb, void* cb_data, Receiver * rcv) {
   if (RequestTask* const new_task = new RequestTask(cb, cb_data, rcv, 
                        /* move the ownership of the ctx */ std::move(ctx)))
      ttn_scheduler.scheduleTask(new_task);
}

void modifyUser(RequestContext_uptr_t ctx) {
   if (RequestTask* const new_task = new RequestTask( /* move the ownership of the ctx */ std::move(ctx)))
      ttn_scheduler.scheduleTask(new_task);
}

void startSchedulerThread() {
   scheduler =std::thread(&TitanScheduler::runNow, &ttn_scheduler);
}

void orderSchedulerShutdown() {
   ttn_scheduler.shutdownNow();
   if (scheduler.joinable()){
      scheduler.join();
   }
}

