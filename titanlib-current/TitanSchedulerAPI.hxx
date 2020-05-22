/*
 * $Id$
 */

#ifndef TITANSCHEDULERAPI_H_
#define TITANSCHEDULERAPI_H_

#include <memory>

#include "RequestTask.hxx"
#include "global.h"

/**
 * @fn fetchUserFromDb
 * @param ctx [in] RequestContext_uptr_t/RequestContext ptr 
 * @param cb [in] callback_type_t ptr defaults to null
 * @param cb_data [in] void ptr  defaults to null
 * @param rcv [in] Receiver defaults to null
 *
 */
void fetchUserFromDb(RequestContext_uptr_t, callback_type_t* cb=nullptr, void* cb_data=nullptr, Receiver* rcv=nullptr );

inline 
void fetchUserFromDb(RequestContext * ctx, callback_type_t* cb=nullptr, void* cb_data=nullptr, Receiver* rcv=nullptr ){

   fetchUserFromDb(/* move the ownership of the ctx */ RequestContext_uptr_t{ctx},cb,cb_data,rcv);

}

/**
 * @fn modifyUser
 * @param ctx[in] RequestContext_uptr_t
 */
extern void modifyUser(RequestContext_uptr_t);

/**
 * @name startSchedulerThread
 * @abstract use this method to start TitanScheduler thread
 */
extern void startSchedulerThread();

/**
 * @name orderSchedulerShutdown
 * @abstract use this method to shutdown TitanScheduler thread
 */
extern void orderSchedulerShutdown();

#endif /* TITANSCHEDULERAPI_H_ */
