/*
 * $Id$
 */

#ifndef TITANSYNCHRONIZER_H_
#define TITANSYNCHRONIZER_H_

#include <atomic>

#include "TitanScheduler.hxx"
#include "global.h"

/**
 * @class TitanSynchronizer
 * @based ttn_scheduler_runner_t
 */
class TitanSynchronizer:public ttn_scheduler_runner_t<TitanSynchronizer> {
public:
   /**
    * @method orderShutdown
    * @abstract don't call it directly it is an implementation of the base interface
    */
   void orderShutdown() { shutdown = true; }
   /**
    * @method mainLoop
    * @abstract don't call it directly it is an implementation of the base interface
    */   
   void mainLoop();
};

/**
 * @name startSynchronizerThread
 * @abstract use this method to start TitanSynchronizer thread
 */
extern void startSynchronizerThread();

/**
 * @name orderSynchronizerShutdown
 * @abstract use this method to shutdown TitanSynchronizer thread
 */
extern void orderSynchronizerShutdown();

#endif /* TITANSYNCHRONIZER_H_ */
