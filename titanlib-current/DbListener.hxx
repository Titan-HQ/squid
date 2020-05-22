/*
 * $Id$
 */


#ifndef DBLISTENER_H_
#define DBLISTENER_H_

#include <list>
#include <functional>
#include "TitaxUser.h"
#include "edgepq.h"
#include "TitanScheduler.hxx"
#include "global.h"


using id_list_t=std::list<size_t>;

class DbListener:public ttn_scheduler_runner_t<DbListener> {
   void processNotify(const PGnotify * const notify);
public:
   void mainLoop();
   void orderShutdown();
};

/**
 * @name startDbListenerThread
 * @abstract use this method to start DbListener thread
 */
extern void startDbListenerThread();

/**
 * @name orderDbListenerShutdown
 * @abstract use this method to shutdown DbListener thread
 */
extern void orderDbListenerShutdown();


#endif /* DBLISTENER_H_ */
