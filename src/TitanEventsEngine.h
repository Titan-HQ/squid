/*
 * TitanEventsEngine.h
 *
 */

#ifndef TITANEVENTSENGINE_H_
#define TITANEVENTSENGINE_H_

#include "AsyncEngine.h"
#include "RequestTask.hxx"

class TitanEventsEngine : public AsyncEngine
{
public:
   int checkEvents(int timeout);
};

#endif /* TITANEVENTSENGINE_H_ */
