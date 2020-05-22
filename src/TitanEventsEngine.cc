/*
 * TitanEventsEngine.cc
 *
 */

#include "TitanEventsEngine.h"
#include "TitanUser.hxx"

int TitanEventsEngine::checkEvents(int timeout) {
   RequestTask* done_tasks = db_receiver.getDoneTasks();
   while (done_tasks != NULL) {
      done_tasks->makeCallback();

      RequestTask* completed = done_tasks;
      done_tasks = done_tasks->next;
      delete completed;
   }

   return EVENT_IDLE;
}
