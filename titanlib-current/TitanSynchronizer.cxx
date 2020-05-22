/*
 * $Id$
 */
#include "TitanSynchronizer.hxx"
#include "TitanUser.hxx"
#include "ttn_app_modes.hxx"
#include "TAPE.hxx"
#include <iostream>
#include <thread>

using namespace titan_v3;
using namespace titan_v3::tools;

static TitanSynchronizer ttn_synchronizer;
static std::thread synchronizer;

void TitanSynchronizer::mainLoop() 
{
   while ( users_cache && !shutdown ) {

      //Get the requests from pending list
      if ( PGconn * const conn=context.getDbConnection() ) {

         users_cache->synchronize(conn);
      }

      std::this_thread::sleep_for(std::chrono::seconds{2});
    }
}

void startSynchronizerThread()
{
   /* disable for now in WTC until we fix the CloudKeys (alt policy)  */ 

   if ( app_mode_t::gateway == GTAPE.app_mode ) {

      synchronizer = std::thread(&TitanSynchronizer::runNow, &ttn_synchronizer);
   }
}

void orderSynchronizerShutdown()
{
   if ( app_mode_t::gateway == GTAPE.app_mode ) {
   
      ttn_synchronizer.shutdownNow();

      if (synchronizer.joinable()) {

         synchronizer.join();
      }
   }
}

