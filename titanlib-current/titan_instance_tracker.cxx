/*
 * Copyright (c) 2006-2012, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 */

/* 
 * File:   titan_instance_tracker.cc
 * Author: cmurray
 * 
 * Created on 18 May 2017, 09:20
 */

#include "titan_instance_tracker.hxx"
#include "TAPE.hxx"

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iterator>
#include <sstream>


titan_instance_tracker::titan_instance_tracker(const char * tracker_name) :
    m_tracker_name( tracker_name)
{
    m_instances.clear();
    m_count_adds = 0;
    m_count_removes = 0;
}

titan_instance_tracker::~titan_instance_tracker()
{
    while ( m_instances.empty() != true )
    {
	const tracker_data * a_ti = m_instances.back();
	m_instances.pop_back();
	delete a_ti;
    }
}

bool titan_instance_tracker::check_exists( void * a_instance)
{
    bool l_exists = false;
    for( auto l_i : m_instances)
    {
	if (l_i->tracked_instance == a_instance)
	{
	    l_exists = true;
	    break;
	}
    }
    return(l_exists);
}

bool titan_instance_tracker::Add( void * a_new_instance )
{
    std::lock_guard< std::mutex > l_g( m_instances_lock );
    /*Check to see if this value already exists*/
    if ( check_exists( a_new_instance )  == false )
    {
	auto p_tracked = new tracker_data();
	p_tracked->tracked_instance = a_new_instance;
	p_tracked->when_added = std::chrono::system_clock::now();
	m_instances.push_back( p_tracked );
	m_count_adds++;
	return(true);
    }
    else
    {
	std::cerr << "titan_instance_tracker::Add() : [" << m_tracker_name << "] instance is already on the list\n";
	return(false);
    }
}

bool titan_instance_tracker::Remove( void * a_instance )
{
   std::lock_guard< std::mutex > l_g( m_instances_lock );
   bool l_removed = false;


   auto l_i = m_instances.begin();
   while ( l_i != m_instances.end() ) {
	
      if ((*l_i)->tracked_instance == a_instance) {

         const auto * p_tracked = *(l_i);

         *(l_i) = nullptr;

         try { 
 
            if ( p_tracked ) {

               delete p_tracked;
            }

         } catch ( ... ) {

         }

         m_instances.erase( l_i );
         //TODO:Could maintain min, avg, max age of items added and removed on this tracker list
         m_count_removes++;
         l_removed = true;

         continue;

      }

      ++l_i;
   }

   return l_removed;
}

/*
 * Walk the list of tracked items and if any are older than argument return true.
 * Optionally inoke the "printer" function to output information on older instances.
 */
bool titan_instance_tracker::Check( std::ostream & a_os, uint32_t a_older_than_secs,  
	             std::function< void( void *i, std::ostream & s)> a_printer )
{
    std::lock_guard< std::mutex > l_g( m_instances_lock );

    uint32_t l_old_items_found = 0;
    std::chrono::seconds l_age( a_older_than_secs );
    a_os << "Checking tracker \"" << m_tracker_name << "\" for items older than " << a_older_than_secs << " seconds\n";
    auto l_now = std::chrono::system_clock::now();
    for (auto l_i : m_instances)
    {
	std::chrono::time_point<std::chrono::system_clock> l_when_aged = l_i->when_added;
	l_when_aged += l_age;
	if ( l_when_aged < l_now)
	{
	    l_old_items_found++;
	    std::time_t l_added_t = std::chrono::system_clock::to_time_t( l_i->when_added );
	    a_os << " Aged: [" << m_tracker_name << "] " <<  std::setw(3)
			<< l_old_items_found << " (" << l_i->tracked_instance << ")";
	    a_os << " @ " << std::put_time(std::localtime(&l_added_t), "%T");    
	    if (a_printer != nullptr )
	    {
		std::stringstream l_info;
		a_printer(l_i->tracked_instance, l_info);
		a_os  <<  " : " << l_info.str();
	    }
	    a_os << "\n";
	}
    }
    a_os << "  (Aged total: " << l_old_items_found << " for " << m_tracker_name << ":  added:" << m_count_adds << " removed:" << m_count_removes << " )\n";
    return( l_old_items_found > 0 );
}


extern void Check_tracker_TaTag( std::ostream & a_os, uint32_t a_older_than_secs);
extern void Check_tracker_UserContext( std::ostream & a_os, uint32_t a_older_than_secs);
extern void Check_tracker_RequestTask( std::ostream & a_os, uint32_t a_older_than_secs);
extern unsigned int get_count_TitanSCheduler_tasks_scheduled();
extern unsigned int get_count_TitanSCheduler_tasks_done();
extern unsigned int get_count_TitanSCheduler_exceptions();
extern "C" int get_Ctree_memory_statistic();
extern "C" unsigned int get_StringList_active_instances();
extern "C" unsigned int get_StringMap_active_instances();
extern "C" unsigned int get_DataBuff_active_instances();
extern "C" unsigned int get_PGresult_active_instances();
extern unsigned int get_Sbuff_active_instances();
extern unsigned int get_Scheduler_Context_active_instances();


void Check_Titan_trackers_and_usage( std::ostream & a_os, unsigned int a_age_in_seconds )
{
    a_os << "\n";
   titan_v3::Output_GTAPE_information( a_os );   
   a_os << "Instance Trackers invocation\n";
   titan_v3::Check_tracker_TaTag(      a_os, a_age_in_seconds);
   Check_tracker_UserContext( a_os, a_age_in_seconds );
   Check_tracker_RequestTask( a_os, a_age_in_seconds);
   //a_os << " TitaxConf instances (c-d) : " << get_TitaxConf_active_instances(); //Always 1
   a_os << "\n TitanScheduler:  tasks requested : " << get_count_TitanSCheduler_tasks_scheduled() << " tasks done : " << get_count_TitanSCheduler_tasks_done();
   a_os << "\n SchedulerContext active instances : " << get_Scheduler_Context_active_instances();
   a_os << "\n g_TitanSCheduler_exceptions : " << get_count_TitanSCheduler_exceptions();
   a_os << "\n Ctree memory : " << get_Ctree_memory_statistic();
   a_os << "\n StringMap active instances : " << get_StringMap_active_instances();
   a_os << "\n StringList active instances : " << get_StringList_active_instances();
   a_os << "\n DataBuff active instances : " << get_DataBuff_active_instances();
   a_os << "\n PGResult active instances : " << get_PGresult_active_instances();
   a_os << "\n SBuff active instances : " << get_Sbuff_active_instances();
   a_os << "\n";
}
