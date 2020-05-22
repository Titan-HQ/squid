/*
 * Copyright (c) 2006-2012, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 */

/* 
 * File:   titan_instance_tracker.h
 * Author: cmurray
 *
 * Created on 18 May 2017, 09:20
 */

#ifndef INSTANCE_TRACKER_H
#define INSTANCE_TRACKER_H

//#include <list>
#include <vector>
#include <mutex>
#include <cstdint>
#include <chrono>
#include <string>
#include <functional>
#include <iostream>

/*
 * Intent: Create a class that can be used to track life time on objects.
 * How:
 * * Create a global named instance for your class
 * * Upon instantiation register the (void *) this with the tracker
 * * Upon distruction deregister
 * * When desired (say on an event) call check( uint32_t a_older_than_secs) to
 *   send a list of items older than the argument to debugs(). Optionally 
 *   provide a printer function.
 */
class titan_instance_tracker 
{
public:
    explicit titan_instance_tracker( const char * tracker_name );
    virtual ~titan_instance_tracker();
    titan_instance_tracker(const titan_instance_tracker& orig) = delete;  
     
    bool Add( void * a_new_instance );
    bool Remove( void * a_instance );
    bool Check( std::ostream & a_os, uint32_t a_older_than_secs = 60, std::function< void( void *i, std::ostream & s)> a_printer = nullptr );

private:
    struct tracker_data
    {
	void * tracked_instance;
	std::chrono::time_point<std::chrono::system_clock> when_added;
    };
    std::string m_tracker_name;
    std::vector< const tracker_data * > m_instances;   /*Items being tracked*/
    std::mutex m_instances_lock;
    unsigned long m_count_adds;
    unsigned long m_count_removes;
   
    bool check_exists( void * a_instance);
};

void Check_Titan_trackers_and_usage( std::ostream & a_os, unsigned int a_age_in_seconds = 600 );

#endif /* INSTANCE_TRACKER_H */

