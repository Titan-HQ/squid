/*
 * $Id$
 */

#include "RequestTask.hxx"
#include "TitanScheduler.hxx"

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros
 */
static int do_RequestTask_tracing = 0;  /*Change to non zero to enable tracing*/
/* Connot use conextexpr or const above as -Wunreachable-code triggers */

titan_instance_tracker *get_titan_instance_tracker_RequestTask()
{
   /* Create on first access, using double checked lock */
   static titan_instance_tracker *g_RequestTask_tracker{};
   static std::mutex l_lock{};

   std::lock_guard<std::mutex> l_lg( l_lock );

   if ( !g_RequestTask_tracker ) {

      g_RequestTask_tracker = new titan_instance_tracker("RequestTask");

   }

   return g_RequestTask_tracker;
}
void print_tracked_RequestTask( void *a_p, std::ostream & a_s)
{
    auto * p_item = static_cast< RequestTask *>( a_p );
    p_item->dump_info( a_s );
}
void Check_tracker_RequestTask( std::ostream & a_os, uint32_t a_older_than_secs)
{
    if (do_RequestTask_tracing != 0)
    {
        get_titan_instance_tracker_RequestTask()->Check(a_os, a_older_than_secs, print_tracked_RequestTask);
    }
    else
    {
        a_os << " RequestTask instance tracking is not enabled (" << a_older_than_secs <<")\n";
    }
}

////////////////////////////////////////////////////////////////////////////////


void RequestTask::execute(SchedulerContext & sch_context) {
   if (context)
      context->execute(sch_context);
}

RequestTask::RequestTask(RequestContext_uptr_t ctx) noexcept : context{/* move the ownership of the ctx */ std::move(ctx)}
{
    if (do_RequestTask_tracing != 0) get_titan_instance_tracker_RequestTask()->Add( this );
}

RequestTask:: ~RequestTask()
{
    if (do_RequestTask_tracing != 0 ) get_titan_instance_tracker_RequestTask()->Remove( this );
}
