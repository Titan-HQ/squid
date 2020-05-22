/*
 * $Id$
 *
 * Copyright (c) 2005-2013, Copperfasten Technologies, Teoranta.  All rights
 * reserved.  Unpublished rights reserved under the copyright laws of
 * the United States and/or the Republic of Ireland.
 *
 * The software contained herein is proprietary to and embodies the
 * confidential technology of Copperfasten Technologies, Teoranta.
 * Possession, use, duplication or dissemination of the software and
 * media is authorized only pursuant to a valid written license from
 * Copperfasten Technologies, Teoranta.
 *
 */

#include "Group.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ipc.h>
#include <sys/msg.h>
#include <sys/sem.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#include "log.h"
#include "ttn_groups.hxx"

TXATR void titax_log(const int level, const char *const fmt, ...);

pthread_mutex_t   sGroupMutex = PTHREAD_MUTEX_INITIALIZER;

TSA_GUARDED_BY(sGroupMutex)
static POLICY *   sPolicyTable = NULL;

TSA_GUARDED_BY(sGroupMutex)
static size_t     sPolicyCount = 0;

TSA_GUARDED_BY(sGroupMutex)
static GROUP *    sGroupTable = NULL;

TSA_GUARDED_BY(sGroupMutex)
static size_t     sGroupCount = 0;

size_t getGroupCount()
{
   size_t ret = 0; 

   LOCKGROUPTABLE();

   ret = sGroupCount;

   UNLOCKGROUPTABLE();

   return ret;
}


/*
 * There are two access masks based upon the URL categories.
 * One is used for access checking during working hours.
 * The other is used for determining access for non-working hours.
 * If a bit is set in the mask, that means that the category may be
 * accessed during the current time interval.
 * The appropriate mask is copied to the "categoryMask" variable
 * according to the current time period.
 */
struct setAccessMasks_elems_{uint_fast64_t i_; POLICY * pitem;t_mask thisBit;CATEGORYPERMS * cat_table;};

TSA_CAP_TR_RQ(sGroupMutex)
static void setAccessMasks(const size_t policyIndex)
{
   if (UWITHIN_(sPolicyCount, policyIndex)){
      struct setAccessMasks_elems_ e={.pitem=&sPolicyTable[policyIndex]};
      e.pitem->workingHoursMask=0;
      e.pitem->nonWorkingHoursMask=0;
      e.cat_table=e.pitem->categoryTable;
      for (;e.i_<MAX_CATEGORIES;++e.i_){
         e.thisBit = ((t_mask)1) << e.i_;
         if (e.cat_table[e.i_].allowWorking)
            e.pitem->workingHoursMask    |= e.thisBit;
         if (e.cat_table[e.i_].allowNonWorking)
            e.pitem->nonWorkingHoursMask |= e.thisBit;
      }
   }
}

TSA_CAP_TR_RQ(sGroupMutex)
static void remap_groups_and_policies()
{
   clearGroupPolicyMaps();

   for (size_t i = 0; i < sGroupCount; ++i) {
      addGroupId(sGroupTable[i].groupNumber, i);
   }

   for (size_t i = 0; i < sPolicyCount; ++i) {
      addPolicyId(sPolicyTable[i].policyId, i);
      setAccessMasks(i);
   }
}


/**
 * @internal
 * @name get_group_by_groupNumber_
 * @warning not thread-safe
 * always use within the block protected by LOCKGROUPTABLE & UNLOCKGROUPTABLE
 * @param groupNumber
 * @param out
 * @param copy
 * @return t/f
 */
TSA_CAP_TR_RQ(sGroupMutex)
static bool get_group_by_groupNumber_(const int groupNumber, GROUP **out,const bool copy)
{
   if (out){
      t_search_val v_={
         .stype.groupNumber=true,
         .svalue.ival=groupNumber,
         .in_groups=sGroupTable,
         .in_groups_count=sGroupCount
      };
      void * ptr_t = v_.in_groups;
      void * ptr_v = sGroupTable;

      if (find_group_by(&v_) && v_.out_group){
         if (!copy && (*out=v_.out_group)){
            if ((*out < sGroupTable) || (*out >= (sGroupTable + sGroupCount))) {

               titax_log(LOG_ERROR , "V_ values: Out:  %p. V_.out: %p. Table: %p."
                     " Count: %zu\n", (void *) *out, (void *) v_.out_group, (void *) v_.in_groups,
                     v_.in_groups_count);
               titax_log(LOG_ERROR , "Tables before: %p   ---   %p.\n", ptr_v, ptr_t);

               titax_log(LOG_ERROR , "Index %zu. Element: %p\n", v_.out_group_idx,
                         (void *) &v_.in_groups[v_.out_group_idx]);

               titax_log(LOG_ERROR , "Table values: Out:  %p. Table: %p."
                     " Count: %zu\n", (void *) &sGroupTable[v_.out_group_idx], (void *) sGroupTable, sGroupCount);
            }
            return true;
         }
         **out=*v_.out_group;
         return true;
      }
      /* The group number is not found - Some error. Set to default one */
      /* mscott: What error is 'some' error??? */
      if (copy && tx_safe_memcpy(*out, &sGroupTable[0], sizeof(GROUP))){
         titax_log(LOG_WARNING , "Unknown group %u\n",groupNumber);
      }
   }
   return false;
}

bool getGroup(const int groupNumber, GROUP *dst)
{
   bool r = false ;

   {
      LOCKGROUPTABLE();

      r = get_group_by_groupNumber_(groupNumber,&dst,true);

      UNLOCKGROUPTABLE();
   }

   return r;
}

bool getGroup_without_lock(const int groupNumber, GROUP **out)
{
   return get_group_by_groupNumber_(groupNumber,out,false);
}

bool getPolicy_without_lock(const int policyId, POLICY **out)
{

   if (sPolicyTable) {
      long index;
      if (INVALID_!=(index = getPolicyIndex(policyId))) {
         *out = &sPolicyTable[index];
         return true;
      }
   }
   return false;
}

bool getPolicy(const int policy_id, POLICY *dst)
{

   bool r = false ;
   {
      LOCKGROUPTABLE();

      POLICY *buffer;
      r = getPolicy_without_lock(policy_id, &buffer);
      if ( r ) {

         tx_safe_memcpy(dst, buffer, sizeof(POLICY));
      }

      UNLOCKGROUPTABLE();
   }
   return r;
}

bool findGroupByName(const char *const name, GROUP *dst)
{
   bool ret=false;
   if (dst && name && name[0]){

      LOCKGROUPTABLE();

      t_search_val v_={
         .stype.groupName=true,
         .svalue.cptr=name,
         .in_groups=sGroupTable,
         .in_groups_count=sGroupCount
      };

      if (find_group_by(&v_) && v_.out_group){
         *dst=*v_.out_group;
         ret=true;
      }

      UNLOCKGROUPTABLE();
   }
   return ret;
}


void checkAccessTimes()
{
   time_t tim = time(NULL);
   struct tm  t;
   localtime_r(&tim, &t);

   struct elems {uint_fast64_t i_; const uint_fast64_t max_; POLICY * ptable_;size_t period_;size_t dayBitMask_; size_t minutesSinceMidnight_;};
   /* Iterate through groups */
   for (struct elems e={
         .max_=sPolicyCount,
         .ptable_=sPolicyTable,
         .dayBitMask_=(1U << t.tm_wday),
         .minutesSinceMidnight_=(size_t)((t.tm_hour * 60) + t.tm_min)};e.i_<e.max_; ++e.i_){
      
      POLICY * const sPT=&e.ptable_[e.i_];

       /* Start off as working time */
      bool isWorking = true;

       /* For each period */
      NONWORKING_HOURS *const nwh = &(sPT->nonWorkingHours);

      for (e.period_=0;e.period_ < nwh->periodCount; ++e.period_){
         NONWORKING_PERIOD * const period=&nwh->periods[e.period_];
         /* Check current day of week is applicable */
         if (period->daysOfWeek & e.dayBitMask_){
            /* Check current time is applicable */
            if (period->start <= e.minutesSinceMidnight_ && e.minutesSinceMidnight_ < period->end){
               isWorking = false;
               break;
            }
         }
      }

      sPT->flags.inWorkingDay = isWorking;
      sPT->currentCategoryMask =
          isWorking
          ? sPT->workingHoursMask
          : sPT->nonWorkingHoursMask;

      sPT->custom_currentCategoryMask =
          isWorking
          ? sPT->custom_workingHoursMask
          : sPT->custom_nonWorkingHoursMask;
   }

}


void replaceGroupPolicyTables(   GROUP * const restrict newGroupTable, 
                                 const size_t newGroupCount,
                                 POLICY * const restrict newPolicyTable,
                                 const size_t newPolicyCount            )
{

/* Destroy existing data */

   if (sGroupCount && sGroupTable){
      tx_safe_free(sGroupTable);
      sGroupTable=NULL;
      sGroupCount=0;
   }

   if (sPolicyCount && sPolicyTable) {
      for (size_t i = 0; i < sPolicyCount; ++i) {
         tx_safe_free(sPolicyTable[i].nonWorkingHours.periods);
         sPolicyTable[i].nonWorkingHours.periods=NULL;
         tx_safe_free(sPolicyTable[i].emailNotify);
         sPolicyTable[i].emailNotify=NULL;
      }
      tx_safe_free(sPolicyTable);
      sPolicyTable=NULL;
      sPolicyCount=0;
   }

   /* Set new groups / policies */
   sGroupTable = newGroupTable;
   sGroupCount = newGroupCount;

   sPolicyTable = newPolicyTable;
   sPolicyCount = newPolicyCount;

   remap_groups_and_policies();

}

bool find_group_by(t_search_val * const restrict sv)
{

   if (sv->stype.groupNumber && sv->in_groups_count){
      long index=0;
      if ( INVALID_!=(index = getGroupIndex(sv->svalue.ival) ) ) {

         if ( sGroupCount > (size_t)index ) { 

            sv->out_group_idx = (size_t) index;
            sv->out_group=&sGroupTable[sv->out_group_idx];
            return true;
         }
         else {
            if ( !sv->retry ) {
               titax_log( LOG_WARNING, 
                           "Invalid index %ld for id %d remaping \n",
                           index, 
                           sv->svalue.ival );
               remap_groups_and_policies();
               sv->retry = true;
               return find_group_by( sv );
            }
            else 
               titax_log( LOG_WARNING, 
                           "Invalid index %ld for id %d AGAIN giving up\n",
                           index, 
                           sv->svalue.ival );
         }
      }
      return false;
   }

   if (sv->stype.groupName && sv->in_groups_count){

      const uint_fast64_t max_ = sv->in_groups_count;

      for (	uint_fast64_t i_ = 0; i_< max_; ++i_ ) {

         GROUP * const in_groups_ = &sv->in_groups[i_];
         if (  ! in_groups_->hide && 
               ! strcmp( in_groups_->name, sv->svalue.cptr ) ) {

            sv->out_group = in_groups_;
            sv->out_group_idx = i_;
            return true;
         }  
      }

      return false;
   }

   return false;
}
