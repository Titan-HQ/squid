/*
 * $Id$
 */

#include "titaxtime.h"
#include <stdio.h>
#include <string.h>
#include <time.h>



TX_INTERNAL_INLINE
bool time_to_str_(   const time_t time,
                     const char * const restrict format,
                     char * const restrict buff, 
                     size_t * const restrict len         ){

   if ( time && format && buff && len && *len ){

      struct tm ti={};

      *len = strftime(  buff,
                        *len,
                        format,
                        localtime_r(&time,&ti)  );

      return ( ( *len ) > 0 );

   }

   return (false);
}


bool titax_localtime_ex(const time_t * const restrict t, char * const restrict out,const size_t sz){
   if (t && out && sz){
      struct tm gmt = {};
      struct tm lt = {} ;
      int min_offset=0, day_offset=0;
      (void)gmtime_r(t, &gmt);
      (void)localtime_r(t, &lt);
      day_offset = lt.tm_yday - gmt.tm_yday;
      /* wrap round on end of year */
      if (day_offset > 1)
      day_offset = INVALID_;
      else if (day_offset < INVALID_)
      day_offset = 1;
      min_offset = day_offset * 1440 + (lt.tm_hour - gmt.tm_hour) * 60+ (lt.tm_min - gmt.tm_min);
      const size_t len = strftime(out, (sz-1) - 5, "%a, %d %b %Y %H:%M:%S ", &lt);
      (void)tx_safe_snprintf(out + len, sz - len, "%+03d%02d",(min_offset / 60) % 24, min_offset % 60);
      return true;
   }
   return false;
}

char * titax_localtime(const time_t * const restrict t){
   char buf[128]={};
   if (titax_localtime_ex(t, buf,sizeof(buf))){
      return strdup(buf);
   }
   return (0) ;
}



void titax_getIsotime(char timestr[TITAX_ISOTIME_LEN]){   
   time_t rawtime=0;
   (void)time(&rawtime);
   titax_getIsotimeFromTime(timestr, &rawtime);
}
 
void titax_getIsotimeFromTime(char timestr[TITAX_ISOTIME_LEN], const time_t * const restrict time){   
   struct tm localTime = {};
   (void)localtime_r(time,&localTime);
   (void)tx_safe_snprintf(timestr,TITAX_ISOTIME_LEN,"%04d-%02d-%02dT%02d:%02d:%02d%+03ld%02ld",
      localTime.tm_year+1900,
      localTime.tm_mon+1,
      localTime.tm_mday,
      localTime.tm_hour,
      localTime.tm_min,
      localTime.tm_sec,
      localTime.tm_gmtoff/(60*60),
      (localTime.tm_gmtoff/60) % 60);
}

/* Covert a string in the same format as the one created by
 * titaxIsoTime into a time_t */
time_t titaxIsoTimeToTime(const char * const restrict time){
   struct tm tm_stamp = {};

   long timezone=0;

   /* 
    * We could use the sscanf_s (or equivalent) here if and when the FreeBSD adds support for it.
    * But in this case, it is not as beneficial as advertised as there is no string handling here.
    */

   sscanf(time,"%d-%d-%dT%d:%d:%d%ld",
      &tm_stamp.tm_year,
      &tm_stamp.tm_mon,
      &tm_stamp.tm_mday,
      &tm_stamp.tm_hour,
      &tm_stamp.tm_min,
      &tm_stamp.tm_sec,
      &timezone);

   tm_stamp.tm_year -= 1900; /* tm_year starts at 1900 */
   tm_stamp.tm_mon -= 1; /* tm_mon starts at 0 */
   timezone = ((timezone / 100) * 60 + (timezone % 100)); /* the offset in hrs * 100 converted to minutes */

   tm_stamp.tm_min -= timezone;

   return  timegm(&tm_stamp);

}

/* Calculate the diffence between 2 iso-8601 timestamps as created by
 * titaxIsoTime: time1-time2. If either time1 or time2 is NULL it is
 * taken as the current time as taken from time(NULL) */
double titaxIsoTimeDiff(const char * const restrict time1, const char * const restrict time2){
   const time_t t0=((!time1 && !time2)?time(NULL):0);
   if (t0) return difftime(t0,t0); //FIXME:: zero ??
   const time_t t1=(time1?titaxIsoTimeToTime(time1):time(NULL));
   const time_t t2=(time2?titaxIsoTimeToTime(time2):time(NULL));
   return difftime(t1,t2);
}

void get_time(char * const restrict res,const size_t rsz){
   if (res &&  rsz){
      time_t now = 0;
      (void)time(&now);
      struct tm t = {};
      (void)localtime_r(&now,&t);
      (void)tx_safe_snprintf(res,rsz, "%d-%02d-%02d %2d:%02d:%02d"
            ,t.tm_year + 1900, t.tm_mon + 1, t.tm_mday, t.tm_hour, t.tm_min, t.tm_sec);
   }
}

//------------------------------------------------------------------------
void get_date(char * const restrict res,const size_t rsz){
   if (res && rsz){
      time_t now=0;
      (void)time(&now);
      struct tm t = {};
      (void)localtime_r(&now,&t);
      (void)tx_safe_snprintf(res,rsz, "%d-%02d-%02d"  , t.tm_year + 1900, t.tm_mon + 1, t.tm_mday);
   }
}


//---------------------------------------------------------------------
bool str_ftime_ex(   const time_t time,
                     const char * const restrict format,
                     char * const restrict buff, 
                     size_t len                        ){

   return time_to_str_( time,
                        format,
                        buff,
                        &len   );
}



//---------------------------------------------------------------------
bool str_ftime(   const char* const restrict fmt,
                  char * const restrict buf, 
                  size_t buf_len                   ){

   if ( fmt && buf && buf_len ){

      time_t now = 0;

      time(&now);

      return time_to_str_( now,
                           fmt,
                           buf,
                           &buf_len );

   }

   return (false);
}

//---------------------------------------------------------------------
bool get_curdate_safe(  char * restrict buf,
                        const size_t len)     {

   return str_ftime("%Y%m%d",buf,len);
}

//---------------------------------------------------------------------


//---------------------------------------------------------------------
bool current_time_ex(const char * const restrict format,char * const restrict buff, size_t * const restrict len){
   if (format && buff && len && *len){
      time_t rt=0;
      (void)time (&rt);
      struct tm ti={};
      (void)gmtime_r(&rt,&ti);
      *len=strftime(buff,*len,format,&ti);
      return ((*len)>0);
   }
   return false;
}

//---------------------------------------------------------------------
bool current_GMT_ex(char * const restrict buff, size_t * const restrict len){
   return (current_time_ex("%a, %d %b %Y %T GMT",buff,len));
}

//---------------------------------------------------------------------
char * current_GMT(size_t * const restrict len){
   if (len){
      char buff[255]={};
      *len=sizeof buff;
      if (current_GMT_ex(buff,len)){
         char* const outbuf=(char*const)tx_safe_malloc(*len+1);
         (void)(outbuf && tx_safe_memcpy(outbuf,buff,*len) && (outbuf[*len]=0));
         return outbuf;
      }
   }
   return 0;
}

