/*
 * $Id$
*/
#ifndef LIB_TITAXTIME_H
#define LIB_TITAXTIME_H

#include <time.h>
#include "global.h"

/* 
 * Format time_t as localtime in format:
 * day, DD MM YY H:M:S OFFSET
 * 
 * Caller must free the returned char *
 */
TXATR char * titax_localtime(const time_t *const);

TXATR bool titax_localtime_ex(const time_t *const  , char *const ,const size_t);

#define TITAX_ISOTIME_LEN ((24+1) * sizeof(char))

/*
 * Get an ISO8601 formatted timestamp based on current time
 */
TXATR void titax_getIsotime(char timestr[TITAX_ISOTIME_LEN]);

/*
 * Get an ISO8601 formatted timestamp based on time time
 */
TXATR void titax_getIsotimeFromTime(char timestr[TITAX_ISOTIME_LEN], const time_t *  time);

/* 
 * Covert a string in the same format as the one created by
 *  titaxIsoTime into a time_t
 */
TXATR time_t titaxIsoTimeToTime(const char * const  );

/*
 * Calculate the diffence between 2 iso-8601 timestamps as created by
 * titaxIsoTime: time1-time2. If either time1 or time2 is NULL it is
 * taken as the current time as taken from time(NULL) 
 */
TXATR double titaxIsoTimeDiff(const char * const , const char * const );


TXATR void get_time(char * const ,const size_t);
TXATR void get_date(char * const  ,const size_t);

/**
 * @fn str_ftime 
 * @abstract based on the format string creates a text representation of the given time
 * @param fmt[in] : format string
 * @param buf[in] : output buffer
 * @param bsz[in] : output buffer size
 * @return bool 
 */
TXATR bool str_ftime_ex(   const time_t,
                           const char * const ,
                           char * const , 
                           size_t               );

/**
 * @fn str_ftime 
 * @abstract based on the format string creates a text representation of the current time
 * @param fmt[in] : format string
 * @param buf[in] : output buffer
 * @param bsz[in] : output buffer size
 * @return bool 
 */
TXATR bool str_ftime(   const char* const, 
                        char * const, 
                        size_t            );


TXATR bool get_curdate_safe(char * , const size_t);
TXATR bool current_time_ex(const char * const ,char * const , size_t * const );
TXATR bool current_GMT_ex(char * const , size_t * const );
TXATR char * current_GMT(size_t * const );


#endif /* LIB_TITAXTIME_H */
