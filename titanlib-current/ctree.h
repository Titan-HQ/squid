/*
 *  $Header: /usr/home/svn/cvsroot/wt1/titax2/libtitax/ctree.h,v 1.9 2010-11-24 10:30:03 jinhee Exp $
 *
 *  $Name: not supported by cvs2svn $
 *  $Author: jinhee $
 *  $Revision: 1.9 $
 *  $State: Exp $
 *
 *  CVS History:
 *
 *  $Log: not supported by cvs2svn $
 *  Revision 1.1  2010/02/01 14:03:05  jinhee
 *  modifed files for squid update.
 *
 *  Revision 1.1.1.1  2008/07/23 11:03:36  sean
 *  Initial Titax code.
 *
 *  Revision 1.8.654.1  2006/07/19 13:19:18  jsutherland
 *  Merged bug 661 and 711 into 3.2.1.0 - This is the new group URL list feature
 *
 *  Revision 1.8.668.1  2006/07/11 15:27:21  dredpath
 *  Merge of bug661 and bug711 features of per user URL categories and group B/A lists.
 *
 *  Revision 1.8  2005/02/01 17:26:08  gbisset
 *  Bug No. 329 - Found and fixed several memory leaks
 *
 *  Revision 1.7  2005/01/21 14:53:34  cmacdonald
 *  Fixed field sizes so that larger word scores can be used
 *
 *  Revision 1.6  2003/11/03 13:13:31  gordon
 *  fix spaces in keywork matching and page and url thresholds
 *
 *  Revision 1.5  2002/09/05 15:16:10  gordon
 *  Progress on packeded V2 software
 *
 *  Revision 1.4  2002/08/09 11:32:40  gordon
 *  Fixed c++ compilation
 *
 *  Revision 1.3  2002/05/08 08:15:04  gordon
 *  cleaned up allowed url characters
 *
 *  Revision 1.2  2002/05/06 08:12:54  gordon
 *  fixed deleting whitelisted user keywords that overrode the builtins
 *
 *  Revision 1.1  2002/04/30 13:37:33  gordon
 *  url content filtering
 *
 *
 */

// Tree data

#ifndef CTREE_H
#define CTREE_H
#include "global.h"

#ifdef __cplusplus
extern "C" {
#endif



struct ctree;
typedef struct ctree CTREE;

struct ctree {
   CTREE    **ptr;        // array of tree pointers
   size_t   val;          // score
   size_t   org;          // builtin score for restoration in update deleted
   size_t   is_lexeme;    // indicates lexical entry
   size_t   is_constant;  // indicates entry that cant be deleted
};

#ifdef __cplusplus
}
#endif

// Prototypes

TXATR CTREE* Ctree(void);
TXATR void   CtreeDestruct(CTREE* const);
TXATR void   CtreePrepareContent(CTREE* const);
TXATR void   CtreeAdd(CTREE* const, const char* const, const size_t, const size_t);
TXATR size_t  CtreeLookup(const CTREE* const, const char** const, const char* const, size_t* const);
TXATR void   CtreeDelete(CTREE*const, const char *const );
TXATR void   CtreePrintStats(void);

/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */
int get_Ctree_memory_statistic(void);

#endif   //CTREE_H
