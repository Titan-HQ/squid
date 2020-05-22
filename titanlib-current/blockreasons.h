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
 *
 *
 * Major reasons for blocking
 *
 * This following lines are carefully written, and parsed by
 * webui/private/genreasons.php to create
 * webui/private/lib/Model/TitaxModelReasons.php
 *
 * Any line defining a reason as to why something is blocked on
 * a per policy basis must be:
 * #define MAJ_REASON_XXXX     <num>    // POLICY: <English description>
 *
 * The <num> and <English description> will be taken to the PHP file.
 *
 * Once a number has been assigned it should NOT be changed. To do so
 * would redefine what would be notified, because the numbers will be
 * stored in the customer's configuration database.
 *
 * These values represent the bit position of the setting in the policyFlags
 * variable within the group structure.
 */
#ifndef BLOCKREASONS_H
#define BLOCKREASONS_H

#include "global.h"


#ifndef MAJ_REASON_UNKNOWN
	#define MAJ_REASON_UNKNOWN              0       // GLOBAL: Reason unknown
#endif
#ifndef MAJ_REASON_SYSTEM_BLOCKED
	#define MAJ_REASON_SYSTEM_BLOCKED       1       // GLOBAL: URLDB
#endif
#ifndef MAJ_REASON_USER_BLOCKED
	#define MAJ_REASON_USER_BLOCKED         2       // GLOBAL: User URLDB
#endif
#ifndef MAJ_REASON_VIRUS
	#define MAJ_REASON_VIRUS                3       // GLOBAL: virus
#endif
#ifndef MAJ_REASON_SPY_URL
	#define MAJ_REASON_SPY_URL              4       // GLOBAL: spyware
#endif
#ifndef MAJ_REASON_ANTIPHISHING
	#define MAJ_REASON_ANTIPHISHING         5       // GLOBAL: phish site
#endif
#ifndef MAJ_REASON_USER_DENYLIST
	#define MAJ_REASON_USER_DENYLIST        6       // GLOBAL: Denied URL
#endif
#ifndef MAJ_REASON_USER_POLICY_DENYLIST
	#define MAJ_REASON_USER_POLICY_DENYLIST 7       // POLICY: Denied URL
#endif
#ifndef MAJ_REASON_URL_BLOCK_ALL
	#define MAJ_REASON_URL_BLOCK_ALL        8       // POLICY: All sites blocked
#endif
#ifndef MAJ_REASON_URL_CONTENT
	#define MAJ_REASON_URL_CONTENT          9       // POLICY: URL content (score)
#endif
#ifndef MAJ_REASON_PAGE_CONTENT
	#define MAJ_REASON_PAGE_CONTENT         10      // POLICY: Page content (score)
#endif
#ifndef MAJ_REASON_IP_ADDR
	#define MAJ_REASON_IP_ADDR              11      // POLICY: IP address URL
#endif
#ifndef MAJ_REASON_FILE_TYPE
	#define MAJ_REASON_FILE_TYPE            12      // POLICY: File type blocked
#endif
#ifndef MAJ_REASON_PAGE_KEYWORD
	#define MAJ_REASON_PAGE_KEYWORD         13      // POLICY: Page content (banned word/phrase)
#endif
#ifndef MAJ_REASON_UNCLASS_SITE
	#define MAJ_REASON_UNCLASS_SITE         14      // POLICY: Unclassified
#endif
#ifndef MAJ_REASON_URL_NOT_ALLOWED
	#define MAJ_REASON_URL_NOT_ALLOWED      15      // POLICY: Only specified URLs allowed
#endif
#ifndef MAJ_REASON_SIN_BIN
	#define MAJ_REASON_SIN_BIN              16      // POLICY: Internet access rights revoked
#endif
#ifndef MAJ_REASON_URL_KEYWORD
	#define MAJ_REASON_URL_KEYWORD          17      // POLICY: URL content (banned word/phrase)
#endif
#ifndef MAJ_REASON_INSTANT_MESSAGING
	#define MAJ_REASON_INSTANT_MESSAGING    18      // POLICY: Instant messaging
#endif
#ifndef MAJ_REASON_PEER_TO_PEER
	#define MAJ_REASON_PEER_TO_PEER         19      // POLICY: Peer to peer
#endif
#ifndef MAJ_REASON_HTTPS_BLOCKED
	#define MAJ_REASON_HTTPS_BLOCKED        20      // POLICY: HTTPS
#endif
#ifndef MAJ_REASON_UNCLASS_HTTPS_SITE
	#define MAJ_REASON_UNCLASS_HTTPS_SITE   21      // POLICY: Unclassified HTTPS
#endif
#ifndef MAJ_REASON_ADMIN_BLOCKED
	#define MAJ_REASON_ADMIN_BLOCKED        22      // Blocked by whitelist.
#endif
#ifndef MAJ_REASON_DOWNLIMIT_BLOCKED
	#define MAJ_REASON_DOWNLIMIT_BLOCKED    23      // Blocked by download limit.
#endif
#ifndef MAJ_REASON_BYPASSED
	#define MAJ_REASON_BYPASSED             999998  // bypass filters.
#endif
#ifndef MAJ_REASON_UNKNOWN_ERROR
	#define MAJ_REASON_UNKNOWN_ERROR        999999  //UNKNOWN ERROR
#endif
/* End of major reason list */

/* Minor reason list */
#ifndef MIN_REASON_UNKNOWN
	#define MIN_REASON_UNKNOWN        0x00000000
#endif
#ifndef MIN_REASON_CAT_BLOCKALL
	#define MIN_REASON_CAT_BLOCKALL   0x00000001
#endif
#ifndef MIN_REASON_CAT_AUDIO
	#define MIN_REASON_CAT_AUDIO      0x00000002
#endif
#ifndef MIN_REASON_CAT_VIDEO
	#define MIN_REASON_CAT_VIDEO      0x00000004
#endif
#ifndef MIN_REASON_CAT_EXE
	#define MIN_REASON_CAT_EXE        0x00000008
#endif
#ifndef MIN_REASON_CAT_IMAGE
	#define MIN_REASON_CAT_IMAGE      0x00000010
#endif
#ifndef MIN_REASON_CAT_TEXT
	#define MIN_REASON_CAT_TEXT       0x00000020
#endif
#ifndef MIN_REASON_CAT_ARCHIVE
	#define MIN_REASON_CAT_ARCHIVE    0x00000040
#endif
#ifndef MIN_REASON_CAT_USER
	#define MIN_REASON_CAT_USER       0x00000080
#endif
#ifndef MIN_REASON_IM_ICQ_AOL
	#define MIN_REASON_IM_ICQ_AOL     0x00000001
#endif
#ifndef MIN_REASON_IM_MSN
	#define MIN_REASON_IM_MSN         0x00000002
#endif
#ifndef MIN_REASON_IM_YAHOO
	#define MIN_REASON_IM_YAHOO       0x00000004
#endif
#ifndef MIN_REASON_IM_GOOGLE_TALK
	#define MIN_REASON_IM_GOOGLE_TALK 0x00000008
#endif
/* End of minor reason list */

#ifndef MAJ_REASON_BYPASSED_MSG
   #define MAJ_REASON_BYPASSED_MSG        "Bypassed"
#endif

#ifndef MAJ_REASON_BYPASSED_MSG_SZ
   #define MAJ_REASON_BYPASSED_MSG_SZ     (sizeof(MAJ_REASON_BYPASSED_MSG)-1)
#endif

typedef struct {

    size_t      major;

    union {
      t_category  category;       // Group flags
      uint32      score;          // Page or URL score. values range??
      uint32      imType;         // IM Type ID
    } minor;

    union {
        uint32  threshold;      // threshold
        uint32  worktime;
        uint32  av_engine;
    } aux;
} BlockReason;

#endif /* BLOCKREASONS_H */
