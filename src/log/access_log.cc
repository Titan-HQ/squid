/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 46    Access Log */

#include "squid.h"
#include "AccessLogEntry.h"
#include "acl/Checklist.h"
#include "client_side_request.h"
#if USE_ADAPTATION
#include "adaptation/Config.h"
#endif
#include "CachePeer.h"
#include "err_detail_type.h"
#include "errorpage.h"
#include "format/Token.h"
#include "globals.h"
#include "hier_code.h"
#include "HttpReply.h"
#include "HttpRequest.h"
#include "log/access_log.h"
#include "log/Config.h"
#include "log/CustomLog.h"
#include "log/File.h"
#include "log/Formats.h"
#include "MemBuf.h"
#include "mgr/Registration.h"
#include "rfc1738.h"
#include "SquidConfig.h"
#include "SquidTime.h"
#include "Store.h"

#if USE_SQUID_EUI
#include "eui/Eui48.h"
#include "eui/Eui64.h"
#endif

//Titax.
#include "TitaxUser.h"
#include "titaxlib.h"
#include "sock_rw.h"
#include "Group.h"
#include "log.h"
#include "Category.h"


void send_log_data2(
    const char* username
    , char** groups
    , int group_count
    , int ip_addr
    , char** categories
    , int category_count
    , const char* url
    , unsigned long duration
    , unsigned long object_size
    , int blocking_source
    , const char* reason
    , int cached
    , char** notifications
    , int notify_count
    ){

    if (!url){
        std::cout << "err:[send_log_data2]: url is null ! \n";
        return;
    };

    char* log_data = NULL;
    int i = 0;
    int known_protocol_flag = 0;
    time_t time_now;
    struct tm ts;
    time(&time_now);
    localtime_r(&time_now, &ts);

    if(!username || !username[0]){
        username = TITAX_ANON_DEFAULT_USER_NAME;
        std::cout << "(send_log_data2/icap)::WRN: anonymous user 0\n";
    }

    /* Compute size of memory required for log data */

    int sz = snprintf(NULL, 0, "%ld %d %lu %lu %08x %d %d %s %s\n",
        (long int)time_now,    /* unixtime */
        ts.tm_hour * 60 + ts.tm_min, /* time */
        object_size,      /* size */
        duration,        /* duration */
        ip_addr,       /* IP address */
        cached,          /* cached */
        blocking_source,  /* status */
        url,             /* URL */
        username         /* User Name */
        );

   /* 
      known_protocol_flag -- This had been introduced as squid is trimming off 
      https from the url and logger will not accept any entry without protcol.
      If there is no protocol specified, log that as https
    */


    if(strncasecmp(url, "http://", 7) == 0){
        known_protocol_flag = 1;
    }
    else if(strncasecmp(url, "https://", 8) == 0){
        known_protocol_flag = 1;
    }
    else if(strncasecmp(url, "ftp://", 6) == 0){
        known_protocol_flag = 1;
    }
    else if (strstr(url,"://")){
        known_protocol_flag = 1;
    };

    if(0 == known_protocol_flag){
        sz += 8;
    }

    /* Groups */
    for(i = 0 ; i < group_count ; i++){
        sz += snprintf(NULL, 0, "G%s\n", groups[i]);
    }

    // Temporary solution for bug 112.
    if(category_count > 5){
        category_count = 0;
    }

    /* Categories */
    for(i = 0 ; i < category_count ; i++){
        sz += snprintf(NULL, 0, "C%s\n", categories[i]);
    }

    /* Notifications */
    for(i = 0 ; i < notify_count ; i++){
        // N is for notification
        // E is for e-mail, only notifications we have at the moment
        sz += snprintf(NULL, 0, "NE%s\n", notifications[i]);
    }

    /* Reason */
    if(reason && strlen(reason) > 0){
        sz += snprintf(NULL, 0, "R%s\n", reason);
    }

    sz++; /* terminating null character */

    /* Allocate memory */
    log_data = (char*)xcalloc(sz, sizeof(char));
    if(!log_data){
        titax_log(LOG_WARNING, "Unable to log access: Out of memory\n");
        return;
    }

    /* Create log_data */
    int pos = 0;
    pos += snprintf(log_data, sz-pos, "%ld %d %lu %lu %08x %d %d %s%s %s\n",
        (long int)time_now,    /* unixtime */
        ts.tm_hour * 60 + ts.tm_min, /* time */
        object_size,      /* size */
        duration,        /* duration */
        ip_addr,       /* IP address */
        cached,          /* cached */
        blocking_source,  /* status */
        (0 == known_protocol_flag) ? "http://" : "", /* Log unknown protocol as https */
        url,             /* URL */
        username         /* User Name */
        );

    /* Groups */
    for(i = 0 ; i < group_count ; i++){
        pos += snprintf(log_data + pos, sz-pos, "G%s\n", groups[i]);
    }

    /* Categories */
    for(i = 0 ; i < category_count ; i++){
        pos += snprintf(log_data + pos, sz-pos, "C%s\n", categories[i]);
    }

    /* Notifications */
    for(i = 0 ; i < notify_count ; i++){
        // N is for notification
        // E is for e-mail, only notifications we have at the moment
        pos += snprintf(log_data + pos, sz-pos, "NE%s\n", notifications[i]);
    }

    /* Reason */
    if(reason && strlen(reason) > 0){
        pos += snprintf(log_data + pos, sz-pos, "R%s\n", reason);
    }

    if(logger_open()){
        /* Send message header - length of LOG + null char + logdata + null char */
        unsigned int dtsz=strlen(log_data) ;
        uint32_t len = 4 * sizeof(char) +dtsz+ sizeof(char);
        char buff[len+sizeof(len)+1];
        len = htonl(len);
        char * pb=buff;
        memset(pb,0,sizeof buff);
        memcpy(pb,&len,sizeof(len));
        pb+=sizeof(len);
        memcpy(pb,"LOG",3);
        pb+=4;
        memcpy(pb,log_data,dtsz);
        pb+=dtsz;
        if(!logger_writen(&buff, sizeof buff)){
            logger_close();
            goto END;
        };

/*
        if(!logger_writen(&len, sizeof(len))){
            logger_close();
            goto END;
        }
        printf(">>>TYPE is:LOG\n");

        // Send message type
        if(!logger_writen("LOG", 4 * sizeof(char))){
            logger_close();
            goto END;
        }

        //printf(">>>Data is:%s\n",log_data);
        // Send message data
        if(!logger_writen(log_data, dtsz + sizeof(char))){
            logger_close();
            goto END;
        }
*/
        logger_close();
        /* Disconnect */
    }
    else{
        printf("send_log_data2->Could not connect to logger\n");
    }

END:
    /* Free log memory */
    xfree(log_data);
    log_data = NULL;
}

#if HEADERS_LOG
static Logfile *headerslog = NULL;
#endif

#if MULTICAST_MISS_STREAM
static int mcast_miss_fd = -1;

static struct sockaddr_in mcast_miss_to;
static void mcast_encode(unsigned int *, size_t, const unsigned int *);
#endif

#if USE_FORW_VIA_DB

typedef struct {
    hash_link hash;
    int n;
} fvdb_entry;
static hash_table *via_table = NULL;
static hash_table *forw_table = NULL;
static void fvdbInit();
static void fvdbDumpTable(StoreEntry * e, hash_table * hash);
static void fvdbCount(hash_table * hash, const char *key);
static OBJH fvdbDumpVia;
static OBJH fvdbDumpForw;
static FREE fvdbFreeEntry;
static void fvdbClear(void);
static void fvdbRegisterWithCacheManager();
#endif

int LogfileStatus = LOG_DISABLE;

void
accessLogLogTo(CustomLog* log, AccessLogEntry::Pointer &al, ACLChecklist * checklist)
{
    const char *url=NULL;
    int cacheHit=0;

    // Titax.
    if(al == NULL || (!al->request) || (al->request && al->request->has_been_logged)){
        return;
    }

    int64_t resp_size = al->cache.objectSize;

    if(al->url == NULL || // No URL specified
    resp_size <= 0      // Nothing there
    ){
        return;
    }

    switch (al->cache.code) {

         case LOG_TCP_DENIED:
         case LOG_TCP_DENIED_REPLY:
             return;

         case LOG_TCP_HIT:
         case LOG_TCP_IMS_HIT:
         case LOG_TCP_NEGATIVE_HIT:
         case LOG_TCP_MEM_HIT:
         case LOG_TCP_OFFLINE_HIT:
         case LOG_UDP_HIT:
         case LOG_TCP_REFRESH_UNMODIFIED:
         case LOG_TCP_REFRESH_MODIFIED:
 //    case LOG_TCP_REFRESH_FAIL:
             cacheHit = 1;
             break;

         default:
             cacheHit = 0;
 //        return;                         /* Not interested */
     }

    /* Don't log acceses to our own resources */
    url = al->url;
    if (strncasecmp(url, "http://", 7) == 0)
        url += 7;
    else if (strncasecmp(url, "https://", 8) == 0)
        url += 8;
    else if (strncasecmp(url, "ftp://", 6) == 0)
        url += 6;

    TITAX_CONF_LOCK();
    TitaxConf* const tc = titax_conf_get_instance();
    if (tc){
       if (tc->hostname_len) {
           if (strncasecmp(tc->hostname, url, tc->hostname_len) == 0   &&
               (url[tc->hostname_len] == '/' || url[tc->hostname_len] == ':')
            ){
               TITAX_CONF_UNLOCK(); 
               return;
           };

       }
       if (tc->fqdn_len) {
           if (strncasecmp(tc->fqdn, url, tc->fqdn_len) == 0   &&
               (url[tc->fqdn_len] == '/' || url[tc->fqdn_len] == ':')
            ){
                TITAX_CONF_UNLOCK();
                 return;
           };
       }
        if (tc->int_ip_4_len) {
           if (strncasecmp(tc->int_ip_4, url, tc->int_ip_4_len) == 0   &&
               (url[tc->int_ip_4_len] == '/' || url[tc->int_ip_4_len] == ':') )
            {
               TITAX_CONF_UNLOCK();
               return;
            }
        }
        if (tc->int_ip_6_len) {
            if (strncasecmp(tc->int_ip_6, url, tc->int_ip_6_len) == 0   &&
                (url[tc->int_ip_6_len] == '/' || url[tc->int_ip_6_len] == ':') )
            {
                TITAX_CONF_UNLOCK();
                return;
            }
        }
    };
    TITAX_CONF_UNLOCK();

    int group_count = al->request->group_count;
    char **groups = NULL;
    if (0 == group_count)
    {
        group_count = 1;
        groups = (char**)xcalloc(1, sizeof(char*));
        groups[0] = xstrdup("Default");
    }
    else
    {
        groups = (char**)xcalloc(group_count, sizeof(char*));
        int i = 0;
        for (i = 0; i < group_count ; ++i)
        {
            GROUP grp;
            getGroup(al->request->groups[i], &grp);
            groups[i] = xstrdup(grp.name);
        }
    }

    char **categories = NULL;
    int    category_count = 0;

    if (0 != al->category)
    {
        // Count bits in al->category. There is typically only a very
        // few number of set bits, so we'll use the method published by
        // Brian Kernighan & Dennis Ritchie, C Programming Language 2nd ed. 1988
        // and Peter Wegner, CACM 3 (1960), 322
        unsigned long long cat = al->category;
        for (category_count = 0; cat; category_count++)
        {
            cat &= cat-1; // clear least significant bit set
        }

        categories = (char**)xcalloc(category_count, sizeof(char*));

        cat = al->category;
        uint32_t bit = 0;
        int j = 0;
        while (cat)
        {
            if (cat & 0x0000000000000001ULL)
            {
                if (bit > DEFINED_TITAX_CATEGORIES)
                {
                    // Custom category - pass as string
                    const char* catname = categoryGetName(bit);
                    int sz = strlen(catname) + 1;
                    categories[j] = (char*)xcalloc(sz, sizeof(char));
                    strcpy(categories[j], catname);
                }
                else
                {
                    int sz = snprintf(NULL, 0, "%d", bit) + 1;
                    categories[j] = (char*)xcalloc(sz, sizeof(char));
                    snprintf(categories[j], sz, "%d", bit);
                }
                j++;
            }
            cat = cat >> 1;
            bit++;
        }
    }

    /*
    // Titax.
    if(titax_conf_is_enable_auth()){
        if ((al->request->authenticated_username) && (!al->request->anonymous_webtitan_user)){
            titax_user_info_dic_inc_byte(al->request->authenticated_username, resp_size);
        }
//      titax_user_info_dic_print_all();
    }
    */

    send_log_data2(
        al->request->loggable_username,// username
        groups,                 // groups
        group_count,            // group count
        al->cache.caddr.s_addr(), // IP address
        categories,             // categories
        category_count,         // category count
        al->url, // URL
        al->cache.msec,         // Duration
        resp_size,         // Object Size
        2,                      // No blocking source
        NULL,                   // No reason
        cacheHit,               // Cached
        NULL,                   // no notifications
        0                       // no notifications
        );

    int i = 0;
    for (i = 0 ; i < group_count ; ++i)
    {
        xfree(groups[i]);
    }
    xfree(groups);

    for (i = 0 ; i < category_count ; ++i)
    {
        xfree(categories[i]);
    }
    xfree(categories);
}

void
accessLogLog(AccessLogEntry::Pointer &al, ACLChecklist * checklist)
{
    if (LogfileStatus != LOG_ENABLE)
        return;

    accessLogLogTo(Config.Log.accesslogs, al, checklist);
#if MULTICAST_MISS_STREAM

    if (al->cache.code != LOG_TCP_MISS)
        (void) 0;
    else if (al->http.method != METHOD_GET)
        (void) 0;
    else if (mcast_miss_fd < 0)
        (void) 0;
    else {
        unsigned int ibuf[365];
        size_t isize;
        xstrncpy((char *) ibuf, al->url, 364 * sizeof(int));
        isize = ((strlen(al->url) + 8) / 8) * 2;

        if (isize > 364)
            isize = 364;

        mcast_encode((unsigned int *) ibuf, isize,
                     (const unsigned int *) Config.mcast_miss.encode_key);

        comm_udp_sendto(mcast_miss_fd,
                        &mcast_miss_to, sizeof(mcast_miss_to),
                        ibuf, isize * sizeof(int));
    }

#endif
}

void
accessLogRotate(void)
{
    CustomLog *log;
#if USE_FORW_VIA_DB

    fvdbClear();
#endif

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->logfile) {
            logfileRotate(log->logfile);
        }
    }

#if HEADERS_LOG

    logfileRotate(headerslog);

#endif
}

void
accessLogClose(void)
{
    CustomLog *log;

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->logfile) {
            logfileClose(log->logfile);
            log->logfile = NULL;
        }
    }

#if HEADERS_LOG

    logfileClose(headerslog);

    headerslog = NULL;

#endif
}

HierarchyLogEntry::HierarchyLogEntry() :
    code(HIER_NONE),
    cd_lookup(LOOKUP_NONE),
    n_choices(0),
    n_ichoices(0),
    peer_reply_status(Http::scNone),
    peer_response_time(-1),
    tcpServer(NULL),
    bodyBytesRead(-1),
    totalResponseTime_(-1)
{
    memset(host, '\0', SQUIDHOSTNAMELEN);
    memset(cd_host, '\0', SQUIDHOSTNAMELEN);

    peer_select_start.tv_sec =0;
    peer_select_start.tv_usec =0;

    store_complete_stop.tv_sec =0;
    store_complete_stop.tv_usec =0;

    peer_http_request_sent.tv_sec = 0;
    peer_http_request_sent.tv_usec = 0;

    firstConnStart_.tv_sec = 0;
    firstConnStart_.tv_usec = 0;
}

void
HierarchyLogEntry::note(const Comm::ConnectionPointer &server, const char *requestedHost)
{
    tcpServer = server;
    if (tcpServer == NULL) {
        code = HIER_NONE;
        xstrncpy(host, requestedHost, sizeof(host));
    } else {
        code = tcpServer->peerType;

        if (tcpServer->getPeer()) {
            // went to peer, log peer host name
            xstrncpy(host, tcpServer->getPeer()->name, sizeof(host));
        } else {
            xstrncpy(host, requestedHost, sizeof(host));
        }
    }
}

void
HierarchyLogEntry::startPeerClock()
{
    if (!firstConnStart_.tv_sec)
        firstConnStart_ = current_time;
}

void
HierarchyLogEntry::stopPeerClock(const bool force)
{
    debugs(46, 5, "First connection started: " << firstConnStart_.tv_sec << "." <<
           std::setfill('0') << std::setw(6) << firstConnStart_.tv_usec <<
           ", current total response time value: " << totalResponseTime_ <<
           (force ? ", force fixing" : ""));
    if (!force && totalResponseTime_ >= 0)
        return;

    totalResponseTime_ = firstConnStart_.tv_sec ? tvSubMsec(firstConnStart_, current_time) : -1;
}

int64_t
HierarchyLogEntry::totalResponseTime()
{
    // This should not really happen, but there may be rare code
    // paths that lead to FwdState discarded (or transaction logged)
    // without (or before) a stopPeerClock() call.
    if (firstConnStart_.tv_sec && totalResponseTime_ < 0)
        stopPeerClock(false);

    return totalResponseTime_;
}

static void
accessLogRegisterWithCacheManager(void)
{
#if USE_FORW_VIA_DB
    fvdbRegisterWithCacheManager();
#endif
}

void
accessLogInit(void)
{
    CustomLog *log;

    accessLogRegisterWithCacheManager();

#if USE_ADAPTATION
    Log::TheConfig.hasAdaptToken = false;
#endif
#if ICAP_CLIENT
    Log::TheConfig.hasIcapToken = false;
#endif

    for (log = Config.Log.accesslogs; log; log = log->next) {
        if (log->type == Log::Format::CLF_NONE)
            continue;

        log->logfile = logfileOpen(log->filename, log->bufferSize, log->fatal);

        LogfileStatus = LOG_ENABLE;

#if USE_ADAPTATION
        for (Format::Token * curr_token = (log->logFormat?log->logFormat->format:NULL); curr_token; curr_token = curr_token->next) {
            if (curr_token->type == Format::LFT_ADAPTATION_SUM_XACT_TIMES ||
                    curr_token->type == Format::LFT_ADAPTATION_ALL_XACT_TIMES ||
                    curr_token->type == Format::LFT_ADAPTATION_LAST_HEADER ||
                    curr_token->type == Format::LFT_ADAPTATION_LAST_HEADER_ELEM ||
                    curr_token->type == Format::LFT_ADAPTATION_LAST_ALL_HEADERS||
                    (curr_token->type == Format::LFT_NOTE && !Adaptation::Config::metaHeaders.empty())) {
                Log::TheConfig.hasAdaptToken = true;
            }
#if ICAP_CLIENT
            if (curr_token->type == Format::LFT_ICAP_TOTAL_TIME) {
                Log::TheConfig.hasIcapToken = true;
            }
#endif
        }
#endif
    }

#if HEADERS_LOG

    headerslog = logfileOpen("/usr/local/squid/logs/headers.log", 512);

    assert(NULL != headerslog);

#endif
#if MULTICAST_MISS_STREAM

    if (Config.mcast_miss.addr.s_addr != no_addr.s_addr) {
        memset(&mcast_miss_to, '\0', sizeof(mcast_miss_to));
        mcast_miss_to.sin_family = AF_INET;
        mcast_miss_to.sin_port = htons(Config.mcast_miss.port);
        mcast_miss_to.sin_addr.s_addr = Config.mcast_miss.addr.s_addr;
        mcast_miss_fd = comm_open(SOCK_DGRAM,
                                  IPPROTO_UDP,
                                  Config.Addrs.udp_incoming,
                                  Config.mcast_miss.port,
                                  COMM_NONBLOCKING,
                                  "Multicast Miss Stream");

        if (mcast_miss_fd < 0)
            fatal("Cannot open Multicast Miss Stream Socket");

        debugs(46, DBG_IMPORTANT, "Multicast Miss Stream Socket opened on FD " << mcast_miss_fd);

        mcastSetTtl(mcast_miss_fd, Config.mcast_miss.ttl);

        if (strlen(Config.mcast_miss.encode_key) < 16)
            fatal("mcast_encode_key is too short, must be 16 characters");
    }

#endif
#if USE_FORW_VIA_DB

    fvdbInit();

#endif
}

#if USE_FORW_VIA_DB

static void
fvdbClear(void){
   if (via_table!=NULL){
      hashFreeItems(via_table, fvdbFreeEntry);
      hashFreeMemory(via_table);
      via_table=NULL;
   };
   via_table = hash_create((HASHCMP *) strcmp, 977, hash4);
   if (forw_table!=NULL){
      hashFreeItems(forw_table, fvdbFreeEntry);
      hashFreeMemory(forw_table);
      forw_table=NULL;
   };
   forw_table = hash_create((HASHCMP *) strcmp, 977, hash4);
}

static void
fvdbInit(void){
   fvdbClear();
   //via_table = hash_create((HASHCMP *) strcmp, 977, hash4);
   //forw_table = hash_create((HASHCMP *) strcmp, 977, hash4);
}

static void
fvdbRegisterWithCacheManager(void)
{
    Mgr::RegisterAction("via_headers", "Via Request Headers", fvdbDumpVia, 0, 1);
    Mgr::RegisterAction("forw_headers", "X-Forwarded-For Request Headers",
                        fvdbDumpForw, 0, 1);
}

static void
fvdbCount(hash_table * hash, const char *key)
{
    fvdb_entry *fv;

    if (NULL == hash)
        return;

    fv = (fvdb_entry *)hash_lookup(hash, key);

    if (NULL == fv) {
        fv = static_cast <fvdb_entry *>(xcalloc(1, sizeof(fvdb_entry)));
        fv->hash.key = xstrdup(key);
        fv->hash.next=NULL;
        hash_join(hash, &fv->hash);
    }

    ++ fv->n;
}

void
fvdbCountVia(const char *key)
{
    fvdbCount(via_table, key);
}

void
fvdbCountForw(const char *key)
{
    fvdbCount(forw_table, key);
}

static void
fvdbDumpTable(StoreEntry * e, hash_table * hash)
{
    hash_link *h;
    fvdb_entry *fv;

    if (hash == NULL)
        return;

    hash_first(hash);

    while ((h = hash_next(hash))) {
        fv = (fvdb_entry *) h;
        storeAppendPrintf(e, "%9d %s\n", fv->n, hashKeyStr(&fv->hash));
    }
}

static void
fvdbDumpVia(StoreEntry * e)
{
    fvdbDumpTable(e, via_table);
}

static void
fvdbDumpForw(StoreEntry * e)
{
    fvdbDumpTable(e, forw_table);
}

static
void
fvdbFreeEntry(void *const data)
{
   try{
    if (const fvdb_entry *const fv = static_cast <const fvdb_entry *const>(data)){
       xfree(fv->hash.key);
       xfree(fv);
    }
   }catch(...){}
}



#endif

#if MULTICAST_MISS_STREAM
/*
 * From http://www.io.com/~paulhart/game/algorithms/tea.html
 *
 * size of 'ibuf' must be a multiple of 2.
 * size of 'key' must be 4.
 * 'ibuf' is modified in place, encrypted data is written in
 * network byte order.
 */
static void
mcast_encode(unsigned int *ibuf, size_t isize, const unsigned int *key)
{
    unsigned int y;
    unsigned int z;
    unsigned int sum;
    const unsigned int delta = 0x9e3779b9;
    unsigned int n = 32;
    const unsigned int k0 = htonl(key[0]);
    const unsigned int k1 = htonl(key[1]);
    const unsigned int k2 = htonl(key[2]);
    const unsigned int k3 = htonl(key[3]);
    int i;

    for (i = 0; i < isize; i += 2) {
        y = htonl(ibuf[i]);
        z = htonl(ibuf[i + 1]);
        sum = 0;

        for (n = 32; n; --n) {
            sum += delta;
            y += (z << 4) + (k0 ^ z) + (sum ^ (z >> 5)) + k1;
            z += (y << 4) + (k2 ^ y) + (sum ^ (y >> 5)) + k3;
        }

        ibuf[i] = htonl(y);
        ibuf[i + 1] = htonl(z);
    }
}

#endif

#if HEADERS_LOG
void
headersLog(int cs, int pq, const HttpRequestMethod& method, void *data)
{
    HttpReply *rep;
    HttpRequest *req;
    unsigned short magic = 0;
    unsigned char M = (unsigned char) m;
    char *hmask;
    int ccmask = 0;

    if (0 == pq) {
        /* reply */
        rep = data;
        req = NULL;
        magic = 0x0050;
        hmask = rep->header.mask;

        if (rep->cache_control)
            ccmask = rep->cache_control->mask;
    } else {
        /* request */
        req = data;
        rep = NULL;
        magic = 0x0051;
        hmask = req->header.mask;

        if (req->cache_control)
            ccmask = req->cache_control->mask;
    }

    if (0 == cs) {
        /* client */
        magic |= 0x4300;
    } else {
        /* server */
        magic |= 0x5300;
    }

    magic = htons(magic);
    ccmask = htonl(ccmask);

    unsigned short S = 0;
    if (0 == pq)
        S = static_cast<unsigned short>(rep->sline.status());

    logfileWrite(headerslog, &magic, sizeof(magic));
    logfileWrite(headerslog, &M, sizeof(M));
    logfileWrite(headerslog, &S, sizeof(S));
    logfileWrite(headerslog, hmask, sizeof(HttpHeaderMask));
    logfileWrite(headerslog, &ccmask, sizeof(int));
}

#endif

