/*
* $Id$
*/

#include <atomic>
#include <cassert>
#include <exception>
#include <iostream>
#include <libpq-fe.h>
#include <sstream>
#include <stdexcept>
#include <streambuf>
#include <string>
#include <vector>
#include <unordered_set>
#include "Extension.h"
#include "Group.h"
#include "Keyword.h"
#include "Redirection.h"
#include "TitaxConf.h"
#include "edgelib.h"
#include "edgepq.h"
#include "global.h"
#include "md5.h"
#include "sqls.h"
#include "txbase16.h"
#include "Category.h"
#include "DbUserRequestTask.hxx"
#include "KeywordPolicy.hxx"
#include "TAPE.hxx"
#include "TitanSchedulerAPI.hxx"
#include "TitanUser.hxx"
#include "log.h"
#include "titaxtime.h"
#include "ttn_cidr.hxx"
#include "ttn_groups.hxx"
#include "ttn_tools.hxx"
#include "tx_log.hxx"
#include "db_pg.hxx"

#ifdef TTN_ATESTS 
   #include "titaxlib.h"
#endif

namespace  titan_v3 {

static 
struct global_flags_t{
    std::atomic<bool> TXDEBUG_       {};
    std::atomic<bool> VERBOSE_       {};
    std::atomic<bool> SHUTDOWN_NOW_  {};
} gflags{};

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation
 * TODO: consider use of macros 
 */
static unsigned int g_tape_instances_c = 0;
static unsigned int g_tape_instances_d = 0;

static int do_TaTag_tracing = 0;  /*Change to non zero to enable tracing*/
/*Unable to use constexpr or const above as -Wunreachable-code triggers*/

constexpr uint_fast64_t GROUP_POLICY_LIMIT = (  sizeof( std::declval<ids_t>().ids )   /

                                                sizeof( std::declval<ids_t>().ids[0] )   );

tx_static_assert_type(  decltype( std::declval<ids_t>().ids ),
                        policy_id_t,
                        "Unable to compile, the base type of the t_group_policy->ids "\
                        "differs from the expected (policy_id_t)\n"                               );

titan_instance_tracker *get_titan_instance_tracker_TaTag()
{
    /* Create on first access, using double checked lock */
    static titan_instance_tracker *g_TaTag_tracker = nullptr;
    static std::mutex l_lock;
    if (g_TaTag_tracker == nullptr)
    {
        std::lock_guard<std::mutex> l_lg( l_lock );
        if( g_TaTag_tracker == nullptr)
            g_TaTag_tracker = new titan_instance_tracker("TaTag");

    }
    return(g_TaTag_tracker);
}

void print_tracked_TaTag( void *a_p, std::ostream & a_s)
{
    using namespace titan_v3::tools::eop;

    auto * p_item = static_cast< TaTag *>( a_p );
    //a_s << "id=" << p_item->id_ << " ";   // Always 0
    a_s << "clean_uri=" << p_item->clean_uri << " ";
    a_s << "h.sc=" << p_item->http.status_code << " ";
    a_s << "h.sm=" << p_item->http.status_msg << " ";
    a_s << "i.e.r.maj=" << p_item->identity.eph.reason.major << " ";
    a_s << "b_a=" << p_item->block_action << " ";
    a_s << "dmd.iip=" <<p_item->dns_meta_data.iip << " ";
    a_s << "dmd.iip_v=" << p_item->dns_meta_data.iip_valid << " ";
    a_s << "i.e.g_wbl_a=" << p_item->identity.eph.global_wbl_actions << " ";
    a_s << "i.e.c_wbl_a=" << p_item->identity.eph.combined_wbl_actions << " ";
    a_s << "a_t=" << p_item->app_type << " ";
}

void Check_tracker_TaTag( std::ostream & a_os, uint32_t a_older_than_secs)
{
    if (do_TaTag_tracing != 0)
    {
        get_titan_instance_tracker_TaTag()->Check(a_os, a_older_than_secs, print_tracked_TaTag);
    }
    else
    {
        a_os << " TaTag instance tracking is not enabled (" << a_older_than_secs << ")\n";
    }
}

void Output_GTAPE_information( std::ostream & a_os)
{
    a_os << "GTAPE Information\n";
    //a_os << "{sizeof(TaTag): " << sizeof(TaTag) << "}\n";  /*sizeof(TaTag): 37808*/
    //a_os << " wbl.domains.count = " << titan_v3::GTAPE.wbl.domains_.count() << "\n";
    //a_os << " txip_map_count = " << txip_map_count() << "\n";
    //a_os << " active TaPE instances = " << get_count_tape_active_instances() << "\n"; //Is always 1
}

////////////////////////////////////////////////////////////////////////////////

    static tx_log                 g_tx_log;

    //Global TAPE
    TaPE                          GTAPE;
////////////////////////////////////////////////////////////////////////////////
    namespace safe_search {

        namespace youtube { 

            const std::unordered_set<std::string> signatures = {    "www.youtube.com",
                                                                    "m.youtube.com",
                                                                    "youtubei.googleapis.com",
                                                                    "youtube.googleapis.com",
                                                                    "www.youtube-nocookie.com"  };
        }

    }

    namespace restrict_access {

        namespace microsoft {

            std::unordered_set<std::string> signatures = { };
        }
    }

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//       ops
//
////////////////////////////////////////////////////////////////////////////////
std::ostream & operator<<(  std::ostream & out,
                            const POLICY_FLAGS & g    ) noexcept 
{

    out<<"\t   filterEnabled:{" << g.filterEnabled << "}\n";
    out<<"\t   blockAll:{" << g.blockAll << "}\n";
    out<<"\t   onlyAllowSpecified:{" << g.onlyAllowSpecified << "}\n";
    out<<"\t   blockAudioFiles:{" << g.blockAudioFiles << "}\n";
    out<<"\t   blockVideoFiles:{" << g.blockVideoFiles << "}\n";
    out<<"\t   blockExeFiles:{" << g.blockExeFiles << "}\n";
    out<<"\t   blockImageFiles:{" << g.blockImageFiles << "}\n";
    out<<"\t   blockTextFiles:{" << g.blockTextFiles << "}\n";
    out<<"\t   blockArchiveFiles:{" << g.blockArchiveFiles << "}\n";
    out<<"\t   logOnlyGroupName:{" << g.logOnlyGroupName << "}\n";
    out<<"\t   urlKeywordEnabled:{" << g.urlKeywordEnabled << "}\n";
    out<<"\t   blockUserDefinedFiles:{" << g.blockUserDefinedFiles << "}\n";
    out<<"\t   textKeywordEnabled:{" << g.textKeywordEnabled << "}\n";
    out<<"\t   blockIPAddressURLs:{" << g.blockIPAddressURLs << "}\n";
    out<<"\t   notifyKeywordMatching:{" << g.notifyKeywordMatching << "}\n";
    out<<"\t   dontBlockOnKeywords:{" << g.dontBlockOnKeywords << "}\n";
    out<<"\t   blockOtherWorkingHours:{" << g.blockOtherWorkingHours << "}\n";
    out<<"\t   blockOtherNonWorkingHours:{" << g.blockOtherNonWorkingHours << "}\n";
    out<<"\t   blockOtherHTTPSWorkingHours:{" << g.blockOtherHTTPSWorkingHours << "}\n";
    out<<"\t   blockOtherHTTPSNonWorkingHours:{" << g.blockOtherHTTPSNonWorkingHours << "}\n";
    out<<"\t   blockHTTPSWorkingHours:{" << g.blockHTTPSWorkingHours << "}\n";
    out<<"\t   blockHTTPSNonWorkingHours:{" << g.blockHTTPSNonWorkingHours << "}\n";
    out<<"\t   inWorkingDay:{" << g.inWorkingDay << "}\n";
    out<<"\t   sinBin:{" << g.sinBin << "}\n";
    out<<"\t   sizeKeywordEnabled:{" << g.sizeKeywordEnabled << "}\n";
    out<<"\t   httpsBlocked:{" << g.httpsBlocked << "}\n";
    out<<"\t   TXTokens_Show_Message:{" << g.TXTokens_Show_Message << "}\n";
    out<<"\t   pageThreshold:{" << g.pageThreshold << "}\n";
    out<<"\t   urlThreshold:{" << g.urlThreshold << "}\n";
    out<<"\t   safeSearch:{" << static_cast<size_t>(g.safeSearch) << "}\n";
    out<<"\t   instantMessaging:{" << static_cast<size_t>(g.instantMessaging) << "}\n";
    out<<"\t   peerToPeer:{" << static_cast<size_t>(g.peerToPeer) << "}\n";
    out<<"\t   pagesizeThreshold:{" << g.pagesizeThreshold << "}\n";
    out<<"\t   mbThreshold:{" << g.mbThreshold << "}\n";

    return out;
}

std::ostream & operator<<(  std::ostream & out,
                            const POLICY & g    ) noexcept 
{

    out<<"\tpolicyId:{" << g.policyId << "}\n";
    out<<"\tname:{" << g.name << "}\n";
    out<<"\tworkingHoursMask:{" << g.workingHoursMask << "}\n";
    out<<"\tworkingHoursMask:{" << g.workingHoursMask << "}\n";
    out<<"\tnonWorkingHoursMask:{" << g.nonWorkingHoursMask << "}\n";
    out<<"\tcurrentCategoryMask:{" << g.currentCategoryMask << "}\n";
    out<<"\tnotifyCategoryMask:{" << g.notifyCategoryMask << "}\n";
    out<<"\tcustom_workingHoursMask:{" << g.custom_workingHoursMask << "}\n";
    out<<"\tcustom_nonWorkingHoursMask:{" << g.custom_nonWorkingHoursMask << "}\n";
    out<<"\tcustom_currentCategoryMask:{" << g.custom_currentCategoryMask << "}\n";
    out<<"\tcustom_notifyCategoryMask:{" << g.custom_notifyCategoryMask << "}\n";
    out<<"\tldapServerID:{" << g.ldapServerID << "}\n";
    out<<"\tnotifyFlags:{" << g.notifyFlags << "}\n";
    out<<"\temailNotify:{" << (g.emailNotify?:"<NULL>") << "}\n";

    out<<"\t[safeSearchFlags]:\n";
    out<<"\t   SSE_OnOff:{" << g.safeSearchFlags.SSE_OnOff << "}\n";
    out<<"\t   SSE_Moderate:{" << g.safeSearchFlags.SSE_Moderate << "}\n";

    out<<"\t[instantMessagingFlags]:\n";
    out<<"\t   ICQAOLBlocked:{" << g.instantMessagingFlags.ICQAOLBlocked << "}\n";
    out<<"\t   MSNBlocked:{" << g.instantMessagingFlags.MSNBlocked << "}\n";
    out<<"\t   YahooBlocked:{" << g.instantMessagingFlags.YahooBlocked << "}\n";
    out<<"\t   GoogleTalkBlocked:{" << g.instantMessagingFlags.GoogleTalkBlocked << "}\n";

    out<<"\t[nonWorkingHours]:\n";
    if ( g.nonWorkingHours.periods ) {

        for ( size_t  n=0; n < g.nonWorkingHours.periodCount; ++n ) {
            out << "\t   period:{" 
                << g.nonWorkingHours.periods[n].daysOfWeek  << " | " 
                << g.nonWorkingHours.periods[n].start       << " | " 
                << g.nonWorkingHours.periods[n].end         << "}\n";
        }
    }

    out<<"\t[categoryTable]:\n";
/*
    for ( int n=0; n < ; ++n ) {
        out << "\t   category:{"

            << g.nonWorkingHours.periods[n].daysOfWeek  << " | " <<
            << g.nonWorkingHours.periods[n].start       << " | " <<
            << g.nonWorkingHours.periods[n].end         << "}\n";
    }
*/
    out<<"\t[flags]:\n";
    out<< g.flags;

    return out;
}
//------------------------------------------------------------------------------
std::ostream & operator<<(  std::ostream & out,
                            const t_proto_types e   ){

    switch (e){

        case PROTO_NONE:out<<"PROTO_NONE";break;
        case PROTO_HTTP:out<<"PROTO_HTTP";break;
        case PROTO_FTP:out<<"PROTO_FTP";break;
        case PROTO_HTTPS:out<<"PROTO_HTTPS";break;
        case PROTO_COAP:out<<"PROTO_COAP";break;
        case PROTO_COAPS:out<<"PROTO_COAPS";break;
        case PROTO_GOPHER:out<<"PROTO_GOPHER";break;
        case PROTO_WAIS:out<<"PROTO_WAIS";break;
        case PROTO_CACHE_OBJECT:out<<"PROTO_CACHE_OBJECT";break;
        case PROTO_ICP:out<<"PROTO_ICP";break;
        #if USE_HTCP
        case PROTO_HTCP:out<<"PROTO_HTCP";break;
        #endif
        case PROTO_URN:out<<"PROTO_URN";break;
        case PROTO_WHOIS:out<<"PROTO_WHOIS";break;
        //case PROTO_INTERNAL:out<<"PROTO_INTERNAL";break; 
        case PROTO_ICY:out<<"PROTO_ICY";break;
        case PROTO_DNS:out<<"PROTO_DNS";break;
        case PROTO_UNKNOWN:out<<"PROTO_UNKNOWN";break;
        case PROTO_MAX:out<<"PROTO_MAX";break;
        //default:out<<"PROTO_UNKNOWN";break;
    }

    return (out);
}
//------------------------------------------------------------------------------
std::ostream & operator<<(  std::ostream & out,
                            const t_method_type e   ){

    switch (e){

        case METHOD_NONE:out<<"METHOD_NONE";break;
        case METHOD_GET:out<<"METHOD_GET";break;
        case METHOD_POST:out<<"METHOD_POST";break;
        case METHOD_PUT:out<<"METHOD_PUT";break;
        case METHOD_HEAD:out<<"METHOD_HEAD";break;
        case METHOD_CONNECT:out<<"METHOD_CONNECT";break;
        case METHOD_TRACE:out<<"METHOD_TRACE";break;
        case METHOD_OPTIONS:out<<"METHOD_OPTIONS";break;
        case METHOD_DELETE:out<<"METHOD_DELETE";break;
        case METHOD_CHECKOUT:out<<"METHOD_CHECKOUT";break;
        case METHOD_CHECKIN:out<<"METHOD_CHECKIN";break;
        case METHOD_UNCHECKOUT:out<<"METHOD_UNCHECKOUT";break;
        case METHOD_MKWORKSPACE:out<<"METHOD_MKWORKSPACE";break;
        case METHOD_VERSION_CONTROL:out<<"METHOD_VERSION_CONTROL";break;
        case METHOD_REPORT:out<<"METHOD_REPORT";break;
        case METHOD_UPDATE:out<<"METHOD_UPDATE";break;
        case METHOD_LABEL:out<<"METHOD_LABEL";break;
        case METHOD_MERGE:out<<"METHOD_MERGE";break;
        case METHOD_BASELINE_CONTROL:out<<"METHOD_BASELINE_CONTROL";break;
        case METHOD_MKACTIVITY:out<<"METHOD_MKACTIVITY";break;
        case METHOD_PROPFIND:out<<"METHOD_PROPFIND";break;
        case METHOD_PROPPATCH:out<<"METHOD_PROPPATCH";break;
        case METHOD_MKCOL:out<<"METHOD_MKCOL";break;
        case METHOD_COPY:out<<"METHOD_COPY";break;
        case METHOD_MOVE:out<<"METHOD_MOVE";break;
        case METHOD_LOCK:out<<"METHOD_LOCK";break;
        case METHOD_UNLOCK:out<<"METHOD_UNLOCK";break;
        case METHOD_SEARCH:out<<"METHOD_SEARCH";break;
        case METHOD_PURGE:out<<"METHOD_PURGE";break;
        case METHOD_OTHER:out<<"METHOD_OTHER";break;
        default:out<<"METHOD_UNKNOWN";break;

    }

    return (out);
}

//------------------------------------------------------------------------------
std::ostream & operator<<(  std::ostream & out,
                            const BlockReason & r   ){

    switch (r.major){

        case MAJ_REASON_UNKNOWN: out<<"MAJ_REASON_UNKNOWN";break;
        case MAJ_REASON_SYSTEM_BLOCKED: out<<"MAJ_REASON_SYSTEM_BLOCKED";break;
        case MAJ_REASON_USER_BLOCKED: out<<"MAJ_REASON_USER_BLOCKED";break;
        case MAJ_REASON_VIRUS: out<<"MAJ_REASON_VIRUS";break;
        case MAJ_REASON_SPY_URL: out<<"MAJ_REASON_SPY_URL";break;
        case MAJ_REASON_ANTIPHISHING: out<<"MAJ_REASON_ANTIPHISHING";break;
        case MAJ_REASON_USER_DENYLIST: out<<"MAJ_REASON_USER_DENYLIST";break;
        case MAJ_REASON_USER_POLICY_DENYLIST: out<<"MAJ_REASON_USER_POLICY_DENYLIST";break;
        case MAJ_REASON_URL_BLOCK_ALL: out<<"MAJ_REASON_URL_BLOCK_ALL";break;
        case MAJ_REASON_URL_CONTENT: out<<"MAJ_REASON_URL_CONTENT";break;
        case MAJ_REASON_PAGE_CONTENT: out<<"MAJ_REASON_PAGE_CONTENT";break;
        case MAJ_REASON_IP_ADDR: out<<"MAJ_REASON_IP_ADDR";break;
        case MAJ_REASON_FILE_TYPE: out<<"MAJ_REASON_FILE_TYPE";break;
        case MAJ_REASON_PAGE_KEYWORD: out<<"MAJ_REASON_PAGE_KEYWORD";break;
        case MAJ_REASON_UNCLASS_SITE: out<<"MAJ_REASON_UNCLASS_SITE";break;
        case MAJ_REASON_URL_NOT_ALLOWED: out<<"MAJ_REASON_URL_NOT_ALLOWED";break;
        case MAJ_REASON_SIN_BIN: out<<"MAJ_REASON_SIN_BIN";break;
        case MAJ_REASON_URL_KEYWORD: out<<"MAJ_REASON_URL_KEYWORD";break;
        case MAJ_REASON_INSTANT_MESSAGING: out<<"MAJ_REASON_INSTANT_MESSAGING";break;
        case MAJ_REASON_PEER_TO_PEER: out<<"MAJ_REASON_PEER_TO_PEER";break;
        case MAJ_REASON_HTTPS_BLOCKED: out<<"MAJ_REASON_HTTPS_BLOCKED";break;
        case MAJ_REASON_UNCLASS_HTTPS_SITE: out<<"MAJ_REASON_UNCLASS_HTTPS_SITE";break;
        case MAJ_REASON_ADMIN_BLOCKED: out<<"MAJ_REASON_ADMIN_BLOCKED";break;
        case MAJ_REASON_DOWNLIMIT_BLOCKED: out<<"MAJ_REASON_DOWNLIMIT_BLOCKED";break;
        case MAJ_REASON_BYPASSED: out<<"MAJ_REASON_BYPASSED";break;
        case MAJ_REASON_UNKNOWN_ERROR:
        default:out<<"MAJ_REASON_UNKNOWN_ERROR";break;

    }

#define TEST_FILE_CAT_(a_cat_,a_msg_)   \
if (r.minor.category & (a_cat_) ){      \
    out << (a_msg_);                    \
    return (out);                       \
}

    if ( r.major==MAJ_REASON_FILE_TYPE ){

        TEST_FILE_CAT_(MIN_REASON_CAT_AUDIO,"(MIN_REASON_CAT_AUDIO)")
        TEST_FILE_CAT_(MIN_REASON_CAT_VIDEO,"(MIN_REASON_CAT_VIDEO)")
        TEST_FILE_CAT_(MIN_REASON_CAT_EXE,"(MIN_REASON_CAT_EXE)")
        TEST_FILE_CAT_(MIN_REASON_CAT_IMAGE,"(MIN_REASON_CAT_IMAGE)")
        TEST_FILE_CAT_(MIN_REASON_CAT_TEXT,"(MIN_REASON_CAT_TEXT)")
        TEST_FILE_CAT_(MIN_REASON_CAT_ARCHIVE,"(MIN_REASON_CAT_ARCHIVE)")
        TEST_FILE_CAT_(MIN_REASON_CAT_USER,"(MIN_REASON_CAT_USER)")

    }

    return out;
}
//------------------------------------------------------------------------------
std::ostream& operator<<(std::ostream& out, const uint128_t& v_){
    out << titan_v3::tools::functors::tos{v_};
    return out;
}
//------------------------------------------------------------------------------
std::ostream& operator<<(std::ostream& out, const search_identity_by & l_){

    using namespace titan_v3::tools::eop;

    if ( search_identity_by::none != l_  ){

        if ( as_bool( l_ & search_identity_by::ip ) ){

            out << "IP ";

        }

        if ( as_bool( l_ & search_identity_by::uname ) ){

            out << "UNAME ";

        }

        if ( as_bool( l_ & search_identity_by::uid ) ){

            out << "UID ";

        }

        if ( as_bool( l_ & search_identity_by::lid ) ){

            out << "LID ";

        }

    } else {

        out<<"None "; 

    }

    return out;

}
//------------------------------------------------------------------------------
std::ostream& operator<<(   std::ostream& out,
                            const TaTag & l_    )
{

    out<<"[TAG]:\n";
    out<<"\tconsumed_body_sz:{"<<l_.consumed_body_sz<<"}\n";
    out<<"\trequest_error_ctx:{"<<l_.request_error_ctx<<"}\n";
    out<<"\tapp_type:{"<<l_.app_type<<"}\n";
    out<<"\tapp_args:{"<<l_.app_args<<"}\n";

    out<<"\tparent:{"<<l_.identity.parent.name<<"}\n";
    out<<"\tchild:{"<<l_.identity.child.name<<"}\n";

    out<<&l_.dns_meta_data<<"\n";

    out<<"[HTTP]\n";
    out<<"\ttstatus_msg:{"<<l_.http.status_msg<<"}\n";
    out<<"\ttstatus_code:{"<<l_.http.status_code<<"}\n";
    out<<"[effective_policyholder]\n";
    
    auto * usr_ = l_.identity.eph.user;

    if ( usr_ ) {
        out<<"\tname:{"<< usr_->name <<"}\n";
        out<<"\tid:{"<< usr_->id  <<"}\n";
    }
    else {
        out<<"\tname:{<NULL>}\n";
        out<<"\tid:{-1}\n";
    }
    out<<"\tip:{"<<l_.identity.eph.location<<"}\n";
    out<<"\tck:{"<<l_.identity.eph.cloud_key<<"}\n";
    out<<"\treason:{"<<l_.identity.eph.reason<<"}\n";
    out<<"\tcombined_wbl_actions:{"<<l_.identity.eph.combined_wbl_actions<<"}\n";
    out<<"\turi:{"<<l_.identity.eph.uri<<"}\n";
    out<<"\tcategory_name:{";
    out<<l_.category_getnames("|");
    out<<"}\n\tcategory_numbers:{";
    out<<titan_v3::tools::functors::citer_sep{l_.identity.eph.category_numbers,"|"};
    out<<"}\n\tcombined_group_names:{";
    out<<titan_v3::tools::functors::citer_sep{l_.identity.eph.combined_group_names,"|"};
    out<<"}\n\tcombined_policy_flags:\n"<<&l_.identity.eph.combined_policy.flags;
    out<<"\n\tpolicy_info:{";

    if ( usr_ ) {

        out<<"\n\t\tinherited:{"<< usr_->policy_info.inherited  <<"}\n";

        out<<"\n\t\tgroups:{";

        for(size_t i=0;i< usr_->policy_info.groups.length;++i) {

            out<< usr_->policy_info.groups.ids[i]<<"|";

        }

        out<<"}\n\t\tpolicies:{";

        for(size_t i=0;i< usr_->policy_info.policies.length;++i) {

            out<<usr_->policy_info.policies.ids[i]<<"|";

        }
    }

    out<<"}\n}\n\tnotifications:{";

    out<<titan_v3::tools::functors::citer_sep{l_.identity.eph.notifications,"|"};

    out<<"}\n\t[combined_policy]\n";

    out<<l_.identity.eph.combined_policy<<"\n";

    return out;
}

//------------------------------------------------------------------------------
std::ostream &operator<<(   std::ostream& out,
                            const t_meta_data & l_ ) noexcept 
{

    out<<"[meta_data]:\n";

    out<<"\t_raw_size:{"<<l_.raw_size<<"}\n";
    out<<"\t_raw_ptr:{"<<(l_.raw_size && l_.raw_ptr.cc ? l_.raw_ptr.cc : "<NULL>")<<"}\n";
    out<<"\t_iuid_valid:{"<<l_.iuid_valid<<"}\n";
    out<<"\t_iuid:{"<<l_.iuid<<"}\n";
    out<<"\t_ilid_valid:{"<<l_.ilid_valid<<"}\n";
    out<<"\t_ilid:{"<<l_.ilid<<"}\n";
    out<<"\t_ip_valid:{"<<l_.iip_valid<<"}\n";
    out<<"\t_ip:{"<<l_.iip<<"}\n";
    out<<"\t_crc:{"<<l_.crc<<"}\n";

    return out;
}
////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//       TaTag
//
////////////////////////////////////////////////////////////////////////////////
TaTag::TaTag()
{
    /* DI */
    if (do_TaTag_tracing != 0) 
        get_titan_instance_tracker_TaTag()->Add( this );

    reset();
}

TaTag::~TaTag()
{
    this->meta_data_clear();

    this->clearScheduledContext();

    /* DI */
    if (do_TaTag_tracing != 0) 
        get_titan_instance_tracker_TaTag()->Remove( this );

}

void TaTag::init_() noexcept 
{
    this->timestamp_=std::chrono::system_clock::now();
    this->user_clear();
    this->meta_data_clear();
    this->http.status_msg.clear();

     #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 
       //remove this "swiss-cheese" macro when we finally start building only on the FB11+
         this->http.status_msg.reserve( 256 );
     #endif

    this->http.status_code=scOkay;

    this->clearScheduledContext();
}

std::string TaTag::category_getnames(std::string sep) const 
{
    return titan_v3::tools::functors::citer_ols{this->identity.eph.category_names,sep};
}

//------------------------------------------------------------------------------
void TaTag::clear() noexcept
{
    app_type=txapp_cmd_none;
    magic_type = 0;
    ttn_md5_clear(&magic_id);

    block_action = {};

    dns_meta_data = {};
    consumed_body_sz=0;
    request_error_ctx=0;
    clean_uri_sz=0;
    clean_uri[0]=0;
//    std::memset( clean_uri, 0, sizeof(clean_uri) );

    this->init_();
}

//------------------------------------------------------------------------------
std::string TaTag::get_timestamp() const 
{
    std::time_t ts_ = std::chrono::system_clock::to_time_t(this->timestamp_);
    char buf[128]={};
    if (::titax_localtime_ex(&ts_, buf,sizeof(buf)-1)){
        return {buf};
    }
    return {};
}
//------------------------------------------------------------------------------
void TaTag::reset() noexcept
{

   clear();

    if (    !default_parent_set_    && 

            users_cache                 )  {

        users_cache->load_default_info(this->identity.parent);

        default_parent_set_=true;

    }

    this->clearScheduledContext();
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//       IHRequest
//
////////////////////////////////////////////////////////////////////////////////   
bool IHRequest::dump(std::ostream& out) {

    out<<"\n>>[IHRequest]:\n";
    out<<"\t{"<<this->get_method()<<"}\n";
    out<<"\t{"<<this->get_canonical()<<"}\n";
    out<<"\t{"<<this->get_host()<<"}\n";
    out<<"\t{"<<this->is_host_numeric()<<"}\n";
    out<<"\t{"<<this->get_path()<<"}\n";
    out<<"\t{"<<this->get_protocol()<<"}\n";
    out<<"\t{"<<this->get_port()<<"}\n";
    out<<"\t{"<<this->get_client_addr()<<"}\n";
    out<<"\t{"<<this->get_indirect_client_addr()<<"}\n";
    out<<"\thttp headers:\n"<<this->headers_get_all("\t   ")<<"\n";
    out<<this->get_flags();
    out<<"\tvalid:{"<<this->is_request_valid()<<"}\n";
    out<<this->ttag;

    return true;

}
//------------------------------------------------------------------------------

bool IHRequest::detect_magid(const std::string & magic_id_str) {

    ttag.app_args.clear();

    std::string url_path = this->get_path();

    size_t magid_pos = url_path.find(magic_id_str);

    if (magid_pos != std::string::npos) {

        size_t session_pos = url_path.find( std::string{REQUEST_SESSION_COOKIE, REQUEST_SESSION_COOKIE_SZ} );

        if (session_pos == std::string::npos){
            ttag.magic_type = 1;
            ttag.block_action = block_actions::magic;
            magid_pos += MD5BASE64_VAL_SIZE;
            if (magid_pos < url_path.size() && url_path[magid_pos] == '/') {
                ++magid_pos;
                size_t end_pos = url_path.find("/", magid_pos);
                if (end_pos != std::string::npos) {
                    ttag.app_args+="xc=";
                    ttag.app_args+=url_path.substr(magid_pos, end_pos - magid_pos);
#if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )

                    ttag.app_args+='&';

#endif
                    magid_pos = end_pos + 1;
                } else {
                    ttag.app_args+="xc=0&";
                }
                end_pos = url_path.find(".js", magid_pos);
                if (end_pos == std::string::npos) {
                    end_pos = url_path.size();
                }
                if (end_pos > magid_pos) {
                    ttag.app_args+="xs=";
                    ttag.app_args+=url_path.substr(magid_pos, end_pos - magid_pos);
                    //magid_pos = end_pos;
                } else {
                    ttag.app_args+="xs=0";
                }
            } else {
                ttag.app_args+="xs=0&xc=0";
            }
        } else {
            size_t query_pos = url_path.find("?");
            if (query_pos != std::string::npos) {
                ttag.magic_type = 3;
                ttag.block_action = block_actions::magic;
                ttag.app_args+=url_path.substr(++query_pos);
            }
        }
        return true;
    }
    return false;
}

bool IHRequest::detect_cloud_key_state() {

    if (ttag.block_action != block_actions::none) {

        return false;

    }

    IHRequestFlags & flags_=this->get_flags();

    if (    !ttag.user_found()                      ||

            !ttag.identity.eph.user->TXTokens_Count     ) {

        ttag.block_action = block_actions::block;

        return false;

    }

    size_t session_pos{};

    size_t session_end{};

    std::string delimiter{};

    std::string lcookies{};
    
    bool state{};

    std::tie( state, lcookies, delimiter ) = http_tools::scan_for_hcookies( *this );

    if ( state ){

        if ((session_pos=lcookies.find( std::string{REQUEST_SESSION_COOKIE,REQUEST_SESSION_COOKIE_SZ} )) != std::string::npos){

            const size_t value_pos = session_pos + REQUEST_SESSION_COOKIE_SZ + 1;

            if (value_pos <= lcookies.size()) {

                session_end=lcookies.find(delimiter, session_pos);

                flags_.ttn_session_started = true;

                ttag.ck_session_id = lcookies.substr(session_pos, session_end - session_pos);

            }

        }

    }

    ttn_md5 md5_{};

   if ( flags_.ttn_is_local_request ) {

      if ( ! ( titax_conf_svr_magid(&md5_) && md5_.hex[0] && md5_.hexsz ) ) {

         titax_log(  LOG_ERROR,
                     "ASSERT :: %s:%d titax_conf_svr_magid failed - dying!\n",
                     __func__,
                     __LINE__                                                 );
         exit(-1);
      }
   }

    std::string magic_id_str{   flags_.ttn_is_local_request         ?

                                std::string{md5_.hex,md5_.hexsz}    :

                                get_host_magid()                        };

    if (!magic_id_str.size()){

        //TODO: TEST ME !!!
        ttag.block_action = block_actions::detect;

        return false;

    }

    if (detect_magid(magic_id_str)){

        return false;

    }

    size_t ck_pos{};

    if (    !lcookies.size()                                                ||

            ( ck_pos = lcookies.find(magic_id_str) ) == std::string::npos       ){

        ttag.block_action = block_actions::detect;

        return false;

    }

    const size_t value_pos = ck_pos + magic_id_str.size() + 1;

    if ( value_pos >= lcookies.size() ){

        ttag.block_action = block_actions::detect;

        return false;

    }

    size_t end_pos = lcookies.find( delimiter, value_pos );

    if ( std::string::npos == end_pos ) {

      end_pos = lcookies.size();
    }

    const size_t value_sz = { end_pos > value_pos ? 

                              end_pos - value_pos : 

                              0                       };
  
    std::string cookie_val = {   value_sz >= MD5BASE64_VAL_SIZE            ?

                                 lcookies.substr( value_pos, value_sz )    :

                                 std::string{}                                };

    const TitaxCKey * const lookup_ck = {   cookie_val.size()                                  ?
                                            TitaxCKey_find_by_tokenval( cookie_val.c_str() )   :
                                            nullptr                                               };

    if ( lookup_ck ){

        if ( lookup_ck->user_id == ttag.identity.eph.user->id ){

            //there are tokens, cookies, cookie is ok, user is found, always log, always allow
            ttag.block_action = {};

            ttag.identity.eph.reason.major=MAJ_REASON_BYPASSED;

            ttag.http.status_msg={MAJ_REASON_BYPASSED_MSG,MAJ_REASON_BYPASSED_MSG_SZ};

            flags_.ttn_has_been_logged={};

            ttag.identity.eph.cloud_key = lookup_ck->str;

            //Do not send our cookies to the target server.
            std::string new_cookie{ lcookies.erase(ck_pos, end_pos - ck_pos + 1).erase( session_pos, session_end - session_pos + 1) };

            headers_del(HDR_COOKIE);

            headers_put(HDR_COOKIE, new_cookie);

            return true;

        }

        TXDEBUG( "TitaxCKey_find_by_tokenval FAILED :%zu:%zu:%s\n", 
                 ttag.identity.eph.user->id,
                 lookup_ck->user_id,
                 lookup_ck->str     );

    } else {

        TXDEBUG("TitaxCKey_find_by_tokenval FAILED :%zu:-1:\n", ttag.identity.eph.user->id);

    }

    ttag.block_action = block_actions::detect;

    return false;

}

std::string IHRequest::get_host_magid() {

    if (get_flags().ttn_is_local_request) {

        ttn_md5 r_{};

        if (titax_conf_svr_magid(&r_) && r_.hex[0] && r_.hexsz){

            return {r_.hex,r_.hexsz};

        }

    }

    t_strptr r_=ttn_md5_get_str(&ttag.magic_id);

    if (r_.ptr_ && r_.sz_) {

        return {r_.ptr_,r_.sz_};

    }

    std::string host_=get_host();

    if (const size_t sz_=host_.size()){

        host_.insert(0,"-",1);

        if (ttn_get_md5raw(host_.c_str(),static_cast<uint32_t>(sz_+1),&ttag.magic_id)){

            (void)ttn_md5_base16_encode(&ttag.magic_id);

            r_=ttn_md5_get_str(&ttag.magic_id);

            if (r_.ptr_ && r_.sz_){

                return {r_.ptr_,r_.sz_};

            }

        }

    }

    return {"None"};

}

bool IHRequest::serialize(const t_err_type err_type ) {

    using namespace titan_v3::tools::eop;

    std::stringstream ss_{};

    std::string delimiter{};

    std::string cstr_{};

    bool state{};

    std::tie( state, cstr_, delimiter ) = http_tools::scan_for_hcookies( *this );

    if ( state ){

        const size_t retry_pos = cstr_.find("titan-retries");

        if (retry_pos != std::string::npos) {

           return false;

        }

        ss_ << cstr_ << delimiter;
    }

    //always close such connections otherwise squid will keep them alive
    if (headers_has(HDR_CONNECTION)){

        headers_del(HDR_CONNECTION);

    }

    headers_put(HDR_CONNECTION, "close");

    (void)headers_del(HDR_COOKIE);

    if ( !ttag.identity.eph.uri.length() ) {

        ttag.identity.eph.uri=get_canonical();

    }

    size_t len_{};

    static tools::SBuff sb_(4096);

    if ( ( len_ = ttag.identity.eph.uri.length() ) ){

        ss_ << "u=";

        const size_t url_enc_sz_ = ( 3 * len_ ) + 1;

        if ( url_encode(    ttag.identity.eph.uri.c_str(),
                            len_,
                            url_enc_sz_,
                            sb_.buf( url_enc_sz_ )          )   ){

            ss_ << sb_.buf() << delimiter;

        } else 
            len_=0;

    }

    if ( !len_ ){

        ss_ << "0" << delimiter;

    }

    const auto & flags_ = this->get_flags();

    //client info
    const auto & cip=get_client_addr();

    //svr info
    const cfg::TCFGInfo & cfg=GTAPE.ttncfg;

    ss_ << "si=" <<(    checks::is_ipv4(cip)    ?

                        cfg.ip_4_str            :

                        cfg.ip_6_str                );

    ss_ <<  delimiter;

    //provide a minimal set of cookies for squid error
    if ( ( ! flags_.ttn_request_is_blocked          && 

           err_type != ERR_NONE                 )   ||

           flags_.ttn_explicitly_allowed                ) {

            ss_ << "ca="  << 4 << delimiter
                << "se="  << err_type<<delimiter 
                << "ct="  << flags_.ttn_is_local_request << delimiter
                << "wtc=" << (this->is_target_server()?1:0) << delimiter;

            ss_ << "titan-retries=1";

            ss_.sync();

            headers_put(HDR_COOKIE,ss_.str());

            return true;

    }

    ss_ << "umi=" << get_host_magid() << delimiter;
    ss_ << "ca=" << ttag.block_action << delimiter
        << "cip=" << cip << delimiter;

    if (ttag.identity.eph.user->invalid_user) {

        ss_ << "cid=" << INVALID_ << delimiter;

    } else {

        ss_ << "cid=" << ttag.identity.eph.user->id << delimiter;

    }

    ss_ << "cn=";

    len_=0;

    if (    ttag.user_found()                                   &&

            ( len_ = strlen( ttag.identity.eph.user->name ) )       ){

                const size_t usr_enc_sz_ = len_ * 3 + 1;

                if (    url_encode( ttag.identity.eph.user->name,
                                    len_,
                                    usr_enc_sz_,
                                    sb_.buf( usr_enc_sz_ )          )   ){

                    ss_<<sb_.buf()<<delimiter;

                } else 
                    len_=0;

    }

    if ( !len_ ){

        ss_ << "0" << delimiter;

    }

    ss_ << "cs=" << ttag.ck_session_id << delimiter
        << "ct=" << flags_.ttn_is_local_request << delimiter
        <<"wtc="<<(this->is_target_server()?1:0) << delimiter;

    ttn_md5 md5_{};

    ss_ <<  delimiter << "smi=" << (    titax_conf_svr_magid(&md5_)         ?

                                        std::string{md5_.hex,md5_.hexsz}    :

                                        ""                                      );


    if (    !flags_.ttn_session_started     && 

            !flags_.ttn_is_local_request        ) {

        //error info
        ss_ <<  delimiter << "ei=" << ttag.http.status_code << delimiter << "et=";

        std::string category_str=this->ttag.category_getnames();

        //only for WTC
        if (    ttag.http.status_code == scOkay     && 

                (   is_target_server()              ||

                    flags_.accelerated  )               ){

                    ttag.http.status_msg="The URL has been categorized under: ";

                    ttag.http.status_msg+=category_str;
        }

        if ( ( len_ = ttag.http.status_msg.size() ) ){

            const size_t msg_stat_enc_sz_ = ( 3 * len_ ) + 1;

            if (    url_encode( ttag.http.status_msg.c_str(),
                                len_,
                                msg_stat_enc_sz_,
                                sb_.buf( msg_stat_enc_sz_ )     )   ){

                ss_<<sb_.buf()<<delimiter;

            } else 
                len_=0;

        }

        if ( !len_ ){

            ss_<<"0"<<delimiter;

        }

        //category info
        ss_ << "cai=" << ttag.category_get() << delimiter<< "cat=";

        if ( ( len_ = category_str.size() ) ){

            const size_t cat_enc_sz_ = ( 3 * len_ ) + 1;

            if (    url_encode( category_str.c_str(),
                                len_,
                                cat_enc_sz_,
                                sb_.buf( cat_enc_sz_ )  )   ){

                ss_<<sb_.buf()<<delimiter;

            } else 
                len_=0;

        }

        if ( !len_ ){

            ss_<<"0"<<delimiter;

        }

        //group info
        ss_ << "gt=";

        if ( ( len_ = ttag.identity.eph.combined_group_names.size() ) ){

            std::string group_str = tools::functors::citer_sep{ttag.identity.eph.combined_group_names,{','}};

            if ( ( len_ = group_str.size() ) ){

                const size_t grp_enc_sz_ = ( 3 * len_ ) + 1;

                if (    url_encode( group_str.c_str(),
                                    len_,
                                    grp_enc_sz_,
                                    sb_.buf( grp_enc_sz_ )  )   ) {

                    ss_<<sb_.buf()<<delimiter;

                } else 
                    len_=0;

            }

        }

        if ( !len_ ){

            ss_<<"0";

        }

    }

    if ( ttag.block_action == block_actions::magic ) {

        ss_ << delimiter << "mt=" << ttag.magic_type << delimiter << "ma=";

        if ( ( len_ = ttag.app_args.size() ) ) {

            const size_t ma_enc_sz_ = ( 3 * len_ ) + 1;

            if (    url_encode( ttag.app_args.c_str(), 
                                len_, 
                                ma_enc_sz_, 
                                sb_.buf( ma_enc_sz_ )   )   ){

                ss_<<sb_.buf();

            } else 
                len_=0;

        }

        if ( !len_ ){

            ss_<<"0";

        }

        ss_ << delimiter;

    }

    ss_ << "titan-retries=1";

    ss_.sync();

    headers_put(HDR_COOKIE, ss_.str());

    return true;

}

//------------------------------------------------------------------------------   
bool IHRequest::redirect2bp(    const t_err_type err_type,
                                const bp_backed_http_t & bp_backed_http_info    ){

    if (checks::is_nz(bp_backed_http_info.ip)){

        this->set_host(factory::to_string(bp_backed_http_info.ip));
        this->set_port(bp_backed_http_info.port);
        this->set_path(bp_backed_http_info.path);
        if (this->serialize(err_type)) {
            IHRequestFlags & flags=this->get_flags();
            //always close such connections otherwise squid will keep them alive
             flags.ttn_client_dst_passthru = true;
             flags.proxyKeepalive=false;
             flags.ttn_is_local_request=true;
             flags.ttn_do_not_check=true;

             //we always redirect to http even if original requests was https
             this->set_protocol(PROTO_HTTP);
             //check method
             switch (this->get_method()){
                case METHOD_GET:
                case METHOD_PUT:
                case METHOD_HEAD:
                    break;
                case METHOD_POST:
                    headers_del(HDR_CONTENT_LENGTH);
                    headers_del(HDR_TRANSFER_ENCODING);
                    break;
                default:this->set_method(METHOD_GET);break;
            }

            return true;
        }
    }

    return false;
}
//------------------------------------------------------------------------------
void IHRequest::set_icap_error(std::string msg) {

    #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 

        // remove this "swiss-cheese" macro when we finally start building only on the FB11+
        ttag.http.status_msg=std::move(msg);

    #endif

    ttag.http.status_code = scForbidden;

    this->get_flags().ttn_request_is_blocked = true;

    //this->get_flags().ttn_blocked_by_icap=true;
}
//------------------------------------------------------------------------------
//TODO::Are we sure that for every http request sent over network, the squid will also create the new HttpRequest object ?
t_wbl_actions IHRequest::check_global_wbl_actions() noexcept 
{

    auto & eph = this->ttag.identity.eph;

    if ( eph.global_wbl_actions_checked ) {

        return eph.global_wbl_actions;
    }

    const auto & tape = GTAPE;

    if ( app_mode_t::cloud == tape.app_mode ) {
        /** 
         * since this code doesn't check multiple blocking reasons,
         * it doesn't have to include the state of the least restrictive 
         */
        eph.global_wbl_actions = tape.wbl.check_fqdn( get_host(), INVALID_ );

    }
    else {

        eph.global_wbl_actions = tape.wbl.check_all( get_host(), get_path() );
    }

    eph.global_wbl_actions_checked = true;

    return eph.global_wbl_actions;
}

////////////////////////////////////////////////////////////////////////////////
//       ACacheInfo
////////////////////////////////////////////////////////////////////////////////
void ACacheInfo::operator()(ICacheInfo::t_cache * const out) {
    (void)(out && zm(out,sizeof(ICacheInfo::t_cache)));
}

////////////////////////////////////////////////////////////////////////////////
//
//       ARequest
//
////////////////////////////////////////////////////////////////////////////////
unsigned short ARequest::get_port() const 
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
void ARequest::set_port(const size_t)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::get_host() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
void ARequest::set_host(const std::string&)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::get_canonical()
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
void ARequest::set_canonical(std::string)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
bool ARequest::is_host_numeric() const 
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
t_proto_types ARequest::get_protocol() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
bool ARequest::set_protocol(const t_proto_types)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::get_path() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
void ARequest::set_path(const std::string& )
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
raw_ipaddr_t  ARequest::get_client_addr()
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
bool ARequest::set_client_addr(const raw_ipaddr_t&)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
raw_ipaddr_t ARequest::get_indirect_client_addr()
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::get_x_forwarded_for_iterator() const 
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string  ARequest::get_extacl_user() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string  ARequest::get_extacl_passwd() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::get_extacl_log() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string  ARequest::get_extacl_message() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
int ARequest::headers_has(const t_http_hdr_types) const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::headers_get(const t_http_hdr_types)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::headers_getex(const t_http_hdr_types)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
void ARequest::headers_put(const t_http_hdr_types,const std::string&)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
int ARequest::headers_del(const t_http_hdr_types)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
void ARequest::headers_clear()
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::headers_get_all(std::string)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
int ARequest::get_authenticateUserAuthenticated() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::get_auth_user_request_username() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
IHRequestFlags & ARequest::get_flags()
{
    return this->flags;
}
//------------------------------------------------------------------------------
IBodyPipe * ARequest::get_bodypipe() const 
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
t_method_type ARequest::get_method() const 
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
bool ARequest::set_method(const t_method_type)
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
int64_t ARequest::get_content_length() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::get_scheme() const 
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
bool ARequest::reset()
{
    this->ttag.reset();
    flags = {};
    return true;
}
//------------------------------------------------------------------------------
bool ARequest::is_target_server() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
std::string ARequest::get_sni() const
{
    assert( false && "unimplemented");
}
//------------------------------------------------------------------------------
bool ARequest::can_report_errors() const
{
    assert( false && "unimplemented");
}

////////////////////////////////////////////////////////////////////////////////
//
//       TaPE (Titan Policy Engine)
//
////////////////////////////////////////////////////////////////////////////////
TaPE::TaPE() :  ttncfg{ttncfg_},
                wbl{*this},
                ldap{*this},
                tools{*this}{

    /* DI */
    g_tape_instances_c++;
}

TaPE::~TaPE(){

    //final cleanup
    if ( this->ext_map_ ) {

        delete[] this->ext_map_;

    }

    /*
    * cleanup here everything e.g. titaxlib 
    */
    destroy_users_cache(); /* opt */
    /* DI */
    g_tape_instances_d++;
}

//------------------------------------------------------------------------------
bool TaPE::open_logger(){
    tx_log & log_=g_tx_log;
    if (log_.active()) 
        return (true);

    const cfg::TCFGInfo & cfg_=this->ttncfg_;
    switch (cfg_.log_cfg.type){
        case ot_file:return (log_.tx_flog::open(cfg_.log_cfg.path,cfg_.log_cfg.path_sz));
        case ot_tcp:return (cfg_.log_cfg.path_sz?log_.tx_slog::open_tcp(cfg_.log_cfg.ip,cfg_.log_cfg.port):false);
        case ot_uds:return (cfg_.log_cfg.path_sz?log_.tx_slog::open_uds(cfg_.log_cfg.path):log_.open_default());
        default:return (true);
    }
}

//------------------------------------------------------------------------------
void TaPE::combine_policies(    const size_t index, 
                                IHRequest & rq_,
                                const POLICY * const __restrict policy,
                                const bool least_restrictive            )
{
    /**
    * TODO: WBL //>>>
    */
    if ( policy ){

        TaTag & ttag = rq_.ttag;

        POLICY * const combi = &ttag.identity.eph.combined_policy;

        //Check if it is the first policy to combine.
        if( !index ) {

            ttag.identity.eph.combined_wbl_actions = wbl.check_fqdn(    rq_.get_host(),
                                                                        policy->policyId    );

            *combi = *policy;

            // combine these so that it we can do a single test
            if( !policy->flags.inWorkingDay ) {

                combi->flags.blockHTTPSWorkingHours = policy->flags.blockHTTPSNonWorkingHours;

                combi->flags.blockOtherWorkingHours = policy->flags.blockOtherNonWorkingHours;

                combi->flags.blockOtherHTTPSWorkingHours = policy->flags.blockOtherHTTPSNonWorkingHours;

            }

            // our combined group is always going to say its in a working day
            combi->flags.inWorkingDay = true;

            return;
        }

        // if any group is unfiltered then all are unfiltered
        combi->flags.filterEnabled &= policy->flags.filterEnabled;

        // sinBin flag is TRUE when "Block Internet Access" is ON.
        // In that case this applies to ALL policies.
        combi->flags.sinBin |= policy->flags.sinBin;
        // dontBlockOnKeywords is the variable for log but don't block
        // stupid legacy field use but not my choice
        combi->flags.dontBlockOnKeywords |= policy->flags.dontBlockOnKeywords;

        combi->flags.logOnlyGroupName |= policy->flags.logOnlyGroupName;

        combine_actions(    ttag.identity.eph.combined_wbl_actions,

                            wbl.check_fqdn( rq_.get_host(), policy->policyId ),

                            least_restrictive                                       );

        if( least_restrictive ) {

            combi->flags.blockAll &= policy->flags.blockAll;

            combi->flags.blockAudioFiles &= policy->flags.blockAudioFiles;

            combi->flags.blockVideoFiles &= policy->flags.blockVideoFiles;

            combi->flags.blockImageFiles &= policy->flags.blockImageFiles;

            combi->flags.blockExeFiles &= policy->flags.blockExeFiles;

            combi->flags.blockTextFiles &= policy->flags.blockTextFiles;

            combi->flags.blockArchiveFiles &= policy->flags.blockArchiveFiles;

            combi->flags.blockUserDefinedFiles &= policy->flags.blockUserDefinedFiles;

            combi->flags.onlyAllowSpecified &= policy->flags.onlyAllowSpecified;

            combi->flags.blockIPAddressURLs &= policy->flags.blockIPAddressURLs;

            combi->flags.urlKeywordEnabled &= policy->flags.urlKeywordEnabled;

            combi->flags.urlThreshold = std::max( combi->flags.urlThreshold, policy->flags.urlThreshold );

            combi->flags.TXTokens_Show_Message &=  policy->flags.TXTokens_Show_Message;

            // combine these so that it we can do a single test
            if( policy->flags.inWorkingDay ) {

                combi->flags.blockHTTPSWorkingHours &= policy->flags.blockHTTPSWorkingHours;

                combi->flags.blockOtherWorkingHours &= policy->flags.blockOtherWorkingHours;

                combi->flags.blockOtherHTTPSWorkingHours &=policy->flags.blockOtherHTTPSWorkingHours;

            } else {

                combi->flags.blockHTTPSWorkingHours &= policy->flags.blockHTTPSNonWorkingHours;

                combi->flags.blockOtherWorkingHours &= policy->flags.blockOtherNonWorkingHours;

                combi->flags.blockOtherHTTPSWorkingHours &= policy->flags.blockOtherHTTPSNonWorkingHours;

            }

            combi->currentCategoryMask |= policy->currentCategoryMask;

            combi->custom_currentCategoryMask |= policy->custom_currentCategoryMask;

            if ( !combi->flags.mbThreshold || !policy->flags.mbThreshold ) {

                combi->flags.mbThreshold = 0;
            }
            else {

                combi->flags.mbThreshold = std::max ( combi->flags.mbThreshold, policy->flags.mbThreshold );
            }

            return;
        }
        //else
        combi->flags.blockAll |= policy->flags.blockAll;

        combi->flags.blockAudioFiles |= policy->flags.blockAudioFiles;

        combi->flags.blockVideoFiles |= policy->flags.blockVideoFiles;

        combi->flags.blockImageFiles |= policy->flags.blockImageFiles;

        combi->flags.blockExeFiles |= policy->flags.blockExeFiles;

        combi->flags.blockTextFiles |= policy->flags.blockTextFiles;

        combi->flags.blockArchiveFiles |= policy->flags.blockArchiveFiles;

        combi->flags.blockUserDefinedFiles |= policy->flags.blockUserDefinedFiles;

        combi->flags.onlyAllowSpecified |= policy->flags.onlyAllowSpecified;

        combi->flags.blockIPAddressURLs |= policy->flags.blockIPAddressURLs;

        combi->flags.urlKeywordEnabled |= policy->flags.urlKeywordEnabled;

        combi->flags.urlThreshold = std::min( combi->flags.urlThreshold,policy->flags.urlThreshold );

        combi->flags.TXTokens_Show_Message |=  policy->flags.TXTokens_Show_Message;

        // combine these so that it we can do a single test
        if( policy->flags.inWorkingDay ) {

            combi->flags.blockHTTPSWorkingHours |= policy->flags.blockHTTPSWorkingHours;

            combi->flags.blockOtherWorkingHours |= policy->flags.blockOtherWorkingHours;

            combi->flags.blockOtherHTTPSWorkingHours |= policy->flags.blockOtherHTTPSWorkingHours;

        } else {

            combi->flags.blockHTTPSWorkingHours |= policy->flags.blockHTTPSNonWorkingHours;

            combi->flags.blockOtherWorkingHours |= policy->flags.blockOtherNonWorkingHours;

            combi->flags.blockOtherHTTPSWorkingHours |= policy->flags.blockOtherHTTPSNonWorkingHours;

        }

        combi->currentCategoryMask &= policy->currentCategoryMask;

        combi->custom_currentCategoryMask &= policy->custom_currentCategoryMask;

        if ( !combi->flags.mbThreshold || !policy->flags.mbThreshold ){

            combi->flags.mbThreshold += policy->flags.mbThreshold;

        } 
        else {

            combi->flags.mbThreshold = std::min( combi->flags.mbThreshold, policy->flags.mbThreshold );
        }

    }

}

//------------------------------------------------------------------------------

constexpr const char IFEB_T1[] =  "Blocked File Extension (";

//TODO: ciaran : Transform --> inline void doTestFileType( bool b_type, t_ttn_ext_categories ftype,char * a_out_ )

#define TEST_FILE_TYPE_(a_blocked_type_,a_ftype_,a_flag_)                           \
if ( (a_blocked_type_) &&                                                           \
     (out_=::fileExtensionBlocked(ext_.ptr_,ext_.sz_,(a_ftype_),greedy_search)) &&  \
     (reason_.minor.category |= (a_flag_) ) && (blocked = true) ) break

bool TaPE::is_file_extension_blocked(   const POLICY & combi_,
                                        const TaTag & ttag_     ) {
    /*
    * Check for blocked file extensions
    * REASON: MAJ_REASON_FILE_TYPE
    */

    const cfg::TCFGInfo & cfg_ = this->ttncfg_;

    const bool greedy_search = cfg_.fext_greedy_match;

    const uint_fast64_t mmc = cfg_.fext_max_match_count;

    t_strptr * const extmap = this->ext_map_;

    if ( mmc && extmap ){

        const POLICY_FLAGS & cf_ = combi_.flags;

        auto & reason_ = const_cast< BlockReason & >( ttag_.identity.eph.reason );

        auto & hstat_ = const_cast< TaTag::s_http_status_ & >( ttag_.http );

        zm( extmap, sizeof( t_strptr ) * mmc );

        size_t ctx{};

        if(     ttag_.clean_uri_sz                                              && 

                ttag_.clean_uri[0]                                              && 

                (   cf_.blockAudioFiles                                         || 

                    cf_.blockVideoFiles                                         ||

                    cf_.blockExeFiles                                           ||

                    cf_.blockImageFiles                                         ||

                    cf_.blockTextFiles                                          ||

                    cf_.blockArchiveFiles                                       ||

                    cf_.blockUserDefinedFiles   )                               && 

                ( ctx = ::map_extentions_from_url(  ttag_.clean_uri,
                                                    ttag_.clean_uri_sz,
                                                    extmap,
                                                    mmc                 ) )     && 

                ctx <= mmc                                                          ){


                const char * out_{};

                bool blocked{};

                reason_.major = MAJ_REASON_FILE_TYPE;

                hstat_.status_code = scForbidden;

                { /* locking scope */ 

                    /*
                     *  The thread safety detector is unable to trace lock aliases
                     *  hence the scoped guard is the only supported pattern
                     *  for the pthread wrapper ( rd_scoped_wrapper_t )
                     *  no std::lock_guard or deferred locks
                     */
                    rd_scoped_wrapper_t fext_wrp{sFileExtensionLock};

                    for ( uint_fast64_t i=0 ; i<mmc; i++ ){

                        auto & ext_ = extmap[i];

                        TEST_FILE_TYPE_(    cf_.blockAudioFiles,
                                            t_ttn_ext_categories::ttn_ext_aud,
                                            MIN_REASON_CAT_AUDIO                );

                        TEST_FILE_TYPE_(    cf_.blockVideoFiles,
                                            t_ttn_ext_categories::ttn_ext_vid,
                                            MIN_REASON_CAT_VIDEO                );

                        TEST_FILE_TYPE_(    cf_.blockExeFiles,
                                            t_ttn_ext_categories::ttn_ext_exe,
                                            MIN_REASON_CAT_EXE                  );

                        TEST_FILE_TYPE_(    cf_.blockImageFiles,
                                            t_ttn_ext_categories::ttn_ext_img,
                                            MIN_REASON_CAT_IMAGE                );

                        TEST_FILE_TYPE_(    cf_.blockTextFiles,
                                            t_ttn_ext_categories::ttn_ext_txt,
                                            MIN_REASON_CAT_TEXT                 );

                        TEST_FILE_TYPE_(    cf_.blockArchiveFiles,
                                            t_ttn_ext_categories::ttn_ext_arc,
                                            MIN_REASON_CAT_ARCHIVE              );

                        TEST_FILE_TYPE_(    cf_.blockUserDefinedFiles,
                                            t_ttn_ext_categories::ttn_ext_usr,
                                            MIN_REASON_CAT_USER                 );

                    }

                }

                if ( blocked && out_ ){

                    const size_t l_ = strlen(out_);

                    #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
                    // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                        hstat_.status_msg.reserve(l_+sizeof(IFEB_T1));
                    #endif

                    hstat_.status_msg = IFEB_T1;

                    hstat_.status_msg += std::string{out_,l_};

                    hstat_.status_msg += ")";

                    return (true);

                }

        }

    }

    return (false);
}

//------------------------------------------------------------------------------   

constexpr const char IRB_MSG1_[]    ="HTTPS disallowed.";
constexpr const char IRB_MSG3_[]    ="Your internet access rights have been revoked.";
constexpr const char IRB_MSG4_[]    ="All sites blocked";
constexpr const char IRB_MSG5_0_[]  ="Download limit (";
constexpr const char IRB_MSG5_1_[]  ="MB) exceeded.";
constexpr const char IRB_MSG6_[]    ="URLs may not specify the host by IP address";
constexpr const char IRB_MSG7_[]    ="URL content filters applied - banned keyword(";
constexpr const char IRB_MSG8_0_[]  ="URL content filters applied - score = ";
constexpr const char IRB_MSG8_1_[]  =" (keywords:";
constexpr const char IRB_MSG9_[]    ="Prohibited - Unclassified Site";
constexpr const char IRB_MSG10_[]   ="Prohibited - Unclassified HTTPS Site";
constexpr const char IRB_MSG11_[]   ="Prohibited by URL database (";


bool TaPE::is_request_blocked( IHRequest & rq_ )
{

    const TaTag & ttag_ = rq_.ttag;

    const auto & eph_ = ttag_.identity.eph;

    const POLICY & combi_ = eph_.combined_policy;

    const POLICY_FLAGS & cf_=combi_.flags;

    auto & reason_ = const_cast< BlockReason & >( eph_.reason );

    auto & hstat_  = const_cast< TaTag::s_http_status_ & >( ttag_.http );

    reason_.major = MAJ_REASON_UNKNOWN;

    if ( !cf_.filterEnabled ) {

        return false;
    }

    if ( cf_.sinBin ) {

        //Is this group set as the sin bin ?
        //REASON: MAJ_REASON_SIN_BIN (1-st occurence)
        reason_.major = MAJ_REASON_SIN_BIN;
        hstat_.status_msg = IRB_MSG3_;
        hstat_.status_code = scForbidden;
        return true;
    }

    if ( cf_.blockAll ) {

        //Is this group set as the sin bin ?
        //REASON: MAJ_REASON_SIN_BIN (1-st occurence)
        reason_.major = MAJ_REASON_URL_BLOCK_ALL;
        hstat_.status_msg = IRB_MSG4_;
        hstat_.status_code = scForbidden;
        return true;
    }

    if (    (  (    cf_.inWorkingDay                        &&

                    cf_.blockHTTPSWorkingHours  )           ||

                (   !cf_.inWorkingDay                       &&

                    cf_.blockHTTPSNonWorkingHours   )   )   &&
 
            PROTO_HTTPS==rq_.get_protocol()                     ) {

        // block https sites
        reason_.major = MAJ_REASON_HTTPS_BLOCKED;
        hstat_.status_msg = IRB_MSG1_;
        hstat_.status_code = scForbidden;
        return true;
    }

    //if this request comes from anonymous user we DO NOT do BW Control! - BTW WHY ????

    constexpr size_t mul_{1024 * 1024};

    if (    ttag_.user_found()                                                          &&

            cf_.mbThreshold>0                                                           &&

            !cf_.logOnlyGroupName                                                       &&

            eph_.user->downloaded_byte > static_cast<size_t>( cf_.mbThreshold * mul_ )      ) {

        std::string & msg_ = hstat_.status_msg;
        msg_.reserve(32+(sizeof(IRB_MSG5_0_)+sizeof(IRB_MSG5_1_)));
        msg_ += IRB_MSG5_0_;
        msg_ += tools::functors::tos{cf_.mbThreshold};
        msg_ += IRB_MSG5_1_;
        hstat_.status_code = scForbidden;
        reason_.major = MAJ_REASON_DOWNLIMIT_BLOCKED;
        return (true);

    }

   if ( ! ( ttag_.clean_uri_sz && ttag_.clean_uri[0] ) ) {

      titax_log(  LOG_ERROR,
                  "ASSERT :: %s:%d failed - dying!\n",
                  __func__,
                  __LINE__                               );
      exit(-1);
   }

    if ( this->is_file_extension_blocked( combi_,ttag_ ) ) {

        return true;
    }

    //restore default state;
    hstat_.status_msg.clear();

    hstat_.status_code = scOkay;

    reason_.major = MAJ_REASON_UNKNOWN;

    if (    cf_.blockIPAddressURLs  &&

            rq_.is_host_numeric()       ) {

        //Blocking by specified IP address
        //REASON: MAJ_REASON_IP_ADDR
        reason_.major = MAJ_REASON_IP_ADDR;
        hstat_.status_msg = IRB_MSG6_;
        hstat_.status_code = scForbidden;
        return true;
    }

    if (    cf_.urlKeywordEnabled   &&

            ttag_.clean_uri_sz      &&

            ttag_.clean_uri[0]          ) {

        //No special cases, so check the user list first as any matching
        //entry here overrides any in the PD supplied list
        int blocked_outright{};

        zm( blocked_keywords_,sizeof( blocked_keywords_ ) );

        ssize_t score = ::scoreDocument(    ttag_.clean_uri,
                                            ttag_.clean_uri_sz,
                                            &blocked_outright,
                                            blocked_keywords_,
                                            sizeof( blocked_keywords_ ) );

        if ( INVALID_ == score ) {

            ::titax_log(LOG_ERROR, "[scoreDocument failed (-1) set to zero \n");
            score=0;
        }

        if ( ( score >= static_cast<ssize_t>( cf_.urlThreshold ) ) || blocked_outright ) {

            if( blocked_outright ) {

                // REASON: MAJ_REASON_URL_KEYWORD
#if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
                std::string & msg_ = hstat_.status_msg;
                msg_.reserve(sizeof(blocked_keywords_)+sizeof(IRB_MSG7_));
                msg_ += IRB_MSG7_;
                msg_ += blocked_keywords_;
                msg_ += ')';
#endif
                hstat_.status_code = scForbidden;
                reason_.major = MAJ_REASON_URL_KEYWORD;
                return true;
            }

            //REASON: MAJ_REASON_URL_CONTENT
#if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
            std::string & msg_ = hstat_.status_msg;
            msg_.reserve(32+sizeof(blocked_keywords_)+sizeof(IRB_MSG8_0_)+sizeof(IRB_MSG8_1_));
            msg_ += IRB_MSG8_0_;
            msg_ += tools::functors::tos{score};
            msg_ += IRB_MSG8_1_;
            msg_ += blocked_keywords_;
            msg_ += ')';
#endif

            hstat_.status_code = scForbidden;

            reason_.major = MAJ_REASON_URL_KEYWORD;

            return true;
        }
    }

    const t_category CCAT{ ttag_.category_get() };

    if (    (   (   cf_.inWorkingDay                        && 

                    cf_.blockOtherWorkingHours  )           ||
 
                (   !cf_.inWorkingDay                       &&
 
                    cf_.blockOtherNonWorkingHours   )   )   &&

            !CCAT                                               ) {

        //REASON: MAJ_REASON_UNCLASS_SITE
        reason_.major = MAJ_REASON_UNCLASS_SITE;
        hstat_.status_msg = IRB_MSG9_;
        hstat_.status_code = scForbidden;
        return true;
    }

    if (    (   (   cf_.inWorkingDay                            &&

                    cf_.blockOtherHTTPSWorkingHours )           ||

                (   !cf_.inWorkingDay                           && 

                    cf_.blockOtherHTTPSNonWorkingHours  )   )   &&

            PROTO_HTTPS==rq_.get_protocol()                     &&

            !CCAT                                                   ) {

        //REASON: MAJ_REASON_UNCLASS_SITE
        reason_.major = MAJ_REASON_UNCLASS_HTTPS_SITE;
        hstat_.status_msg = IRB_MSG10_;
        hstat_.status_code = scForbidden;
        return true;
    }

    // Checking for unclassified site.
    if ( !CCAT ) {

        return false;
    }

    const t_category R1{    (   CCAT &  (   !ttag_.identity.eph.control.categoryE   ?
                                            combi_.currentCategoryMask              :
                                            combi_.custom_currentCategoryMask           )   )   };

    // Generate the reason information - the category which blocked us
    const t_category R2{ ( R1 ^ CCAT ) };

    // I added this code to return true when there's no flag which indicate
    // this url is in blocked category.
    if ( R1 == CCAT ) {

        // Not blocked at all.
        return (false);
    }

    /*
    * REASON: MAJ_REASON_SYSTEM_BLOCKED
    */
    this->category_str_[0] = 0;

    if ( ttag_.identity.eph.control.categoryE ) {

        custom_createCategoryString(    R2,
                                        this->category_str_,
                                        sizeof(this->category_str_) );

    }

    if ( !ttag_.identity.eph.control.categoryE ) {

        createCategoryString(   R2,
                                this->category_str_,
                                sizeof(this->category_str_) );

    }

    #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 
    // remove this "swiss-cheese" macro when we finally start building only on the FB11+

    std::string & msg_ = hstat_.status_msg;

    msg_.reserve(sizeof(category_str_)+sizeof(IRB_MSG11_)+1);

    msg_ += IRB_MSG11_;

    msg_ += category_str_;

    msg_ += ')';

    #endif

    hstat_.status_code = scForbidden;

    reason_.major = (   ! eph_.control.categoryE    ?

                        MAJ_REASON_SYSTEM_BLOCKED   :

                        MAJ_REASON_USER_BLOCKED         );

    reason_.minor.category = R2;

    reason_.aux.worktime = static_cast<uint32>(cf_.inWorkingDay);

    return true; //blocked

}

//------------------------------------------------------------------------------
//this method is NOT REENTRANT
//it will not clear the previous state & the request won't be assessed
using eff_elems_t = struct eff_elems_t{
    size_t                  i_;
    const size_t            max_;
    int                     (&policies_)[MAX_TITAX_GROUP_POLICY];
    globals::strings_t      & notifications_;
    POLICY                  * policy_;
    const bool              lrestrictive_;
};

using dis_elems_t = struct dis_elems_t {
    size_t                 i_;
    const size_t           max_;
    int                    (&groups_)[MAX_TITAX_GROUP_POLICY];
    globals::strings_t     & combined_group_names_;
    GROUP                  * grp_;
};

urldb_simple_stats_t TaPE::categorize( IHRequest & rq_ ) noexcept
{
    /* configure once */

    static char rbuf[ URLDB_TMP_R_BUF_MAX + 2 ] = {};//replace with a member vector

    static int urldbfd = INVALID_;

    t_txip_socket_ex conn = { .port = 18882,

                              .op_so_stream = true,

                              .op_so_reuse_addr = true,

                              .op_so_nosigpipe = true,

                              .op_io_no_block = true,

                              .op_connect_no_block=true,

                              .connect_timeout.tv_usec=1000,

                              .ip = "127.0.0.1"          };

    urldb_call_t urldbcall = {   .out={ .buf = rbuf, .bsz = URLDB_TMP_R_BUF_MAX },

                                 .urlsvr = { .conn = &conn, .fd = &urldbfd },

                                 .max_try = 4                                       };

    /* configure per request */
    TaTag & ttag_ = rq_.ttag;

    urldbcall.in = {    .buf=ttag_.clean_uri,

                        .bsz=ttag_.clean_uri_sz };

    urldbcall.out.ac = &ttag_.identity.eph.control;

    urldbcall.debug = this->ttncfg_.debug;

    std::string err_msg{ UNKNOWN_ };

    using namespace titan_v3::tools::eop;

    t_urldb_rc udbstat{ urldb_rc_er_cal };

    try{

        /* query urldb */
        udbstat = urldb_send_request( &urldbcall );

        switch ( udbstat ) {

            default : {

                TXDEBLOG(
                    titax_log(  LOG_NOTICE,
                                "category %llu for [ %s ]\n",
                                ttag_.category_get(),
                                urldbcall.in.buf                );

                    )

                return urldb_simple_stats_t::ok;
            }

            case t_urldb_rc::urldb_rc_er_dec :
            case t_urldb_rc::urldb_rc_er_cal :
            case t_urldb_rc::urldb_rc_er_unc : {

                TXDEBLOG(
                    titax_log(  LOG_NOTICE,
                                "category UNKNOWN for [ %s ] \n",
                                urldbcall.in.buf                    );
                        )

                return urldb_simple_stats_t::unknown;
            }

            case t_urldb_rc::urldb_rc_er_opn :
            case t_urldb_rc::urldb_rc_er_rcv :
            case t_urldb_rc::urldb_rc_er_snd :
            case t_urldb_rc::urldb_rc_er_udb : throw errors::urldb_connection_error();

        } /* switch */

    } catch ( const std::exception & e ) {

            err_msg = e.what();

    } catch ( ... ) {

    }

    tools::functors::urldb_rc_map urldb_rc_map;

    titax_log(  LOG_WARNING,
                "Categorization failed for [ %s ] code %s | error %s\n",
                urldb_rc_map( udbstat ).c_str(),
                urldbcall.in.buf,
                err_msg.c_str()                                         );

    return urldb_simple_stats_t::error;
}

static 
void acquire_categories( TaTag & ttag_ ) noexcept TSA_CAP_TR_RQ(sCatLock, custom_sCatLock)
{
    auto cat_ = ttag_.category_get();

    auto & eph_ = ttag_.identity.eph;

    CATEGORY * cat_table{};

    size_t i_{};

    if ( cat_ && ( cat_table = getCatTable() ) ) {

        /* Get the titax defined categories */

        const CATEGORY * ct_{ getcustomCatTable() };

        if ( !ct_ || !eph_.control.categoryE ){

            ct_ = cat_table;
        }

        if ( ct_ ) {

            try{

                tools::getcategories( cat_, [ &eph_, &i_, ct_ ]( const size_t n_ ) {

                                            eph_.category_names.emplace_back( ct_[ n_ ].name );

                                            eph_.category_numbers.emplace_back( tools::functors::tos{ n_ } );

                                            ++i_;

                                    });

            } catch ( const std::exception & e ){

                titax_log(  LOG_WARNING,
                            "acquiring categories %s\n",
                            e.what()                    );

                cat_ = i_ = 0;

            } catch ( ... ){

                titax_log(  LOG_WARNING,
                            "acquiring categories failed!!! \n" );

                cat_ = i_ = 0;

            }
        }
    }

    if( !cat_ && !i_ ){

        eph_.category_names.emplace_back("Unclassified");

        eph_.category_numbers.emplace_back("0"); //??
    }

}


bool TaPE::fetch_missing_info( IHRequest & rq_ )
{

    TaTag & ttag_ = rq_.ttag;

    auto & eph_ = ttag_.identity.eph;

    const cfg::TCFGInfo & cfg_ = this->ttncfg_;

    auto canonical = (  this->app_mode == app_mode_t::cloud ?

                        rq_.get_host()                      :

                        rq_.get_canonical()                    );

    if ( !canonical.size() ){

        titax_log(LOG_ERROR, ">>> canonical is empty \n");

        return false;

    }

    ttag_.clean_uri_sz = ::cleanup_url(   canonical.c_str(),

                                          canonical.length(),

                                          ttag_.clean_uri,

                                          sizeof( ttag_.clean_uri ),

                                          true                       );

    if ( !ttag_.clean_uri_sz || !ttag_.clean_uri[0] ) {

      ttag_.clean_uri_sz = 0 ;
      eph_.uri = std::move(canonical);
      titax_log(LOG_ERROR,  "%s :: clean_uri is empty for [%s] \n", __func__, eph_.uri.c_str() );
      return false;
    }


    ttag_.clean_uri[ttag_.clean_uri_sz] = 0;

    ttag_.category_clear();

    const urldb_simple_stats_t cat_status{  ! cfg_.disable_urldb            ?

                                            categorize( rq_ )               :

                                            urldb_simple_stats_t::disabled      };

     if (   urldb_simple_stats_t::error == cat_status    ||

            urldb_simple_stats_t::disabled == cat_status    ) {

        IHRequestFlags & flags = rq_.get_flags();

        if (    ! cfg_.least_restrictive    &&

                ! flags.ttn_explicitly_allowed      &&

                ! flags.ttn_request_is_blocked         ) {

            ttag_.http.status_msg = (   urldb_simple_stats_t::disabled != cat_status ?

                                        "Url Database is temporarily unavailable"    :

                                        "Unknown category"                              );

            eph_.reason.major = MAJ_REASON_SYSTEM_BLOCKED; 
            ttag_.http.status_code = scForbidden;
            flags.ttn_request_is_blocked = true;
            flags.ttn_do_not_check = true;
            flags.ttn_has_been_processed = true;
        }

        if ( urldb_simple_stats_t::disabled == cat_status ) {

            TXDEBLOG(
                titax_log(  LOG_NOTICE,
                          "Categorisation is disabled by the configuration\n" );
                 )
        }
    }

    { /* locking scope */

        sh_scoped_lock_t cat_locks{ sCatLock, custom_sCatLock };

        acquire_categories( ttag_ );
    }

    // This is a place to check image search engines URL
    // and rewrite URL path according to user's group SafeSearch policy options
    SAFESEARCH_SETTING safe_search = SAFESEARCH_OFF; // SafeSearch defaults to OFF

    unsigned long sse_pl_onoff = SSE_ALL_ON; // All engines as safe search

    unsigned long sse_pl_moderate{};

    // Init combined_policy.
    ttag_.combined_policy_clear();

    const bool safesearch_disabled = titax_conf_get_safesearch_disabled(true);

    { /* locking scope */

        mx_scoped_wrapper_t grp_wrp{sGroupMutex};

        auto & u_policy_info = eph_.user->policy_info;

        if (    (   !eph_.user->parent_id                           ||

                    u_policy_info.inherited   )                     && 

                locations::UNASSIGNED != eph_.location.policy_id        ){

            /* lets select an alternative policy for this eph */
            u_policy_info.policies.ids[0] = eph_.location.policy_id;
            u_policy_info.policies.length = 1;

            u_policy_info.groups.ids[0] = 0;
            u_policy_info.groups.length = 0;


            /* questions : 
             * What if, a given policy is invalid ? 
             * What if, it is a WT machine where the policies, currently, are associated only via groups.
             * Then in the history we won't be able to show any groups, therefore, the customer won't 
             * be able to check which policy is actually affecting such request.   
             */
        }
        else if ( u_policy_info.policies.length == 0 &&
                  ttag_.identity.parent.id > 0 && 
                  ttag_.identity.parent.policy_info.policies.length > 0 ) {

           u_policy_info = ttag_.identity.parent.policy_info;
        }

        /* protective code 
         *
         * detects the emergency situation where for what ever reason 
         * the policies.length or groups.length exceeds the allowed limits
         */

        if ( u_policy_info.policies.length <= GROUP_POLICY_LIMIT ) {

           eff_elems_t l_eff = {   .max_             = u_policy_info.policies.length,
                                   .policies_        = u_policy_info.policies.ids,
                                   .notifications_   = eph_.notifications,
                                   .lrestrictive_    = ttncfg.least_restrictive  };

           for ( ; l_eff.i_ < l_eff.max_; ++l_eff.i_ ) {

              l_eff.policy_ = nullptr;

              if (    getPolicy_without_lock( l_eff.policies_[ l_eff.i_ ], &l_eff.policy_ )   &&

                       l_eff.policy_                                                               ) {

                 if ( l_eff.policy_->emailNotify && l_eff.policy_->emailNotify[0] ) {

                    l_eff.notifications_.push_back( l_eff.policy_->emailNotify );
                 }

                 this->combine_policies( l_eff.i_, rq_, l_eff.policy_, l_eff.lrestrictive_ );

                 if (  ! safesearch_disabled                               &&

                       l_eff.policy_->flags.filterEnabled                  &&

                       safe_search != SAFESEARCH_ON                        &&

                       SAFESEARCH_OFF != l_eff.policy_->flags.safeSearch       ) {

                    if ( SAFESEARCH_ON == l_eff.policy_->flags.safeSearch ) {

                       safe_search = SAFESEARCH_ON;

                       sse_pl_onoff = SSE_ALL_ON;

                       sse_pl_moderate = 0;
                    }

                    if ( SAFESEARCH_CUSTOM == l_eff.policy_->flags.safeSearch ) {

                       safe_search = SAFESEARCH_CUSTOM;

                       sse_pl_onoff &= l_eff.policy_->safeSearchFlags.SSE_OnOff;

                       sse_pl_moderate |= l_eff.policy_->safeSearchFlags.SSE_Moderate;

                    }
                 }
              }
              else {

                     if (eph_.user) {

                        titax_log(  LOG_ERROR,
                                 "TCGuard :: %s :: Unable to get the policy by id (%d) :: "\
                                 "removing the user [%zu|%s] from the cache as invalid\n",
                                 __func__,
                                 l_eff.policies_[ l_eff.i_ ],
                                 eph_.user->id,
                                 eph_.user->name );

                        users_cache->removeUserById(eph_.user->id);
                     }
                     else {

                        titax_log(  LOG_WARNING,
                                    "TCGuard :: %s :: Unable to get the policy by id (%d)\n",
                                    __func__,
                                    l_eff.policies_[ l_eff.i_ ] );
                     }
                     return false;
              }

           } /* loop */

           /* display groups */
            if ( u_policy_info.groups.length > GROUP_POLICY_LIMIT ) {

               titax_log(  LOG_ERR,
                           "TCGuard :: %s :: The count of groups (%zu) exceeds the allowed "\
                           "limit (%zu), so the count of effective policies is used instead (%zu)\n",
                           __func__,
                           u_policy_info.groups.length,
                           GROUP_POLICY_LIMIT,
                           u_policy_info.policies.length                                                            );

               u_policy_info.groups.length = u_policy_info.policies.length;
            }

            dis_elems_t l_dis = {   .max_                   = u_policy_info.groups.length, 
                                    .groups_                = u_policy_info.groups.ids,
                                    .combined_group_names_  = eph_.combined_group_names   };

            for ( ; l_dis.i_ < l_dis.max_; ++l_dis.i_ ) {

               l_dis.grp_ = nullptr;

               if (  getGroup_without_lock( l_dis.groups_[l_dis.i_], &l_dis.grp_ )   &&

                     l_dis.grp_                                                      &&

                     l_dis.grp_->name[0]                                                 ) {

                     if ( !cfg_.use_gids ) {

                        l_dis.combined_group_names_.push_back( l_dis.grp_->name );
                     } 
                     else {

                        /*Use Group Ids*/
                        l_dis.combined_group_names_.push_back( tools::functors::tos{ l_dis.grp_->groupNumber+1 } );
                     }
               } 
               else {

                     if (eph_.user) {

                        titax_log(  LOG_ERROR,
                                 "TCGuard :: %s :: Unable to get the group by id (%d) :: "\
                                 "removing the user [%zu|%s] from the cache as invalid\n",
                                 __func__,
                                 l_dis.groups_[l_dis.i_],
                                 eph_.user->id,
                                 eph_.user->name );

                        users_cache->removeUserById(eph_.user->id);
                     }
                     else {

                         titax_log(  LOG_ERROR,
                                     "TCGuard :: %s :: Unable to get the group by id (%d)\n",
                                     __func__,
                                     l_dis.groups_[l_dis.i_] );

                     }
                     return false;
               }
            }
        }  /* effective policies */
        else {

           titax_log(  LOG_ERR,
                       "TCGuard :: %s :: The count of effective policies (%zu) "
                       "exceeds the allowed limit (%d), "
                       "the default policy is applied and displayed!\n",
                       __func__,
                       u_policy_info.policies.length,
                       MAX_TITAX_GROUP_POLICY );
        }

        if ( eph_.combined_policy.flags.logOnlyGroupName ) {

            ttag_.make_child_anonymous();
        }

    } /* locking scope */

    std::string host = rq_.get_host();

    if ( !host.empty() && !ttncfg.restrict_access_domains_str.empty() ) {

        if ( !http_tools::microsoft_enforce_restrict_access( rq_, host, ttncfg ) ) {

            titax_log(  LOG_ERR,
                        "%s:%d:failed to add headers to restrict the access\n",
                        __FILE__,
                        __LINE__                                             );

            /* pass thru */
        }
    }

    // try to modify the URL if safe search is on
    if ( SAFESEARCH_OFF != safe_search) {

        if ( app_mode_t::cloud == app_mode ) {

            if ( !host.empty() ){

                static char new_host[SQUID_MAX_URL + 1]; //use member vector

                new_host[0] = 0;

                redirections_get_redi_host( host.c_str(),
                                            host.size(),
                                            new_host,
                                            sizeof(new_host)    );

                if ( new_host[0] != 0 ) {

                    rq_.ttag.identity.eph.redirection_host = new_host;
                }
            }
        } 
        else {

            try{

                http_tools::modify_safe_search_url( rq_,
                                                    sse_pl_onoff,
                                                    sse_pl_moderate );

            } catch( const std::exception & e_ ){

                titax_log(LOG_ERR, "safe search error :%s\n", e_.what() );

            }
        }
    }

    #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )

    // remove this "swiss-cheese" macro when we finally start building only on the FB11+
    ttag_.identity.eph.uri = rq_.get_canonical();

    #endif

    return true; //fetched
}
//------------------------------------------------------------------------------
//THIS METHOD IS REENTRANT
bool TaPE::is_request_allowed( IHRequest & rq_ ) {
//it will CLEAR the previous state & the request WILL BE assessed.
    using namespace titan_v3::tools::eop;
// only if protocol is not PROTO_DNS
    TaTag & ttag=rq_.ttag;

    IHRequestFlags & flags = rq_.get_flags();

    // drop google preamble if its a google cache request
    //temporarily removed
    //this->_remove_cache_preambles();
    if (!this->fetch_missing_info( rq_ )){

        ttag.identity.eph.reason.major=MAJ_REASON_UNKNOWN;

        #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 
            ttag.http.status_msg="(7) Blocked from proxy";
        #endif

        ttag.http.status_code=scForbidden;

        flags.ttn_request_is_blocked=true;

        flags.ttn_has_been_processed=true;

        return false;

    }

    if ( flags.ttn_has_been_processed && flags.ttn_do_not_check && flags.ttn_request_is_blocked ) {

        /* block the request if the fetch_missing_info decided so. */
        return false;
    }

    flags.ttn_log_not_block = ttag.identity.eph.combined_policy.flags.dontBlockOnKeywords;

    //continue processing - check  w/b lists
    const t_wbl_actions r_{ rq_.combined_wbl_actions };

    if ( t_wbl_actions::wba_none != r_ ){

        if ( as_bool( r_ & t_wbl_actions::wba_bypassfilters ) ){

            flags.ttn_has_been_processed=true;

            if ( !as_bool(r_ & t_wbl_actions::wba_log) ){

                flags.ttn_has_been_logged=true;

            }

            return true;

        }

        if ( as_bool( r_ & t_wbl_actions::wba_block ) ){

            ttag.identity.eph.reason.major=MAJ_REASON_ADMIN_BLOCKED;

            #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 
            // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                ttag.http.status_msg="(6) Blocked from proxy ";
            #endif

            ttag.http.status_code=scForbidden;

            flags.ttn_request_is_blocked=true;

            flags.ttn_has_been_processed=true;

            if ( !as_bool(r_ & t_wbl_actions::wba_log) ){

                flags.ttn_has_been_logged=true;

            }

            return false;

        }

    }

    //continue processing - check sinBin
    if (    !flags.ttn_has_been_processed                   && 

            ttag.identity.eph.combined_policy.flags.sinBin      ){

        ttag.identity.eph.reason.major=MAJ_REASON_SIN_BIN;

        #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
        //continue processing - check
            ttag.http.status_msg="Your internet access rights have been revoked.";
        #endif

        ttag.http.status_code=scForbidden;

        flags.ttn_request_is_blocked=true;

        flags.ttn_has_been_processed=true;

        return false;

    }

    //continue processing - check
    if (    !flags.ttn_has_been_processed   &&
            this->is_request_blocked( rq_ )     ){

        flags.ttn_request_is_blocked=true;

        flags.ttn_has_been_processed=true;

        return false;

    }

    flags.ttn_has_been_processed=true;

    return true; //allowed

}
//------------------------------------------------------------------------------ 

constexpr const char LOG_ERR_MSG1[] = "TaPE couldn't log this request::[ ttn_has_been_processed:";

constexpr const char LOG_ERR_MSG3[] = "true";

constexpr const char LOG_ERR_MSG4[] = "false";

constexpr const char LOG_ERR_MSG5[] = " | ttn_has_been_logged:";

constexpr const char LOG_ERR_MSG6[] = " | is_request_valid:";

constexpr const char LOG_ERR_MSG7[] = " | uri: {";

constexpr const char LOG_ERR_MSG8[] = "} ]\n";

void TaPE::log( IHRequest & rq_,
                ICacheInfo & get_   ){

    //TODO: DO NOT USE this->current_rq_

        IHRequestFlags & flags = rq_.get_flags();

        TaTag & ttag = rq_.ttag;

        if (    this->ttncfg.log_cfg.type       &&
                flags.ttn_has_been_processed    &&
                !flags.ttn_has_been_logged      &&
                ttag.identity.eph.uri.length()  &&
                rq_.is_request_valid()              ) {

                if ( !this->open_logger() ) {

                    TXDEBLOG(titax_log(LOG_NOTICE, "TaPE couldn't open  connection to the logger \n"));
                    flags.ttn_has_been_logged=true;
                    return;
                }

                auto & log = g_tx_log;

                if ( !log.lock() ) {

                    std::cout<<"TaPE couldn't lock the logger\n";
                    TXDEBLOG(titax_log(LOG_NOTICE, "TaPE couldn't lock the logger \n"));
                    flags.ttn_has_been_logged=true;
                    return;
                }

                log.clear();

                (void)((rq_.ttag.user_found() && (
                    ((
                        (ttag.identity.eph.user->id==ttag.identity.parent.id && ttag.identity.eph.user->name[0])
                        &&
                        ((log.uname=ttag.identity.eph.user->name).size() || true)
                    ) || (
                        (
                            (ttag.identity.parent.fullname[0])
                            &&
                            ((log.uname=ttag.identity.parent.fullname).size() || true)
                        ) || (
                            ((log.uname=ttag.identity.parent.name).size()||true)
                        )
                    ))
                    &&
                    ((log.parent_id=static_cast<ssize_t>(ttag.identity.parent.id)) || true)

                )) || (

                    (!ttag.identity.parent.invalid_user &&
                        (((ttag.identity.parent.fullname[0] && ((log.uname=ttag.identity.parent.fullname).size() || true)) || ((g_tx_log.uname=ttag.identity.parent.name).size())))
                        &&
                        ((log.parent_id=static_cast<ssize_t>(ttag.identity.parent.id))|| true)
                    ) || (
                        //for webtitan in case user is not found
                        (log.parent_id={INVALID_})
                        &&
                        ((log.uname=TITAX_ANON_DEFAULT_USER_NAME).size() || true)
                    )
                ));

                if ( ttag.identity.eph.cloud_key.size() ) {

                    log.cloud_key = std::move( ttag.identity.eph.cloud_key );
                }

                (void)(!ttag.identity.eph.user->invalid_user && 
                    !ttag.identity.eph.combined_policy.flags.logOnlyGroupName &&
                    ((/* WTC */ !ttag.identity.parent.default_user && (((ttag.dns_meta_data.iuid_valid && !ttag.identity.child.invalid_user) && (log.meta_uname=ttag.identity.child.name).c_str()) || ( (log.meta_uname="").c_str() /*send anonymous for WTC internal user*/)))
                    ||
                    (/* WT */ ((ttag.identity.eph.user->fullname[0] && ((log.meta_uname=ttag.identity.eph.user->fullname).size() || true)) || ((log.meta_uname=ttag.identity.eph.user->name).size() || true))))
                );

                if ( ttag.dns_meta_data.iip_valid && checks::is_nz( ttag.dns_meta_data.iip )  ) {

                    log.meta_internal_ip_addr = ttag.dns_meta_data.iip;
                } /* else don't send anything */


                /* {} warns against an implicit narrowing conversion - don't change it */
                if ( flags.ttn_request_is_blocked ) {

                    log.ip_addr = { rq_.get_client_addr() };

                    log.blocking_source = { ttag.identity.eph.reason.major };

                    log.reason = std::move( ttag.http.status_msg );

                    log.url = std::move( ttag.identity.eph.uri );

                    log.groups = std::move( ttag.identity.eph.combined_group_names );

                    if ( ttag.identity.eph.notifications.size() ) {

                        if ( log.blocking_source == MAJ_REASON_USER_BLOCKED ) {

                            if ( ( ttag.identity.eph.reason.minor.category & ttag.identity.eph.combined_policy.custom_notifyCategoryMask) != 0   ) {

                                log.notifications = std::move( ttag.identity.eph.notifications ) ;

                            }

                        } 
                        else if ( log.blocking_source == MAJ_REASON_SYSTEM_BLOCKED ) {

                            if ( ( ttag.identity.eph.reason.minor.category & ttag.identity.eph.combined_policy.notifyCategoryMask ) != 0 ) {

                                log.notifications = std::move( ttag.identity.eph.notifications );
                            }
                        } 
                        else if ( ( ttag.identity.eph.combined_policy.notifyFlags & ( 1 << log.blocking_source ) ) !=0 ){

                            log.notifications = std::move( ttag.identity.eph.notifications );
                        }
                    }

                    if ( ttag.category_get() ) {

                        log.categories = std::move( ttag.identity.eph.category_numbers );
                    }

                    if ( ttag.identity.eph.location.name.size() ) {

                        log.location += ttag.identity.eph.location.name;
                    }

                    flags.ttn_has_been_logged = true;

                }
                else {

                    ICacheInfo::t_cache cache{};

                    get_(&cache);

                    if ( cache.blocked ) {

                        flags.ttn_has_been_logged=true;
                        log.unlock();
                        return;
                    }

                    log.cached = { cache.cached };

                    log.ip_addr = { rq_.get_client_addr() };

                    log.duration = { cache.msec } ;

                    if ( !( log.object_size = { cache.replySize } ) ) {

                        log.object_size = { cache.objectSize };
                    }

                    const auto & reason_ = ttag.identity.eph.reason;

                    log.blocking_source = {	(   reason_.major == MAJ_REASON_BYPASSED        ||

                                                ttag.http.status_code != scOkay         )   ?

                                                reason_.major                               :

                                                LOGGER_REASON_ALLOWED                           };


                    log.reason = std::move( ttag.http.status_msg );
                    /* log.blocking_source == LOGGER_REASON_ALLOWED ? log.reason.clear() */

                    log.url = std::move( ttag.identity.eph.uri );

                    if ( ttag.identity.eph.location.name.size() ) {

                        log.location += ttag.identity.eph.location.name;
                    }

                    log.groups = std::move( ttag.identity.eph.combined_group_names );

                    if ( ttag.category_get() ) {

                        log.categories = std::move( ttag.identity.eph.category_numbers ); 
                    }

                    //faulty assumption that  download limits are available only for an authenticated and known users

                    if (    users_cache         &&

                            ttag.user_found()   &&

                            ttncfg.enable_auth  &&

                            ttag.identity.eph.combined_policy.flags.mbThreshold  ) {

                        users_cache->updateBandwidth(   ttag.identity.eph.user->id,
                                                        log.object_size             );
                    }
                }

                log.policy_name = ttag.identity.eph.combined_policy.name;

                switch (this->ttncfg.log_cfg.type){
                    case ot_file:{
                        log.tx_flog::log();
                    }break;
                    case ot_tcp:
                    case ot_uds:{
                        log.tx_slog::log();
                    }break;
                    default:break;
                }

                flags.ttn_has_been_logged = true;
                log.unlock();
                return;
        }

        TXDEBLOG(
            if (!flags.ttn_is_local_request){
                titan_v3::tools::functors::tos err_msg{};
                err_msg<<LOG_ERR_MSG1;
                err_msg<<(flags.ttn_has_been_processed?LOG_ERR_MSG3:LOG_ERR_MSG4);
                err_msg<<LOG_ERR_MSG5;
                err_msg<<(flags.ttn_has_been_logged?LOG_ERR_MSG3:LOG_ERR_MSG4);
                err_msg<<LOG_ERR_MSG6;
                err_msg<<(rq_.is_request_valid()?LOG_ERR_MSG3:LOG_ERR_MSG4);
                err_msg<<LOG_ERR_MSG7;
                err_msg<<ttag.identity.eph.uri;
                err_msg<<LOG_ERR_MSG8;
                std::cout<<err_msg;
                titax_log(LOG_NOTICE,"%s",err_msg.c_str());
            }
        )

}

#ifndef MATCHACL_RESULT_
    #define MATCHACL_RESULT_(a_val_) {do{flags.ttn_request_is_blocked=!static_cast<bool>(a_val_);return(a_val_);}while( false );}
#endif

request_state TaPE::matchACL(   IHRequest & ir,
                                IACLChecklist *const checklist_,
                                t_check_authentication_method * const checkauth_    ){


    //This skips cloud keys, because this is WebTitan (not Cloud).
    ir.ttag.block_action = block_actions::block;
    cfg::TCFGInfo & cfg_=this->ttncfg;
    if(!cfg_.lock_and_reload()){
        ::titax_log(LOG_WARNING,"TTNCFG:RELOAD:FAILED\n");
        return(request_state::allow);
    }
    IHRequestFlags & flags=ir.get_flags();
    TaTag & ttag=ir.ttag;
    std::string host=ir.get_host();
    TXDEBLOG(::titax_log(LOG_WARNING,"matchACL:[%s]\n",host.c_str());)
    if ( gflags.TXDEBUG_ ) {
        std::cout<<cfg_;
    }

    const auto & cidr_stat = cidr::factory::make_cidr( ir.get_client_addr() );

    if ( !cidr_stat.second ) {

        titax_log(  LOG_WARNING,
                    "%s:%d:: make make_cidr failed - access deny!\n",__func__,__LINE__ );

        flags.ttn_request_is_blocked=true;
        ttag.identity.eph.reason.major=MAJ_REASON_SYSTEM_BLOCKED;
        #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 
        // remove this "swiss-cheese" macro when we finally start building only on the FB11+
            ttag.http.status_msg="Unrecognized source of request";
        #endif
        ttag.http.status_code=scBadRequest;
        MATCHACL_RESULT_(request_state::deny)
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                LOCAL REQUEST
    ////////////////////////////////////////////////////////////////////////////////

    if (cfg_.is_request_local(host)){

        //do not log local requests
        flags.ttn_has_been_logged=flags.ttn_has_been_processed=flags.ttn_is_local_request=flags.ttn_do_not_check=true;
        //This is more for the WTC 
        const auto is_tserver = ir.is_target_server() ;

        if ( is_tserver ) {

            flags.ttn_client_dst_passthru=true;
        }

        ttag.identity.eph.uri=ir.get_canonical();

        if ( ir.get_port() == cfg_.proxy_port ){
            flags.ttn_request_is_blocked=true;
            ttag.identity.eph.reason.major=MAJ_REASON_SYSTEM_BLOCKED;
            #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 
            // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                ttag.http.status_msg="WT::INVALID REQUEST:1";
            #endif
            ttag.http.status_code=scBadRequest;
            MATCHACL_RESULT_(request_state::deny)
            assert( false && "ACLTitanAuth::match::failed:@c0");
        }

        flags.ttn_explicitly_allowed = true;

        if ( !cfg_.transparentproxy || !is_tserver) {

            MATCHACL_RESULT_(request_state::allow)
        }
        else {

            MATCHACL_RESULT_(request_state::deny)
        }


    }

    ////////////////////////////////////////////////////////////////////////////////
    //             REQUEST VALIDITY
    ////////////////////////////////////////////////////////////////////////////////

    if (!ir.is_request_valid()){

        if (    users_cache                                             &&  

                users_cache->load_default_info( ttag.identity.parent )      ) {

            ttag.identity.child= ttag.identity.parent;

        }

        if (!ir.is_request_valid()){
            ttag.identity.eph.uri=ir.get_canonical();
            ttag.identity.eph.reason.major=MAJ_REASON_SYSTEM_BLOCKED;
            #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
            // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                ttag.http.status_msg="WT::INVALID REQUEST:2";
            #endif
            ttag.http.status_code=scForbidden;
            flags.ttn_has_been_logged=flags.ttn_has_been_processed=true;
            MATCHACL_RESULT_(request_state::deny)
        }
        /***
        * In some rare cases we might end up here but it might not be a bug.
        * In two seen cases proxy crashed here (because of the assert) with requests
        * containing the NTLM AUTH Header (TT hash)
        * So for now this assert is disabled
        * assert( false && "ACLTitanAuth::match::failed:@c2");
        */
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                LICENCE
    ////////////////////////////////////////////////////////////////////////////////
    if (cfg_.disable_filteronreq ||  !cfg_.is_lic_valid()){
        flags.ttn_explicitly_allowed = true;
        MATCHACL_RESULT_(request_state::allow)
    }

    using uip_i_type=uniqips_type::input_type;
    using uip_r_type=uniqips_type::result_type;

    switch (this->uniqips[uip_i_type{ .ip=cidr_stat.first, .max=cfg_.license.max_ips}]){
        case uip_r_type::error:{
            // add debug print
            if (this->fetchIdentity( ir, search_identity_by::none, cidr_stat.first )){
                #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
                    // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                    ttag.identity.eph.uri=ir.get_canonical();
                    ttag.identity.eph.reason.major=MAJ_REASON_SYSTEM_BLOCKED;
                    ttag.http.status_msg="Maximum user number already reached";
                    ttag.http.status_code=scForbidden;
                #endif
                MATCHACL_RESULT_(request_state::deny)
            }
            assert( false && "ACLTitanAuth::match::failed:@c3");

        } break;
        case uip_r_type::added:
        //add print
        break;
        //found
        //unlimited
        default:break;
    }

    ////////////////////////////////////////////////////////////////////////////////
    //                W/B lists
    ////////////////////////////////////////////////////////////////////////////////

    using namespace titan_v3::tools::eop;

    t_wbl_actions r_=ir.check_global_wbl_actions();
    if ( t_wbl_actions::wba_none != r_){
        /*
        * a=wba_bypassauth
        * b=wba_bypassfilters
        * c=wba_block
        * -----------------------
        * | FLAGS     | RESULT_S |
        * |-----------|---------|
        * | a         |    1    |
        * | b         |    1    |
        * | c         |    0    |
        * | a & b & c |    1    | - b always override c
        * | a & b     |    1    |
        * | a & c     |    0    |
        * | b & c     |    1    | - b always override c
        * -----------------------
        *
        */

        if ( as_bool(r_ & t_wbl_actions::wba_bypassauth) && as_bool(r_ & t_wbl_actions::wba_bypassfilters) &&
            this->fetchIdentity(ir,search_identity_by::none,cidr_stat.first)) {

                if (!as_bool(r_ & t_wbl_actions::wba_log)) 
                    flags.ttn_do_not_check=flags.ttn_has_been_logged=true;

                flags.ttn_explicitly_allowed = true;
                MATCHACL_RESULT_(request_state::allow)
                assert( false && "ACLTitanAuth::match::failed:@c4");
        }

        if (as_bool(r_ & t_wbl_actions::wba_bypassauth) && as_bool(r_ & t_wbl_actions::wba_block) &&
            this->fetchIdentity(ir,search_identity_by::none,cidr_stat.first)){

                if (!as_bool(r_ & t_wbl_actions::wba_log))
                    flags.ttn_do_not_check=flags.ttn_has_been_logged=true;

                #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
                    // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                    ttag.identity.eph.uri=ir.get_canonical();
                    ttag.identity.eph.reason.major=MAJ_REASON_ADMIN_BLOCKED;
                    ttag.http.status_msg="(0) Blocked from proxy ";
                    ttag.http.status_code=scForbidden;
                #endif
                MATCHACL_RESULT_(request_state::deny)
                assert( false && "ACLTitanAuth::match::failed:@c5");
        }

        if (    as_bool( r_ & t_wbl_actions::wba_bypassauth )                       && 

                this->fetchIdentity( ir,search_identity_by::none,cidr_stat.first )  &&

                (   !checklist_                                                     ||

                    checklist_->Update(request_state::dunno,"Titan auth DUNNO/ALLOWED - bypass auth")   )   ) {

                if (!as_bool(r_ & t_wbl_actions::wba_log))
                    flags.ttn_has_been_logged=true;

                MATCHACL_RESULT_(request_state::dunno)
                assert( false && "ACLTitanAuth::match::failed:@c6");
        }

        if (as_bool(r_ & t_wbl_actions::wba_block) && !as_bool(r_ & t_wbl_actions::wba_log) &&
            this->fetchIdentity(ir,search_identity_by::none,cidr_stat.first)){

                if (!as_bool(r_ & t_wbl_actions::wba_log))
                    flags.ttn_do_not_check=flags.ttn_has_been_logged=true;

                #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
                // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                    ttag.identity.eph.uri=ir.get_canonical();
                #endif 
                if (ttag.identity.eph.uri.size()){
                    #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) ) 
                        // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                        ttag.identity.eph.reason.major=MAJ_REASON_ADMIN_BLOCKED;
                        ttag.http.status_msg="(1) Blocked from proxy ";
                        ttag.http.status_code=scForbidden;
                    #endif
                    MATCHACL_RESULT_(request_state::deny)
                }
                assert( false && "ACLTitanAuth::match::failed:@c7");

        }
    }

    ir.processing_step = 1;
    return matchACLCheckAuth(ir, checklist_, checkauth_);
}

////////////////////////////////////////////////////////////////////////////////
//                AUTH CACHE
////////////////////////////////////////////////////////////////////////////////
request_state TaPE::matchACLCheckAuth(  IHRequest & ir,
                                        IACLChecklist *const  checklist_,
                                        t_check_authentication_method * const checkauth_    ) {

    IHRequestFlags & flags=ir.get_flags();

    TaTag & ttag=ir.ttag;

    const auto & cidr_stat = cidr::factory::make_cidr( ir.get_client_addr() );

    if ( !cidr_stat.second )  {

        titax_log(  LOG_WARNING,
                    "%s:%d:: make make_cidr failed - access deny!\n",__func__,__LINE__ );

        flags.ttn_do_not_check=flags.ttn_has_been_logged=true;

        #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )

            // remove this "swiss-cheese" macro when we finally start building only on the FB11+
            ttag.identity.eph.reason.major=MAJ_REASON_SYSTEM_BLOCKED;

            ttag.http.status_msg="Unrecognized source of request";

            ttag.http.status_code=scBadRequest;

        #endif

        MATCHACL_RESULT_(request_state::deny)
    }

    t_wbl_actions r_ = ir.check_global_wbl_actions();

    request_state answer=request_state::allow;

    //TODO: add handling of the transparent & intercept
    cfg::TCFGInfo & cfg_ = this->ttncfg;

    if ( cfg_.enable_auth ){

        //TODO:tmp solution  to restore old behaviour until we move handling of the portal page to dynamic backend and redo the auth. UI Page

        if (    !cfg_.intercept_login   &&

                flags.intercepted           ){

            #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )

                // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                ttag.identity.eph.reason.major=MAJ_REASON_ADMIN_BLOCKED;

                ttag.http.status_msg="(2) Blocked from proxy ";

                ttag.http.status_code=scForbidden;

            #endif

            MATCHACL_RESULT_(request_state::deny)

            assert( false && "ACLTitanAuth::match::failed:@c8");

        }

        /**
         * precedence :
         * user id 
         * location tag (vloc)
         * ip 
         */
        search_identity_by tsib_ {  ir.ttag.dns_meta_data.iuid_valid                ?

                                    search_identity_by::uid                         :

                                    (   ir.ttag.dns_meta_data.otp_tag_len           ?

                                        tsib_ = search_identity_by::lid             :

                                        tsib_ = search_identity_by::ip          )       };

        if (    cfg_.allow_ip                       ||

                (   cfg_.intercept_login            &&

                    flags.intercepted       )       ||

                (   (   cfg_.allow_ldap             ||

                        cfg_.enable_ntlm            ||

                        cfg_.use_kshield    )       &&

                    cfg_.ip_session             )       ){


                if (    fetchIdentity( ir, tsib_, cidr_stat.first ) &&

                        ir.ttag.user_found()                            ) {

                    using namespace titan_v3::tools::eop;

                    if( as_bool(r_ & t_wbl_actions::wba_block) ){

                        if ( !as_bool(r_ & t_wbl_actions::wba_log) ){

                            flags.ttn_do_not_check=flags.ttn_has_been_logged=true;

                        }

                        #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )

                            // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                            ttag.identity.eph.reason.major=MAJ_REASON_ADMIN_BLOCKED;

                            ttag.http.status_msg="(3) Blocked from proxy ";

                            ttag.http.status_code=scForbidden;

                        #endif

                        MATCHACL_RESULT_(request_state::deny)

                        assert( false && "ACLTitanAuth::match::failed:@c9");

                    }

                    if ( as_bool(r_ & t_wbl_actions::wba_bypassfilters) ){

                        if ( !as_bool(r_ & t_wbl_actions::wba_log) ) {

                            flags.ttn_do_not_check=flags.ttn_has_been_logged=true;

                        }

                        MATCHACL_RESULT_(request_state::allow)

                        assert( false && "ACLTitanAuth::match::failed:@c10");

                    }

                    if (    !checklist_                                     ||

                            checklist_->Update( request_state::dunno,
                                                "Titan auth DUNNO/ALLOWED")     ){

                        MATCHACL_RESULT_(request_state::dunno)

                    }

                     titax_log(  LOG_ERROR,
                                 "ASSERT :: %s :: ACLTitanAuth::match::failed:@c11 - dying!\n", __func__ );
                     exit(-1);

                } else if (ir.ttag.isScheduledContextSet()) {

                    //Schedule user retrieval from DB.
                    MATCHACL_RESULT_(request_state::read_sched)

                }

        } /* if */

        if (    !cfg_.allow_wada        &&

                cfg_.allow_ip           &&

                !cfg_.allow_ldap        &&

                !cfg_.enable_ntlm       &&

                !cfg_.use_kshield       &&

                !ir.ttag.user_found()       ){

                #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )

                    // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                    ttag.identity.eph.reason.major=MAJ_REASON_ADMIN_BLOCKED;

                    ttag.http.status_msg="(4) Blocked from proxy ";

                    ttag.http.status_code=scForbidden;

                #endif

                MATCHACL_RESULT_(request_state::deny)

                assert( false && "ACLTitanAuth::match::failed:@c12");

        }

        if (    cfg_.enable_ntlm    ||

                cfg_.allow_ldap     ||

                cfg_.use_kshield        ){

            //TODO: temporary solution until we move handling of the portal page to dynamic backend and redo the auth. UI Page
            if (    !flags.intercepted              &&

                    cfg_.allow_ldap                 &&

                    cfg_.tmp_intercept_login_pfm        ){

                    #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
                        // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                        ttag.app_type=txapp_cmd_forward_auth_portal;

                        ttag.identity.eph.reason.major=MAJ_REASON_UNKNOWN_ERROR;

                        ttag.http.status_msg="Login"; //sso

                        ttag.http.status_code=scNotFound;

                    #endif

                    MATCHACL_RESULT_(request_state::deny)
                    assert( false && "ACLTitanAuth::match::failed:@c13");
            }

            if ( checkauth_ && checklist_ ) {

                answer=checkauth_(checklist_);

            }

            if (    cfg_.use_kshield                &&

                    request_state::deny == answer   &&

                    cfg_.allow_wada                     ){

                answer=request_state::allow;

            }

        } /* if */

    } /* if */

    if (    answer == request_state::allow  || 

            answer == request_state::deny       ) {

        ir.processing_step = 2;

        return matchACLCheckAnswer( ir, checklist_, answer );

    }

    // If the answer is not allowed or denied (matches/not matches) and
    // async authentication is not in progress, then we are done.
    if( checklist_                  && 

        checklist_->keepMatching()      ){

        checklist_->markFinished(answer, "AuthenticateAcl exception");

    }

    MATCHACL_RESULT_(request_state::dunno) // other

    assert( false && "ACLTitanAuth::match::failed:@c19");

}


request_state TaPE::matchACLCheckAnswer(    IHRequest & ir, 
                                            IACLChecklist *const  checklist_, 
                                            request_state answer                ) {

    IHRequestFlags & flags=ir.get_flags();
    TaTag & ttag=ir.ttag;

    const auto & cidr_stat = cidr::factory::make_cidr( ir.get_client_addr() );

    if ( !cidr_stat.second ) {
            
        titax_log(  LOG_WARNING,
                    "%s:%d:: make make_cidr failed - access deny!\n",__func__,__LINE__ );

        answer=request_state::deny;
    }

    // convert to tri-state ACL match 1,0,-1
    switch (answer) {
        case request_state::allow :{

            if (    this->ttncfg.enable_auth        &&

                    (   this->ttncfg.allow_ldap     || 

                        this->ttncfg.enable_ntlm    || 

                        this->ttncfg.use_kshield        )   ) {

                    const auto & loc = locations.find( cidr_stat.first );

                    const bool is_ts = loc.second && loc.first.terminal_server;
                    
                    if (   (  ir.ttag.user_found()                                              || 

                              fetchIdentity( ir, search_identity_by::uname, cidr_stat.first ) ) &&

                              ttncfg.ip_session                                                 && 

                              !is_ts                                                                ) {

                            TitaxUser * u_{};
                            if ( !ttag.identity.child.invalid_user && 
                                    (ttag.identity.eph.user->id==ttag.identity.child.id)){

                                        u_=&ttag.identity.child;
                            }

                            if (!u_ && (!ttag.identity.parent.invalid_user) &&
                                    (ttag.identity.eph.user->id==ttag.identity.parent.id)){

                                        u_=&ttag.identity.child;
                            }

                            if ( u_ ){
                                //find first or update
                                using namespace titan_v3::locations; 
                                auto p=this->locations.add( cidr_stat.first ,u_->id,location_t::types::session);
                                if (p.second){
                                    ir.ttag.identity.eph.location=std::move(p.first);
                                } else {
                                    ir.ttag.identity.eph.location.zero();
                                }

                                TXDEBLOG(std::cout<<this->locations<<std::endl);
                            }
                    } else if (ir.ttag.isScheduledContextSet()) {
                        //Schedule user retrieval from DB.
                        MATCHACL_RESULT_(request_state::read_sched)
                    }
            }

            ////////////////////////////////////////////////////////////////////////////////
            //                W/B lists
            ////////////////////////////////////////////////////////////////////////////////
            using namespace titan_v3::tools::eop;

            t_wbl_actions r_ = ir.check_global_wbl_actions();
            if ( as_bool(r_ & t_wbl_actions::wba_block)){
                if (!as_bool(r_ & t_wbl_actions::wba_log))
                    flags.ttn_do_not_check=flags.ttn_has_been_logged=true;

                #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
                    // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                    ttag.identity.eph.reason.major=MAJ_REASON_ADMIN_BLOCKED;
                    ttag.http.status_msg="(5) Blocked from proxy ";
                    ttag.http.status_code=scForbidden;
                #endif
                MATCHACL_RESULT_(request_state::deny)
                assert( false && "ACLTitanAuth::match::failed:@c15");
            }

            if (as_bool(r_ & t_wbl_actions::wba_bypassfilters)){
                if (!as_bool(r_ & t_wbl_actions::wba_log))
                    flags.ttn_do_not_check=flags.ttn_has_been_logged=true;

                MATCHACL_RESULT_(request_state::allow)
                assert( false && "ACLTitanAuth::match::failed:@c16");
            }

            if ((!checklist_ || checklist_->Update(request_state::dunno, "Titan auth DUNNO/ALLOWED"))) {

                MATCHACL_RESULT_(request_state::dunno)
            }

            titax_log(  LOG_ERROR,
                        "ASSERT :: %s :: ACLTitanAuth::match::failed:@c17 - dying!\n",__func__ );
            exit(-1);
        }

        case request_state::deny:{
            #if ( ( __FreeBSD_version >= MIN_OS_FB_10_3 ) || ! defined ( __clang_analyzer__ ) )
                // remove this "swiss-cheese" macro when we finally start building only on the FB11+
                ttag.identity.eph.reason.major=MAJ_REASON_ADMIN_BLOCKED;
                ttag.http.status_msg="Authentication failed - wrong credentials";
                ttag.http.status_code=scForbidden;
            #endif
            MATCHACL_RESULT_(request_state::deny) // non-match
            assert( false && "ACLTitanAuth::match::failed:@c18");
        }break;
        default:{
            if(checklist_ && checklist_->keepMatching()) 
                checklist_->markFinished(answer, "AuthenticateAcl exception");

            MATCHACL_RESULT_(request_state::dunno) // other
            assert( false && "ACLTitanAuth::match::failed:@c19");
        }break;
    }

    return(request_state::allow);
}

//------------------------------------------------------------------------------

constexpr const char FETCHIDENTITY_FLAG1[] = "AUTHFAIL::User couldn't be identified by the IP address:{";

constexpr const char FETCHIDENTITY_FLAG2[] = "AUTHFAIL::User couldn't be identified by the NAME:{";

bool TaPE::fetchIdentity(   IHRequest & ir ,
                            const search_identity_by st,
                            const cidr_t & cip              ){

    UsersCache::UserStatus user_status = UsersCache::UserNotFound;
    UsersCache::UserStatus parent_status = UsersCache::UserNotFound;
    using namespace titan_v3::locations;

    bool is_ts_{};

    auto is_location_valid_=[&]{

        if (st == search_identity_by::lid) {

            auto loc = locations.find(    std::string{   ir.ttag.dns_meta_data.otp_tag,
                                                         ir.ttag.dns_meta_data.otp_tag_len   }   );

            if (    loc.second                                  &&

                    loc.first.type != location_t::types::none       ) {

               return loc;
            }
        }

        auto loc = locations.find( cip );

        if  ( loc.second ) {

            is_ts_ = loc.first.terminal_server;

            if (  ! is_ts_                                  &&

                  loc.first.type != location_t::types::none       ) {

               return loc;
            }
        }

        return find_pair_t::failure();
    };

    switch (st){ 
        case search_identity_by::uid:{

            auto valid_loc = is_location_valid_();

            if ( valid_loc.second && users_cache ){

               TaTag & ttag = ir.ttag;

               user_status = users_cache->get_user_by_id(   ttag.dns_meta_data.iuid,
                                                            ttag.identity.child      );

               switch (user_status){

                  case UsersCache::UserFound:{

                     if (ir.ttag.identity.child.parent_valid) {

                        if ( valid_loc.first.user_id == ttag.identity.child.parent_id ){

                           parent_status = users_cache->get_user_by_id( ttag.identity.child.parent_id,
                                                                        ttag.identity.parent            );

                           switch (parent_status){

                              case UsersCache::UserFound:break;

                              case UsersCache::UserNotLoaded:{
                                 ttag.setScheduledContext( new UserParent{ttag.identity.child.parent_id} );
                                 return false;
                              }

                              case UsersCache::LoadUserNotFound:{
                                 fetchUserFromDb( new UserParent{ttag.identity.child.parent_id} );
                                 ttag.identity.parent = ttag.identity.child;
                              }break;

                              case UsersCache::UserNotFound:{
                                 ttag.identity.parent = ttag.identity.child; 
                              }break;
                           } /* switch */

                           ttag.identity.eph.location=std::move(valid_loc.first);
                           return true;

                        }

                     } else {

                        if ( valid_loc.first.user_id == ttag.identity.child.id ){

                           ttag.identity.parent = ttag.identity.child;
                           ttag.identity.eph.user = &ttag.identity.parent;
                           ttag.make_child_anonymous();

                           ttag.identity.eph.location=std::move(valid_loc.first);
                           return true;

                        }
                     }

                  } break;

                  case UsersCache::UserNotLoaded:{

                     ttag.setScheduledContext(new UserById{ ttag.dns_meta_data.iuid,
                                                            valid_loc.first.user_id /* parent */   });
                     return false;
                  }

                  case UsersCache::LoadUserNotFound:{

                     fetchUserFromDb(new UserById{  ttag.dns_meta_data.iuid, 
                                                    valid_loc.first.user_id /* parent */ }); 
                  }break;

                  case UsersCache::UserNotFound:break;

               } /* switch */

            } /* if */

        } [[clang::fallthrough]]; /* search_identity_by::uid */

        //not implemented yet
        case search_identity_by::lid: [[clang::fallthrough]];

        case search_identity_by::ip:{

            auto valid_loc = is_location_valid_();

            if ( valid_loc.second && users_cache ) {

               TaTag & ttag=ir.ttag;
               /*
                *
                * If the default parent user (aka the customer) is present (not null) and has no groups then we can assume it is the WT500
                * and if so then if the child user has no group we will dynamically assign it to the Default group/policy.
                * WARNING this change is persistent as long as the list of users is not reloaded.
                *
                */

               user_status = users_cache->get_user_by_location( valid_loc.first,
                                                                ttag.identity.child);

               if (user_status == UsersCache::UserFound){

                  if (ir.ttag.identity.child.parent_valid) {

                     parent_status = users_cache->get_user_by_id(   ttag.identity.child.parent_id,
                                                                    ttag.identity.parent            );

                     if (parent_status == UsersCache::UserNotLoaded) {

                        ttag.setScheduledContext(new UserParent{ttag.identity.child.parent_id});

                        return false;
                     }
                     else if (parent_status == UsersCache::LoadUserNotFound) {

                        fetchUserFromDb(new UserParent{ttag.identity.child.parent_id});
                        ttag.identity.parent = ttag.identity.child;
                     }
                     else  if (parent_status == UsersCache::UserNotFound) {

                        ttag.identity.parent = ttag.identity.child;
                     }

                  }
                  else {

                     ttag.identity.parent = ttag.identity.child;
                     ttag.identity.eph.user = &ttag.identity.parent;
                     ttag.make_child_anonymous();
                  }

                  ttag.identity.eph.location=std::move(valid_loc.first);

                  return true;

               } else if (user_status == UsersCache::UserNotLoaded) {

                  ttag.setScheduledContext(new UserFromIp{std::move(valid_loc.first)});

                  return false;

               } else if (user_status == UsersCache::LoadUserNotFound) {

                  fetchUserFromDb(new UserFromIp{valid_loc.first}); //cpy
               }

               ttag.identity.eph.location=std::move(valid_loc.first);

            } /* if */

            if ( !is_ts_ ) {

                std::string msg_{FETCHIDENTITY_FLAG1};

                msg_ += factory::to_string(cip);

                msg_ += '}';

                titax_log(LOG_NOTICE,"%s",msg_.c_str());

            }

            //no effective policy found aka user not found aka anon-webtitan
            return true;

        } /* sib_ip */

        case search_identity_by::uname:{

            const cfg::TCFGInfo & cfg_ = this->ttncfg_;

            if( users_cache && ir.get_authenticateUserAuthenticated() ) {

                std::string ubuf = ir.get_auth_user_request_username();

                if ( ubuf.size() ) {

                    if ( cfg_.enable_ntlm || cfg_.allow_ldap || cfg_.use_kshield ) {
                        //  NTLM:
                        //    user@domain
                        //    domain/user

                        if ( users_cache->getListType() == UsersListType::ult_plain ) {

                            std::string uname = tools.conv2pform(ubuf);

                            if ( uname.length() ) {

                                user_status = users_cache->find_user_by_name_utf8(uname, ir.ttag.identity.child);
                            }

                            if ( user_status == UsersCache::UserNotLoaded ) {

                                ir.ttag.setScheduledContext(new UserByName{uname});
                                return false;
                            }

                        }
                        else { // ult_hybrid || ult_multidomain

                            std::string domains;

                            for (   auto dm = ldap.ldap_domains.cbegin();
                                    user_status != UsersCache::UserFound && dm != ldap.ldap_domains.cend();
                                    ++dm                                                                    ) {

                                // REPEATED !!!
                                std::string uname = tools.conv2pform( ubuf );

                                if ( uname.length() ) {

                                    user_status = users_cache->find_user_by_name_utf8( uname, ir.ttag.identity.child );

                                    if ( user_status == UsersCache::UserNotLoaded ) {

                                        if (domains.length()) {

                                            domains += ", ";
                                        }

                                        domains += "'" + *dm + "'";
                                    }

                                    if ( user_status == UsersCache::UserNotLoaded || domains.length() ) {

                                        ir.ttag.setScheduledContext(new UserByName{uname, domains});

                                        return false;
                                    }
                                }
                            }
                        }
                    } /* flags if */

                    if (user_status == UsersCache::UserFound){
                        /*
                         *
                         * If the default parent user (aka the customer) is present (not null) and has no groups then we can assume it is the WT500
                         * and if so then if the child user has no group we will dynamically assign it to the Default group/policy.
                         * WARNING this change is persistent as long as the list of users is not reloaded.
                         *
                         */

                        const TitaxUser & _u_by_ip = ir.ttag.identity.child;

                        if ( _u_by_ip.parent_valid ) {

                            parent_status = users_cache->get_user_by_id(    _u_by_ip.parent_id,
                                                                            ir.ttag.identity.parent );

                            if ( parent_status == UsersCache::UserFound ) {

                                return true;
                            }

                            if ( parent_status == UsersCache::UserNotLoaded ) {

                                ir.ttag.setScheduledContext( new UserParent{ _u_by_ip.parent_id } );

                                return false;
                            }

                        }

                    }

                    std::string msg_{ FETCHIDENTITY_FLAG2 };

                    msg_.reserve( 1+ubuf.size()+sizeof(FETCHIDENTITY_FLAG2)-1 );

                    msg_ += ubuf;

                    msg_ += '}';

                    titax_log( LOG_NOTICE, "%s", msg_.c_str() );

                    //no effective policy found aka user not found aka anon-webtitan
                    return false;
                }
            }

        } break; /* search_identity_by::uname */

        default: return true;

    } /* switch */

    return true;
}

//------------------------------------------------------------------------------

bool TaPE::init(    const char* const log_name,
                    const int log_level,
                    const bool verbose,
                    vPGconn* const db_          ){

    #ifndef TTN_ATESTS

        ::titax_loginit(log_name);

        ::titax_logsetlevel_stderr(log_level);

        /* check mode */
        static parse_app_mode_fn get_app_mode{};

        app_mode_=get_app_mode();

        try{

            init_users_cache(100000); //connect it to the app mode 

        }catch (const std::exception& e) {

            tools::functors::tos msg{__FILE__};

            msg<<":"<<__LINE__<<"::exception ["<<e.what()<<"]";

            titax_log(LOG_ERROR, "%s\n",msg.c_str());

            exit(INVALID_);

        }

        /* initialize titax lib */
        ::titax_init_all(verbose);

    #else

        (void)log_name;

        (void)log_level;

        (void)verbose;

        if (!db_) 
            return false;

        try{

            init_users_cache(1024);

        }catch (...) {

            return false;

        }

        if (!titax_init_all_4tests(static_cast<PGconn * const>(db_))) 
            return false;

    #endif

    cfg::TCFGInfo & cfg_=this->ttncfg_;

    /*
    * TODO:
    * initialize here titaxlib
    */

    if ( ! cfg_.lock_and_init() ) {

       titax_log( LOG_ERROR,
                  "ASSERT :: %s :: lock_and_init failed - dying!\n",__func__ );
       exit(-1);
    }

    //load only once
    if ( ext_map_ ) {

         delete[] ext_map_;

         ext_map_ = nullptr;
    }

    ext_map_ = new ::t_strptr[cfg_.fext_max_match_count]{};

    if ( ! ext_map_ ) {

       titax_log( LOG_ERROR,
                  "ASSERT :: %s :: ext_map_ is NULL - dying!\n",__func__ );
       exit(-1);
   }

    (void)(cfg_.verbose && (std::cout<<"TaPE::init::"<<cfg_<<"\n"));

    this->ldap.reload_domains(db_);

    this->wbl.reload(db_);

    //this->_open_logger();

    wada_cfg_t wcfg_ = {

        .wada_cache_file=ttncfg.wada_cache_file,

        .keep_existing_entries=cfg_.wada_keep_existing_entries
    };


    /* note : this method internally stores the raw pointer to the wada_cache_file member */
    if ( wada.configure( &wcfg_ ) ){

        (void)(cfg_.verbose && std::cout<<"wada loading....\n");

        if ( wada.reload_from_files() ) {

            (void)(cfg_.verbose && std::cout<<"wada loaded\n");
            //return true;
        } else {

            (void)(cfg_.verbose && std::cout<<"wada NOT loaded\n");

        }

        return true; // add option to require wada files 

    }

    return false;
}

//------------------------------------------------------------------------------
   
using t_lstate =  enum {
    wbls_blocked=-1,
    wbls_unknown=0,
    wbls_allowed=1,
};
using t_restrictiveness =  enum {
    restricted=-1,
    unrestricted=1
};

constexpr
t_lstate GET_STATE_( t_wbl_actions a_v_ ){

    using namespace titan_v3::tools::eop;

    return (    (as_bool(a_v_ & t_wbl_actions::wba_bypassfilters))  ? 

                t_lstate::wbls_allowed                              : 

                (   ( as_bool(a_v_ & t_wbl_actions::wba_block) )    ? 

                    t_lstate::wbls_blocked                          : 

                    t_lstate::wbls_unknown                      )       );

}

constexpr
t_wbl_actions GET_ACTION_(t_lstate a_v_){

    using namespace titan_v3::tools::eop;

    return (    !(a_v_)                                 ?

                t_wbl_actions::wba_none                 :

                (   (a_v_)==t_lstate::wbls_allowed      ?

                    t_wbl_actions::wba_bypassfilters    :

                    t_wbl_actions::wba_block            )   );
}

constexpr
t_restrictiveness GET_RF_(bool a_v_){

    return (    (a_v_)                          ?

                t_restrictiveness::restricted   :

                t_restrictiveness::unrestricted     );
}

constexpr
bool GET_BA_(   t_wbl_actions a_v1_,
                t_wbl_actions a_v2_ ){

    using namespace titan_v3::tools::eop;

    return (    as_bool(a_v1_ & t_wbl_actions::wba_bypassauth) ||

                as_bool(a_v2_ & t_wbl_actions::wba_bypassauth)     );

}

t_wbl_actions TaPE::t_wbl::check_all( const std::string & host_, const std::string & path_ ) const noexcept
{

    // Compliant with the matrix of truth at [http://dokuwiki.spamtitan.com/doku.php?id=webtitanwiki:wtwblistsmatrix]
    using namespace titan_v3::tools::eop;

    std::lock_guard<std::mutex> wbl_lock{ lock_ };

    t_restrictiveness least_restrictive = GET_RF_( owner_.ttncfg.least_restrictive );

    const auto hsz = host_.size();

    t_wbl_actions dl{ t_wbl_actions::wba_none };

    if (hsz) {

        dl = domains_.find_fqdn( host_, INVALID_ );
    }

    t_lstate sdl{ GET_STATE_( dl ) };

    if ( sdl ) {

        switch (least_restrictive) {

            case t_restrictiveness::restricted: {

                if ( as_bool( ( t_wbl_actions::wba_bypassauth | t_wbl_actions::wba_bypassfilters ) & dl ) ) {

                    return dl;
                }

            } break;

            case t_restrictiveness::unrestricted: {

                if ( as_bool( t_wbl_actions::wba_block & dl ) ) {

                    return dl;
                }

            } break;
        }
    }

    t_wbl_actions kl{};

    auto & kpi=titan_v3::KeywordPolicies::get_instance();

    if ( !kpi.keywords_find( host_.c_str(), path_.c_str(), kl ) ) {

        return dl;
    }

    if ( kl != t_wbl_actions::wba_none ) {

        kl |= t_wbl_actions::wba_log;
    }

    t_wbl_actions re{ t_wbl_actions::wba_none };

    const bool ba{ GET_BA_( dl, kl ) };

    t_lstate skl{ GET_STATE_( kl ) };

    if ( sdl != skl && sdl && skl ) {

        const auto v_ = ( sdl * skl * static_cast<int>( least_restrictive ) );

        t_lstate sre = static_cast<t_lstate>( v_ );

        re = GET_ACTION_( sre );

        if ( as_bool( re ) ) {

            if ( ba ) {

                re |= t_wbl_actions::wba_bypassauth;
            }

            re |= t_wbl_actions::wba_log;

            return re;
        }
    }

    if ( sdl == skl ) {

        re = dl;

        if ( as_bool( re ) ) {

            if ( ba ) {

                re |= t_wbl_actions::wba_bypassauth;
            }

            return re;
        }
    }

    re = ( sdl ? dl : kl );

    if ( ba ) {

        re |= t_wbl_actions::wba_bypassauth;
    }

    return re;
}

struct wbl_reload_elems {
    uint_fast64_t i_;
    const uint_fast64_t max_;
    PGresult* const rset_;
    const char * str_;
    size_t sz_;
    t_wbl_actions  act_;
    int pid_;
};
   
bool TaPE::t_wbl::reload(vPGconn* const  db_){
    bool local_db{};
    PGconn* db{};
    if ((db_ && (db=static_cast<PGconn * const>(db_))) || 
        (local_db=check_raw_dbconn(&db,16,&db_config_connect))){

            std::lock_guard<std::mutex> wbl_lock{lock_};
            this->domains_.clear();
            {
                if (PGresult* const rset=::pq_get_rset(db, TITAXLIB_QS_V_DP_FLAGS)){

                    using namespace titan_v3::tools::eop;
                    struct wbl_reload_elems e={
                        .max_=txpq_row_count(rset),
                        .rset_=rset
                    };

                    for (;e.i_<e.max_;++e.i_){
                        if ((e.str_=::txpq_cv_str(e.rset_, e.i_, 1)) && (e.sz_=::strlen(e.str_))){

                            (void)( this->domains_.add( e.str_,
                                                        e.sz_,
                                                        (e.pid_=::txpq_cv_int(rset, e.i_, 2)),
                                                        (e.act_=to_enum<t_wbl_actions>(::txpq_cv_ulong(rset, e.i_, 3) )) ) 
                                    && e.str_[0]=='.' && 
                                    
                                    this->domains_.add(e.str_+1,e.sz_-1,e.pid_,e.act_));
                        }
                    }

                    ::txpq_reset(rset);

                    if (local_db)
                        ::pq_conn_close(db);

                    if (owner_.ttncfg.verbose)
                        domains_.dump();

                    return true;
                }
            }

            if (db && local_db)
                ::pq_conn_close(db);

    }
    return false;
}
//------------------------------------------------------------------------------
bool TaPE::t_ldap::reload_domains(vPGconn* const  db_){
    bool local_db{};
    this->ldap_domains_.clear();
    PGconn* db{};
    if ( (db_ && (db=static_cast<PGconn * const>(db_))) ||
        (local_db = check_raw_dbconn( &db, 16, &db_config_connect )) ){

            if (PGresult* const rset=::pq_get_rset(db, TITAXLIB_QS_T_LDAPSERVERS_DOMAINS)){

                uint_fast64_t i_=0;

                const uint_fast64_t l_=::txpq_row_count(rset);

                while(i_<l_){
                    if (const char * str_=txpq_cv_str(rset, i_++, 0)){
                        if (str_[0]) 
                            ldap_domains_.emplace_back(str_);
                    }
                }

                ::txpq_reset(rset);
                
                if(local_db) 
                    pq_conn_close(db);
                
                if (owner.ttncfg.verbose){
                    for (const auto &_dm : this->ldap_domains_){
                        std::cout<<"{"<<_dm<<"}\n";
                    }
                }
                
                return (this->ldap_domains_.size()>0);
            }
            
            if (local_db)
                pq_conn_close(db);
    }
    return (false);
}

//------------------------------------------------------------------------------
template <typename T>
static constexpr T get_uname_(T uname){
    size_t found = uname.find_first_of(R"(\/)");
    if (std::string::npos==found){
        if (std::string::npos==(found=uname.find_first_of("@"))){
            return uname;
        }
        return uname.substr(0,found); 
    }
    return uname.substr(found+1,uname.length()-found+1);
}


//convert username string to plain form
std::string TaPE::t_tools::conv2pform(std::string uname){
    if (uname.size()){
        std::string out=get_uname_(uname);
        std::transform(out.begin(), out.end(), out.begin(), ::tolower);
        size_t found=0;
        while ((found = out.find("%20", found)) != std::string::npos) {
            out.replace(found, 3, " ");
            ++found;
        }
        return out;
    }
    return {};
}
//------------------------------------------------------------------------------
//convert username string to common form (currently it is uname@domain)
std::string TaPE::t_tools::conv2cform(std::string uname,const std::string &  domain){
    if (uname.size()){
        std::size_t found=0;
        if ((found=uname.find_first_of(R"(\/)")) && (found!=std::string::npos)){
            std::string ntdm=uname.substr(0,found);
            std::transform(ntdm.begin(), ntdm.end(), ntdm.begin(), ::tolower);
            if (domain.find(ntdm) != std::string::npos) {
                std::string out=uname.substr(found+1,uname.length()-found+1 );
                out+={'@'};
                out+=domain;
                std::transform(out.begin(), out.end(), out.begin(), ::tolower);
                return out;
            }
            return {};
        }

        if ((found==std::string::npos) && 
            (found=uname.find_first_of("@")) &&
            (found!=std::string::npos)){

                std::transform(uname.begin(), uname.end(), uname.begin(), ::tolower);
                return uname;
        }
        std::string out=uname;
        out+={'@'};
        out+=domain;
        std::transform(out.begin(), out.end(), out.begin(), ::tolower);
        return out;
    }
    return {};
}
//------------------------------------------------------------------------------   
#define RETURN_(a_msg_) return {a_msg_}

std::string TaPE::t_tools::err2str(const t_err_type e_)const{
    switch (e_){
        case ERR_CACHE_MGR_ACCESS_DENIED: RETURN_("Cache Manager Access Denied.");
        case ERR_CANNOT_FORWARD: RETURN_ ("This request could not be forwarded to the origin server or to any parent caches.");
        case ERR_READ_TIMEOUT: RETURN_ ("A Timeout occurred while waiting to read data from the network. Please retry your request.");
        case ERR_LIFETIME_EXP: RETURN_ ("Connection Lifetime Expired.");
        case ERR_READ_ERROR: RETURN_ ("An error condition occurred while reading data from the network. Please retry your request.");
        case ERR_WRITE_ERROR: RETURN_ ("An error condition occurred while writing to the network. Please retry your request.");
        case ERR_CONNECT_FAIL: RETURN_ ("The remote host or network may be down. Please try the request again.");
        case ERR_SECURE_CONNECT_FAIL: RETURN_ ("Failed to negotiate a mutually acceptable security settings with the remote host.");
        case ERR_SOCKET_FAILURE: RETURN_ ("The proxy is unable to create a TCP socket, presumably due to excessive load. Please retry your request.");
        case ERR_DNS_FAIL: RETURN_ ("Unable to determine IP address from host name.");
        case ERR_URN_RESOLVE: RETURN_ ("Cannot Resolve URN.");
        case ERR_ONLY_IF_CACHED_MISS: RETURN_ ("Valid document was not found in the cache and only-if-cached directive was specified.");
        case ERR_INVALID_REQ: RETURN_ ("Invalid Request error was encountered while trying to process the request");
        case ERR_INVALID_RESP: RETURN_ ("Invalid HTTP Response message received from the contacted server.");
        case ERR_INVALID_URL: RETURN_ ("Some aspect of the requested URL is incorrect.");
        case ERR_ZERO_SIZE_OBJECT: RETURN_ ("The proxy did not receive any data for this request.");
        case ERR_PRECONDITION_FAILED: RETURN_ ("Some precondition specified by the HTTP client in the request header has failed.");
        case ERR_CONFLICT_HOST: RETURN_ ("The domain name being accessed no longer exists on the machine you are requesting it from.");
        case ERR_FTP_DISABLED: RETURN_ ("This cache does not support FTP.");
        case ERR_FTP_UNAVAILABLE: RETURN_ ("FTP server is unavailable.");
        case ERR_FTP_FAILURE: RETURN_ ("There has been an FTP protocol error.");
        case ERR_FTP_PUT_ERROR: RETURN_ ("FTP server may not have permission or space to store the file.");
        case ERR_FTP_NOT_FOUND: RETURN_ ("File not found.");
        case ERR_FTP_FORBIDDEN: RETURN_ ("Not allowed to perform this FTP request.");
        case ERR_ICAP_FAILURE: RETURN_ ("Some aspect of the ICAP communication failed.");
        case ERR_GATEWAY_FAILURE: RETURN_ ("Gateway Proxy Failure.");
        case ERR_ACCESS_DENIED:
        case ERR_CACHE_ACCESS_DENIED:
        case ERR_FORWARDING_DENIED:
        case ERR_NO_RELAY:
        case ERR_TOO_BIG:
        case ERR_UNSUP_HTTPVERSION:
        case ERR_UNSUP_REQ:
        case ERR_FTP_PUT_CREATED:
        case ERR_FTP_PUT_MODIFIED:
        case ERR_ESI:
        case ERR_DIR_LISTING:
        case ERR_SQUID_SIGNATURE:
        case ERR_SHUTTING_DOWN:
        case TCP_RESET:
        case MGR_INDEX:
        case ERR_NONE:
        default:return tools::tos{e_};
    }
}

void TaPE::t_tools::titax_log_msg(const int level, const char *const msg){
    ::titax_log(level,"%s",msg);
}

}; // namespace titan_v3 


////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////
//
//       GTAPE
//
////////////////////////////////////////////////////////////////////////////////

#ifdef TTN_ATESTS 

bool gtape_init(vPGconn* const db_){
    return titan_v3::GTAPE.init(nullptr,0,false,db_);
}

#endif

bool gtape_reload_wbl_domains(vPGconn* const  db_){
    return titan_v3::GTAPE.wbl.reload(db_);
}

bool gtape_reload_ldap_domains(vPGconn* const  db_){
    return titan_v3::GTAPE.ldap.reload_domains(db_);
}

void gtape_uniqips_clear_old(){
    titan_v3::GTAPE.uniqips_clear_old();
}

void gtape_lic_mgr_query(){
    titan_v3::lic_mgr::query();
}

bool gtape_lic_mgr_save_cache(){
    return titan_v3::lic_mgr::save();
}


TX_INTERNAL_INLINE
bool gtape_location_is_known_raw_ipaddr_(   const c_raw_ipaddr_t * const __restrict ip,
                                            const char * const __restrict otp_tag = {},
                                            size_t otp_tag_len = {}   )
{
    using namespace titan_v3;

    if ( ip ) {

        if ( otp_tag && !otp_tag_len ) {

            otp_tag_len = strlen(otp_tag);
        }

        std::string tag = ( otp_tag && otp_tag_len              ?

                            std::string{ otp_tag, otp_tag_len } :

                            std::string{}                           );

        if ( checks::is_ipv4(*ip) ) {

            return  titan_v3::GTAPE.locations.is_known({    ip->v4,
                                                            IPV4_MAX_PREFIX },   /* <- implicit constructor */
                                                            tag                 );
        }

        return titan_v3::GTAPE.locations.is_known({ ip->v6, 
                                                    IPV6_MAX_PREFIX },   /* <- implicit constructor */
                                                    tag                 );
    }

    return false;
}

bool gtape_location_is_known_raw_ipaddr( const c_raw_ipaddr_t * const __restrict ip)
{
    return gtape_location_is_known_raw_ipaddr_(ip);
}

bool gtape_location_is_known(   const c_raw_ipaddr_t * const __restrict ip,
                                const char * const __restrict otp_tag,
                                const size_t otp_tag_len    )
{
    return gtape_location_is_known_raw_ipaddr_( ip,
                                                otp_tag,
                                                otp_tag_len );
}

bool gtape_location_is_known_str_ipaddr(const char * const __restrict ip_str)
{
    if ( ip_str && *ip_str ){
        using namespace titan_v3::cidr;
        const auto s=factory::make_cidr(ip_str);
        if (s.second){
            return titan_v3::GTAPE.locations.is_known(s.first);
        }
    }
    return false;
}


/* add user id ??? */
/**
 * @abstract 
 * @param ip[in] c_raw_ipaddr_t it must be in host byte order
 */
bool gtape_location_add_session(    const c_raw_ipaddr_t * const __restrict ip, 
                                    const size_t u_id )
{
    if ( ip && titan_v3::cidr::checks::is_valid(*ip) ) {

        using namespace titan_v3::locations;

        const auto & cidr_stat = titan_v3::cidr::factory::make_cidr( *ip ) ;

        if ( cidr_stat.second ) {

             auto & locations = titan_v3::GTAPE.locations;

             const auto & loc_st = locations.find( cidr_stat.first );

             if ( !loc_st.second || !loc_st.first.terminal_server ) {
                // find first and update or add 
                return locations.add( cidr_stat.first, u_id, location_t::types::session ).second;
             }
        }
    }

    return false;
}


bool gtape_location_reload(PGconn* const __restrict  db){
    return (db && titan_v3::GTAPE.locations.reload(db));
}

wada_api_t * gtape_wada_api(){
    return titan_v3::GTAPE.wada.as_api();
}

app_t gtape_app_mode() {
    return titan_v3::GTAPE.app_mode;
}


/////////////////////////////////////////////////////////////////////////////
// DEBUG handler
/////////////////////////////////////////////////////////////////////////////

bool ttn_get_txdebug_state() {
   return titan_v3::gflags.TXDEBUG_;
}

void ttn_set_txdebug_state(bool s) {
   titan_v3::gflags.TXDEBUG_=s;
}

bool ttn_get_verbose_state() {
   return titan_v3::gflags.VERBOSE_;
}

void ttn_set_verbose_state(bool s) {
   titan_v3::gflags.VERBOSE_=s;
}

void ttn_set_shutdown_now() {
    titan_v3::gflags.SHUTDOWN_NOW_=true;
}

bool ttn_get_shutdown_now() {
    return titan_v3::gflags.SHUTDOWN_NOW_;
}

/* vim: set ts=4 sw=4 et : */

