/*
 * $Id$
 *
 * Copyright (c) 2005-2018, Copperfasten Technologies, Teoranta.  All rights
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

/*
C Library for DB.
*/

#include "edgepq.h"
#include "log.h"
#include "pthread_np.h"
#include "sqls.h"
#include <assert.h>
#ifdef TTN_ATESTS
   #if ( ! defined ( __clang_analyzer__ ) ) 
      // remove this "swiss-cheese" macro when we finally start building only on the FB11+
      #include <internal/libpq-int.h>
   #endif
#endif

//------------------------------------------------------------------------

#ifdef TTN_ATESTS
/* to fix portability issues raised by the cppcheck */
#define VANULL (void*)0L
static int pctx_=0;
static const char *const* params_=NULL;
#if ( ! defined ( __clang_analyzer__ ) ) 

/**
 * Direct copy from  /usr/local/include/postgresql/internal/c.h
 * unfortuantely it is needed because of the differences betwen PGSQL 9.3 and 9.4.
 * Please remove it when all build machines will switch to PG 9.4+
 * PG_VERSION_NUM
 */
#define MemSetPG(start, val, len) \
        do \
        { \
                /* must be void* because we don't know if it is integer aligned yet */ \
                void   *_vstart = (void *) (start); \
                int             _val = (val); \
                Size    _len = (len); \
\
                if ((((uintptr_t) _vstart) & LONG_ALIGN_MASK) == 0 && \
                        (_len & LONG_ALIGN_MASK) == 0 && \
                        _val == 0 && \
                        _len <= MEMSET_LOOP_LIMIT && \
                        /* \
                         *      If MEMSET_LOOP_LIMIT == 0, optimizer should find \
                         *      the whole "if" false at compile time. \
                         */ \
                        MEMSET_LOOP_LIMIT != 0) \
                { \
                        long *_start = (long *) _vstart; \
                        long *_stop = (long *) ((char *) _start + _len); \
                        while (_start < _stop) \
                                *_start++ = 0; \
                } \
                else \
                        memset(_vstart, _val, _len); \
        } while (0)


#endif

/**
 * 
 * @param c: count of columns
 * @return 
 */
static PGresult* alloc_columns_(const int c){
   PGresult* const rs=PQmakeEmptyPGresult(0,PGRES_TUPLES_OK);
   #if ( ! defined ( __clang_analyzer__ ) ) 
   if (rs){
      rs->numAttributes=c;
      rs->attDescs = (PGresAttDesc *) pqResultAlloc(rs, sizeof(PGresAttDesc)*(size_t)rs->numAttributes, FALSE);
      MemSetPG(rs->attDescs, 0, sizeof(PGresAttDesc)*(size_t)rs->numAttributes);
   }
   #endif
   return rs;
}

/**
 * 
 * add next row, have to specify/fill all fields, use NULL for empty columns
 * @param rs: record set
 * @param ...: var args all string (columns)
 * @return 1|0
 */
static bool add_row__(PGresult* const restrict rs, ... ){
   if (rs){
   #if ( ! defined ( __clang_analyzer__ ) ) 
      va_list fields;
      va_start ( fields, rs ); 
      struct {int c_; char * v_; const int max_; const int r_;} e={
         .max_=rs->numAttributes,
         .r_=rs->ntups
      };
      while(e.c_<e.max_ && ((e.v_=va_arg(fields, char *))||1) && (PQsetvalue(rs, e.r_, e.c_++, e.v_,(e.v_?(int)strlen(e.v_):0))));
      va_end(fields);
      return (e.c_==rs->numAttributes); 
   #endif
   }
   return false ;
}

typedef struct
{
   size_t args_sz;
   void * args;
   int id;
   int ctx;
}t_qtype;

static void scan_query( const char * const restrict q, t_qtype * const out )
{
   #define RETURN_(a_id_,a_ctx_){   \
      if ( out ) {                  \
        out->id = a_id_;            \
        out->ctx = a_ctx_;          \
        out->args_sz = 0;           \
      }                             \
      return;                       \
   }

   #define RETURN_INT_ARGS(a_id_,a_ctx_, a_sz_, ... ){                  \
        if ( out ) {                                                    \
            const size_t msz = sizeof(int) * a_sz_;                     \
            if ( ( out->args = malloc( msz ) ) ) {                      \
                memcpy( out->args, (int[a_sz_]){ __VA_ARGS__ }, msz );  \
                out->args_sz = a_sz_;                                   \
                out->id = a_id_;                                        \
                out->ctx = a_ctx_;                                      \
                return;                                                 \
            }                                                           \
            out->id = INVALID_;                                         \
            out->ctx = INVALID_;                                        \
            out->args_sz = 0;                                           \
        }                                                               \
        return;                                                         \
   }

   if (!strcmp(q,TNPQ_TEST_SQL1)) RETURN_(0,1)
   if (!strcmp(q,TNPQ_TEST_SQL2)) RETURN_(1,2)
   if (!strcmp(q,TNPQ_TEST_SQL3)) RETURN_(2,1)
   if (!strcmp(q,TNPQ_TEST_SQL4_PARSED)) RETURN_(3,2)
   if (!strcmp(q,TNPQ_TEST_SQL5_PARSED)) RETURN_(4,1)

   if (!strcmp(q,TITAXLIB_QS_PING)) RETURN_(10,1)
   if (!strcmp(q,TITAXLIB_QS_T_FILTERING)) RETURN_(11,15)
   if (!strcmp(q,TITAXLIB_QS_T_GROUPS)) RETURN_(13,5)

   if (!strcmp(q,TITAXLIB_QS_T_POLICIES)) RETURN_(14,10)
   if (!strcmp(q,TITAXLIB_QS_T_POLICYNONWORKINGHOURS)) RETURN_(15,4)
   if (!strcmp(q,TITAXLIB_QS_T_POLICYFLAGS)) RETURN_(16,31)
   if (!strcmp(q,TITAXLIB_QS_T_POLICYNOTIFICATIONS)) RETURN_(17,2)
   if (!strcmp(q,TITAXLIB_QS_T_POLICYSAFESEARCH)) RETURN_(18,3)
   if (!strcmp(q,TITAXLIB_QS_T_KEYWORDS)) RETURN_(19,2)
   if (!strcmp(q,TITAXLIB_QS_T_AUTHPOLICY)) RETURN_(20,10)
   if (!strcmp(q,TITAXLIB_QS_T_NETWORKING)) RETURN_(21,7)
   if (!strcmp(q,TITAXLIB_QS_T_CACHE)) RETURN_(22,1)
   if (!strcmp(q,TITAXLIB_QS_T_URLCATEGORIES_1)) RETURN_(23,2)
   if (!strcmp(q,TITAXLIB_QS_T_URLCATEGORIES_2)) RETURN_(24,2)
   if (!strcmp(q,TITAXLIB_QS_T_REDIRECTIONS)) RETURN_(25,2)
   if (!strcmp(q,TITAXLIB_QS_T_KEYWORD_POLICIES_AUTH)) RETURN_(26,3)
   if (!strcmp(q,TITAXLIB_QS_T_KEYWORD_POLICIES_FILTER)) RETURN_(27,3)
   if (!strcmp(q,TITAXLIB_QS_T_KEYWORD_POLICIES_BLOCK)) RETURN_(28,3)
   if (!strcmp(q,TITAXLIB_QS_F_USERS_LIST_TYPE)) RETURN_(29,1)
   if (!strcmp(q,TITAXLIB_QS_V_USERS)) RETURN_(30,10)
   if (!strcmp(q,TITAXLIB_QS_T_USERGROUPS_DISPLAY)) RETURN_(31,2)
   if (!strcmp(q,TITAXLIB_QS_T_USERGROUPS_EFFECTIVE)) RETURN_(32,3)
   if (!strcmp(q,TITAXLIB_QS_V_LOCATIONS)) RETURN_(33,8)
   if (!strcmp(q,TITAXLIB_QS_V_USERS_CKEY_COUNTS)) RETURN_(34,2)
   if (!strcmp(q,TITAXLIB_QS_V_ACTIVE_USED_BYPASS_TOKENS_SHORT)) RETURN_(35,3)
   if (!strcmp(q,TITAXLIB_QS_T_USERS_BANDWIDTH)) RETURN_(36,2)
   if (!strcmp(q,TITAXLIB_QS_T_UPDATE_TIMES)) RETURN_(37,2)
   if (!strcmp(q,TITAXLIB_QS_V_DP_FLAGS)) RETURN_(38,4)
   if (!strcmp(q,TITAXLIB_QS_T_LDAPSERVERS_DOMAINS)) RETURN_(39,1)
   if (!strcmp(q,TITAXLIB_QS_V_TOP_USERS)) RETURN_(40,10)

   if ( !strncmp(   q,
                    TITANLIB_TEST_QS_ALL_EFFECTIVE_POLCIES, 
                    sizeof(TITANLIB_TEST_QS_ALL_EFFECTIVE_POLCIES)-1 ) ) {

       if ( ! strncmp( q, 
                        TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS,
                        sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS)-1 )  ) {

          if ( ! strncmp( q + sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS)-1,
                            TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_3_4, 
                            sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_3_4)-1    )   ) {

             RETURN_INT_ARGS(43,4,3,1,3,4)
         }

          if ( ! strncmp( q + sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS)-1,
                            TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_3, 
                            sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_3)-1    )   ) {

             RETURN_INT_ARGS(43,4,2,1,3)
         }

          if ( ! strncmp( q + sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS)-1,
                            TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_4, 
                            sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_4)-1    )   ) {

             RETURN_INT_ARGS(43,4,2,1,4)
         }

         if ( ! strncmp( q + sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS)-1,
                            TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_5,
                            sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS_1_5)-1    )   ) {

             RETURN_INT_ARGS(43,4,2,1,5)
         }

            RETURN_(INVALID_,INVALID_)
      }

      if ( ! strncmp( q, 
                        TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID, 
                        sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID)-1 )   ) {

         if ( ! strncmp( q + sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID)-1,
                            TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID_2,
                            sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID_2)-1       )   ) {

             RETURN_INT_ARGS(43,4,1,2)
         }

         if ( ! strncmp( q + sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID)-1,
                            TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID_4,
                            sizeof(TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_ID_4)-1       )   ) {

             RETURN_INT_ARGS(43,4,1,4)
         }

         RETURN_(INVALID_,INVALID_)
      }

      if ( ! strncmp( q, 
                        TITAXLIB_QS_T_TOP_POLICIES, 
                        sizeof(TITAXLIB_QS_T_TOP_POLICIES)-1    )   ) {

          RETURN_(41,3)
      }

      RETURN_(42,4)
    }

    RETURN_(INVALID_,INVALID_)
}

static bool mock_TNPQ_TEST_SQL1(PGresult* const restrict rs){
   return add_row__(rs,"1");
}

static bool mock_TNPQ_TEST_SQL2(PGresult* const restrict rs){
   return (add_row__(rs,"XYZ","0") && add_row__(rs,"anonymous","99"));
}

static bool mock_TNPQ_TEST_SQL3(){
   return true;
}

static bool mock_TNPQ_TEST_SQL4(PGresult* const restrict rs){
   if (pctx_==3 && params_){
      return add_row__(rs,params_[0],((params_[1] || params_[2])?"TRUE":"FALSE"));
   }
   return true;
}

static bool mock_TNPQ_TEST_SQL5(PGresult* const restrict rs){
   if (pctx_==2 && params_ && params_[1]){
      return add_row__(rs,params_[0]);
   }
   return true;
}

static bool mock_TITAXLIB_QS_PING(PGresult* const restrict rs){
   return add_row__(rs,"1");
}

static bool mock_TITAXLIB_QS_T_FILTERING(PGresult* const restrict rs){
   return add_row__(rs,"FALSE","NONE","150"
               ,"\nmp3\nwav\nau\naif\nmid\nogg","\nmpg\nmpeg\nasf\navi\nmov\nqt\nram\nrm\nwmv"
               ,"\nexe\nbat\napp\nscr","\ngif\njpg\njpeg\nbmp\ntif\ntiff\npcx\npng"
               ,"\ntxt\n\ndoc\nwri\nxls\nrtf\npdf\ndbs","\nzip\ntar\nbz2\ngz\nrpm\narc\njar\nrar\nlzh\ntgz\niso\ndmg"
               ,"aaa\nbbb\nccc","TRUE","FALSE","FALSE","FALSE",VANULL);
}
/*
static bool mock_TITAXLIB_QS_T_GROUPS_COUNT(PGresult* const rs){
   return add_row__(rs,"2");
}
*/
static bool mock_TITAXLIB_QS_T_GROUPS(PGresult* const restrict rs){
   return (
            add_row__(rs,"1","TRUE","FALSE","Default","1") &&
            add_row__(rs,"2","TRUE","FALSE","Sin bin","2") &&
            add_row__(rs,"3","FALSE","FALSE","TESTG1","5") &&
            add_row__(rs,"4","FALSE","FALSE","TESTG2","1") &&
            add_row__(rs,"5","FALSE","FALSE","TESTG3","5") &&
            add_row__(rs,"6","FALSE","FALSE","TESTG4","1") &&
            add_row__(rs,"7","FALSE","FALSE","TESTG5","5")
         );
}

static bool mock_TITAXLIB_QS_T_POLICIES(PGresult* const restrict rs){
   return (

            add_row__(rs
                     ,"1"
                     ,"TRUE"
                     ,"Default"
                     ,"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
                     ,"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
                     ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                     ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                     ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                     ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                     ,""
                     )
            && add_row__(rs
                        ,"2"
                        ,"TRUE"
                        ,"Deny everything"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,""
                        )
            && add_row__(rs
                        ,"3"
                        ,"TRUE"
                        ,"Allow Everything"
                        ,"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
                        ,"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,""
                        ,""
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,""
                        )
            && add_row__(rs
                        ,"4"
                        ,"TRUE"
                        ,"Sample Corporate Policy"
                        ,"NNNNNNNNNNNNYYYNYYNNNYNNNYNYYYYYNYNNNNYYYNYYNYYYYYNNNYYYYYYYYYYY"
                        ,"NNNYNNNNNYYNYYYNYYNNYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYNYNYYYYYYYYYYY"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,""
                        ,""
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,""
                        )
           
            && add_row__(rs
                        ,"5"
                        ,"FLASE"
                        ,"TESTP"
                        ,"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
                        ,"YYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYYY"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,"NNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNNN"
                        ,""
                        )
           );
}

static bool mock_TITAXLIB_QS_T_POLICYNONWORKINGHOURS(PGresult* const restrict rs){
   return (
               add_row__(rs,"5","1000001","00:00","23:59")
               && add_row__(rs,"5","0111110","12:00","14:00")
               && add_row__(rs,"5","0111110","18:00","23:59")
            );
}

static bool mock_TITAXLIB_QS_T_POLICYFLAGS(PGresult* const restrict rs){
   return (
            add_row__(rs,"1","TRUE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE"
                        ,"100","FALSE","350","FALSE","100","FALSE","FALSE","FALSE","FALSE","TRUE","TRUE","FALSE","FALSE","FALSE",
                        "SAFESEARCH_OFF","0","0","FALSE")
            && add_row__(rs,"2","TRUE","FALSE","TRUE","TRUE","TRUE","TRUE","TRUE","TRUE","TRUE","TRUE","FALSE","FALSE"
                        ,"100","FALSE","350","FALSE","0","TRUE","FALSE","TRUE","TRUE","TRUE","TRUE","TRUE","TRUE","TRUE"
                        ,"SAFESEARCH_OFF","0","0","FALSE")
            && add_row__(rs,"3","TRUE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE"
                        ,"100","FALSE","350","FALSE","0","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE"
                        ,"SAFESEARCH_OFF","0","0","FALSE")
            && add_row__(rs,"4","TRUE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE"
                        ,"100","FALSE","350","FALSE","0","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE"
                        ,"SAFESEARCH_OFF","0","0","FALSE")
            && add_row__(rs,"5","TRUE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE","FALSE"
                        ,"100","FALSE","350","FALSE","100","FALSE","FALSE","FALSE","FALSE","TRUE","TRUE","FALSE","FALSE","FALSE",
                        "SAFESEARCH_OFF","0","0","FALSE")
            );
}

static bool mock_TITAXLIB_QS_T_POLICYNOTIFICATIONS(PGresult* const restrict rs){
   return (
            add_row__(rs,"1","7") &&
            add_row__(rs,"1","8") &&
            add_row__(rs,"1","10") &&
            add_row__(rs,"1","11") &&
            add_row__(rs,"1","12") &&
            add_row__(rs,"1","13") &&
            add_row__(rs,"1","14") &&
            add_row__(rs,"1","16") &&
            add_row__(rs,"1","17") &&
            add_row__(rs,"1","20") &&
            add_row__(rs,"1","21") &&
            add_row__(rs,"5","7") &&
            add_row__(rs,"5","8") &&
            add_row__(rs,"5","10") &&
            add_row__(rs,"5","11") &&
            add_row__(rs,"5","12") &&
            add_row__(rs,"5","13") &&
            add_row__(rs,"5","14") &&
            add_row__(rs,"5","16") &&
            add_row__(rs,"5","17") &&
            add_row__(rs,"5","20") &&
            add_row__(rs,"5","21")
         );
}

static bool mock_TITAXLIB_QS_T_POLICYSAFESEARCH(PGresult* const restrict rs){
   return (
            add_row__(rs,"5","google","ON") &&
            add_row__(rs,"5","yahoo","ON") &&
            add_row__(rs,"5","bing","ON") &&
            add_row__(rs,"1","google","ON") &&
            add_row__(rs,"1","yahoo","ON") &&
            add_row__(rs,"1","bing","ON")
         );
}

static bool mock_TITAXLIB_QS_T_KEYWORDS(PGresult* const restrict rs){
   return (
            add_row__(rs,"xxx","30")
            && add_row__(rs,"adult content","25")
            && add_row__(rs,"adult material","25")
            && add_row__(rs,"adult movie","25")
            && add_row__(rs,"adult only","25")
            && add_row__(rs,"adult oriented","25")
            && add_row__(rs,"adult site","25")
            && add_row__(rs,"adult website","25")
         );
}

static bool mock_TITAXLIB_QS_T_AUTHPOLICY(PGresult* const restrict rs){
   //enable_auth | allow_ip | allow_ldap | allow_kshield | enable_ntlm | allow_wada | ip_session | ip_session_ttl | terminal_server_ip | intercept_login 
   return add_row__(rs,"TRUE","TRUE","FALSE","FALSE","FALSE","FALSE","TRUE","1200","10.1.0.1,10.1.0.2","FALSE");
}

static bool mock_TITAXLIB_QS_T_NETWORKING(PGresult* const restrict rs){
   return add_row__(rs,VANULL,"5","wt-513-435","example.com","10.1.8.8","TRUE",VANULL);
}

static bool mock_TITAXLIB_QS_T_CACHE(PGresult* const restrict rs){
   return add_row__(rs,"8888");
}

static bool mock_TITAXLIB_QS_T_URLCATEGORIES_1(PGresult* const restrict rs){
   return (
               add_row__(rs,"0","Compromised")
               && add_row__(rs,"1","Criminal Skills/Hacking")
               && add_row__(rs,"2","Hate Speech")
               && add_row__(rs,"3","Illegal Drugs")
               && add_row__(rs,"4","Phishing/Fraud")
               && add_row__(rs,"5","Spyware and Malicious Sites")
               && add_row__(rs,"6","Nudity")
               && add_row__(rs,"7","Mature")
               && add_row__(rs,"8","Pornography/Sex")
               && add_row__(rs,"9","Violence")
               && add_row__(rs,"10","Weapons")
               && add_row__(rs,"11","Anonymizer")
               && add_row__(rs,"12","Computers and Technology")
               && add_row__(rs,"13","Download Sites")
               && add_row__(rs,"14","Translator")
               && add_row__(rs,"15","Alcohol")
               && add_row__(rs,"16","Health")
               && add_row__(rs,"17","Pharmacy")
               && add_row__(rs,"18","Tobacco")
               && add_row__(rs,"19","Gambling")
               && add_row__(rs,"20","Games")
               && add_row__(rs,"21","Cars/Transportation")
               && add_row__(rs,"22","Dating")
               && add_row__(rs,"23","Home/Leisure")
               && add_row__(rs,"24","Personal Webpages")
               && add_row__(rs,"25","Restaurants")
               && add_row__(rs,"26","Sports and Recreation")
               && add_row__(rs,"27","Travel")
               && add_row__(rs,"28","Government")
               && add_row__(rs,"29","Military")
               && add_row__(rs,"30","Non-profits")
               && add_row__(rs,"31","Politics and Law")
               && add_row__(rs,"32","Religion")
               && add_row__(rs,"33","Education")
               && add_row__(rs,"34","Art")
               && add_row__(rs,"35","Entertainment and Videos")
               && add_row__(rs,"36","Humor")
               && add_row__(rs,"37","Music")
               && add_row__(rs,"38","News")
               && add_row__(rs,"39","Finance")
               && add_row__(rs,"41","Shopping")
               && add_row__(rs,"42","Chat/IM")
               && add_row__(rs,"43","Community Sites")
               && add_row__(rs,"44","Social Networking")
               && add_row__(rs,"45","Web-based Email")
               && add_row__(rs,"46","Portal Sites")
               && add_row__(rs,"47","Search Engines")
               && add_row__(rs,"48","Online Ads")
               && add_row__(rs,"49","Business/Services")
               && add_row__(rs,"50","Job Search")
               && add_row__(rs,"51","Real Estate")
               && add_row__(rs,"52","Spam")
               && add_row__(rs,"53","Miscellaneous")
          );
}

static bool mock_TITAXLIB_QS_T_URLCATEGORIES_2(){
   return true; //no records
}

static bool mock_TITAXLIB_QS_T_REDIRECTIONS(PGresult* const restrict rs){
   return (
               add_row__(rs,"src.domain","dst.domain")
               && add_row__(rs,"https://www.src.domain","http://10.1.1.2")
               && add_row__(rs,"https://10.1.1.1","10.1.1.2")
           );
}

static bool mock_TITAXLIB_QS_T_KEYWORD_POLICIES_AUTH(PGresult* const restrict rs) {

    return (    add_row__(rs, "TRUE", "f", "keywordX")
                && add_row__(rs,"FALSE", "f", "Xkeyword")
                && add_row__(rs,"FALSE", "t", "www.keywordsX.ie")
                && add_row__(rs, "TRUE", "t", "www.keywordsX.com/watch?v=abcd")
                && add_row__(rs,"FALSE", "f", "Xstring keyword-X")
                && add_row__(rs, "TRUE", "f", "stringX keyword_X")
                && add_row__(rs, "TRUE", "f", "keywordA")
            );
}

static bool mock_TITAXLIB_QS_T_KEYWORD_POLICIES_FILTER(PGresult* const restrict rs) {

    return (    add_row__(rs, "TRUE", "f", "keywordY")
                && add_row__(rs,"FALSE", "f", "Ykeyword")
                && add_row__(rs,"FALSE", "t", "www.keywordsY.ie")
                && add_row__(rs, "TRUE", "t", "www.keywordsY.com/watch?v=efgh")
                && add_row__(rs,"FALSE", "f", "Ystring keyword-Y")
                && add_row__(rs, "TRUE", "f", "stringY keyword_Y")
                && add_row__(rs, "TRUE", "f", "keywordA")
            );
}

static bool mock_TITAXLIB_QS_T_KEYWORD_POLICIES_BLOCK(PGresult* const restrict rs) {

   return (     add_row__(rs, "TRUE", "f", "keywordZ")
                && add_row__(rs,"FALSE", "f", "Zkeyword")
                && add_row__(rs,"FALSE", "t", "www.keywordsZ.ie")
                && add_row__(rs, "TRUE", "t", "www.keywordsZ.com/watch?v=ijkl")
                && add_row__(rs,"FALSE", "f", "Zstring keyword-Z")
                && add_row__(rs, "TRUE", "f", "stringZ keyword_Z")
           );
}

static bool mock_TITAXLIB_QS_F_USERS_LIST_TYPE(PGresult* const restrict rs){
   return add_row__(rs,"0");
}

static bool mock_TITAXLIB_QS_V_USERS(PGresult* const restrict rs){
   return (
      add_row__(rs,"1","admin","Root User"                               , VANULL,"21232f297a57a5a743894a0e4a801fc3" ,"0", VANULL  ,"TMP-0-8697-FR5DCSXT8OAY" , VANULL                                    ,"t") &&
      add_row__(rs,"2","test1","test1 tester1"                          , VANULL,"5a105e8b9d40e1329780d62ea2265d8a" ,"0", "1"   ,VANULL                      , VANULL                                    ,"f") &&
      add_row__(rs,"3","test2","test2 tester2"                          , VANULL,"36e0f90bcda4bd0173898e345355aef4" ,"0", "1"   ,VANULL                      , "36de174f-b688-46c8-bbb4-62bbb22114f4"  ,"f") &&
      add_row__(rs,"4","test3","test3 tester3"                          , VANULL,"4cfad7076129962ee70c36839a1e3e15" ,"0", "1"   ,VANULL                      , "225d8a21-9bfc-47d0-9e8d-fc7f128747ed"  ,"f") &&
      add_row__(rs,"5","logonname","Firstname Lastname"                 , VANULL,"0a89ab1973994e105cb08bb8a6244740" ,"0", "1"   ,VANULL                      , "eeb1c121-ae55-4933-8c45-b688431f4e4f"  ,"f") &&
      add_row__(rs,"6",u8"jäck",u8"SchöneGrüße"                         , VANULL,"35ac8520a37dd54f43b03480d169ceac" ,"1", "1"   ,VANULL                      , "16b9b91a-a873-49bc-bba8-c4bf37c803f9"  ,"f") &&
      add_row__(rs,"7",u8"oŚĆ",u8"złośćmniębiĘŻĘnaśmięrdząćychlęŃÓchów" , VANULL,"800bdc3888f2b9797e776262731e0a0e" ,"3", "1"   ,VANULL                      , "ce4f96fd-e5b6-4d7c-acd3-2d43abfda0a6"  ,"f") &&
      add_row__(rs,"8",u8"\xD0\x90\xD0\x91\xD0\x92",u8"\xD0\x90\xD0\x91\xD0\x92\xD0\x93\xD2\x90\xD0\x94\xD0\x82\xD0\x83\xD0\x95\xD0\x80\xD0\x81\xD0\x84\xD0\x96\xD0\x97\xD0\x97\xCC\x81\xD0\x85\xD0\x98\xD0\x8D\xD0\x86\xD0\x87\xD0\x99\xD0\x88\xD0\x9A\xD0\x9B\xD0\x89\xD0\x9C\xD0\x9D\xD0\x8A",VANULL,"23497e367aca7bf92a14fb27c35f9b85","0", "1",VANULL, "d7d5a9fe-1739-405e-9ecd-02b1164ac73c","f")
   );
}

static bool mock_TITAXLIB_QS_T_USERGROUPS_DISPLAY(PGresult* const restrict rs){
   return (
            add_row__(rs,"3","1") &&
            add_row__(rs,"3","4") &&
            add_row__(rs,"3","6") &&
            add_row__(rs,"4","2") &&
            add_row__(rs,"5","4") &&
            add_row__(rs,"5","6") &&
            add_row__(rs,"6","3") &&
            add_row__(rs,"6","5") &&
            add_row__(rs,"6","7") &&
            add_row__(rs,"8","4") &&
            add_row__(rs,"8","5") &&
            add_row__(rs,"8","6") &&
            add_row__(rs,"8","7")
           );
}

static bool mock_TITAXLIB_QS_T_USERGROUPS_EFFECTIVE(PGresult* const restrict rs){
   return (
            add_row__(rs,"3","6","1") &&
            add_row__(rs,"4","2","2") &&
            add_row__(rs,"5","6","1") &&
            add_row__(rs,"6","7","5") &&
            add_row__(rs,"7","7","5") &&
            add_row__(rs,"8","6","1") &&
            add_row__(rs,"8","7","5")
           );
}

static bool mock_TITAXLIB_QS_V_LOCATIONS(PGresult* const restrict rs){
   return (
            add_row__(rs,"7","2",VANULL,"8.0.0.0","8.255.255.255","0",VANULL,"1") &&
            add_row__(rs,"6","1","6.6.6.6",VANULL,VANULL,"0",VANULL,"2")
         );
}

static bool mock_TITAXLIB_QS_V_USERS_CKEY_COUNTS(PGresult* const restrict rs){
   return (
            add_row__(rs,"1","0") &&
            add_row__(rs,"2","0") &&
            add_row__(rs,"3","0") &&
            add_row__(rs,"4","0") &&
            add_row__(rs,"5","0") &&
            add_row__(rs,"6","1") &&
            add_row__(rs,"7","3") &&
            add_row__(rs,"8","0") 
         );
}

static bool mock_TITAXLIB_QS_V_ACTIVE_USED_BYPASS_TOKENS_SHORT(PGresult* const restrict rs){
   return (
            add_row__(rs,"7","alabama","2e57b9077d6927d0ce3a42f88aa9b200") &&
            add_row__(rs,"7","token1","78b1e6d775cec5260001af137a79dbd5")
         );
}

static bool mock_TITAXLIB_QS_T_USERS_BANDWIDTH(PGresult* const restrict rs){
   return (
            add_row__(rs,"6","0") &&
            add_row__(rs,"7","8888") &&
            add_row__(rs,"8","101")
         );
}

static bool mock_TITAXLIB_QS_T_UPDATE_TIMES(PGresult* const  restrict rs){
   return (
            add_row__(rs,"backup","20380119031407") &&
            add_row__(rs,"exports","20380119031407") &&
            add_row__(rs,"keywords","20380119031407") &&
            add_row__(rs,"keyword_policies","20380119031407") &&
            add_row__(rs,"policydns","20380119031407") &&
            add_row__(rs,"authpolicy","20380119031407") &&
            add_row__(rs,"snmp","20380119031407") &&
            add_row__(rs,"cache","20380119031407") &&
            add_row__(rs,"policynonworkinghours","20380119031407") &&
            add_row__(rs,"urlcategories","20380119031407") &&
            add_row__(rs,"networking","20380119031407") &&
            add_row__(rs,"datetime","20380119031407") &&
            add_row__(rs,"groups","20380119031407") &&
            add_row__(rs,"policyflags","20380119031407") &&
            add_row__(rs,"policysafesearch","20380119031407") &&
            add_row__(rs,"domain_policies","20380119031407") &&
            add_row__(rs,"policies","20380119031407") &&
            add_row__(rs,"redirections","20380119031407") &&
            add_row__(rs,"filtering","20380119031407") &&
            add_row__(rs,"policynotifications","20380119031407") &&
            add_row__(rs,"bypass_tokens","20380119031407") &&
            add_row__(rs,"reportscheduling","20380119031407") &&
            add_row__(rs,"users","20380119031407") &&
            add_row__(rs,"usergroups","20380119031407") &&
            add_row__(rs,"usersbandwidth","20380119031407") &&
            add_row__(rs,"userlogins","20380119031407")
         );
}

static bool mock_TITAXLIB_QS_V_DP_FLAGS(PGresult* const restrict rs){
   return (
            add_row__(rs,"8",".policy_white_filters.com","5","5") &&
            add_row__(rs,"9",".policy_block_all.com","5","9") &&
            add_row__(rs,"4",".white_auth.com","-1","3") &&
            add_row__(rs,"5",".white_filters.com","-1","5") &&
            add_row__(rs,"6",".white_all.com","-1","7") &&
            add_row__(rs,"7",".block_all.com","-1","9") &&
            add_row__(rs,"1",".microsoft.com","-1","7") &&
            add_row__(rs,"3",".msftncsi.com","-1","7") &&
            add_row__(rs,"2",".windowsupdate.com","-1","7")
          );
}

static bool mock_TITAXLIB_QS_T_LDAPSERVERS_DOMAINS(){
   return true;//no records
}

static bool mock_TITAXLIB_QS_V_TOP_USERS(PGresult* const restrict rs){
    return (add_row__(rs,"1","admin","Root User", VANULL,"21232f297a57a5a743894a0e4a801fc3" ,"0", VANULL,"TMP-0-8697-FR5DCSXT8OAY" , VANULL,"t"));
}

static bool mock_TITAXLIB_QS_T_TOP_POLICIES(PGresult* const restrict rs){
    return (add_row__(rs,"1","1", "1"));
}


static bool mock_TITANLIB_TEST_QS_ALL_EFFECTIVE_POLCIES(PGresult* const restrict rs)
{
    /* user 1: no groups only policy */
    add_row__( rs, "1", VANULL, "1", "f" );

    char sbuf[32]={};

    /* user 2: single policy & groups beyond the redline */
    for ( uint32_t i=FIRST_NON_BUILDIN_GROUP_ID; i<MAX_TITAX_GROUP_POLICY+10; ++i ){

        if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

            add_row__( rs, "2", sbuf, "1", "f" );
        }
    }

    /* user 3 : 3 policies policies & groups beyond the redline */
    for ( uint32_t i=FIRST_NON_BUILDIN_GROUP_ID; i< (MAX_TITAX_GROUP_POLICY>>1) ; ++i ){

        if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

            add_row__( rs, "3", sbuf, "1", "f" );
        }
    }

    for ( uint32_t i=(MAX_TITAX_GROUP_POLICY>>1); i<MAX_TITAX_GROUP_POLICY+1 ; ++i ){

        if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

            add_row__( rs, "3", sbuf, "2", "f" );
        }
    }

    for ( uint32_t i=MAX_TITAX_GROUP_POLICY+1; i<MAX_TITAX_GROUP_POLICY+30 ; ++i ){

        if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

            add_row__( rs, "3", sbuf, "3", "f" );
        }
    }

    /* user 4 : 1 policy & 10 groups & inherited true */
    for ( uint32_t i=DEFAULT_GROUP_NUM; i< (MAX_TITAX_GROUP_POLICY>>1) ; ++i ){

        if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

            add_row__( rs, "4", sbuf, "1", "t" );
        }
    }

    return true;
}

static bool mock_TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS(    PGresult* const restrict rs, 
                                                                const size_t ids_sz, 
                                                                int * const restrict ids    )
{   /* user_id, group_id, policy_id, inherited */

    if ( ids_sz && ids ) {

        char sbuf[32]={};

        if ( ids_sz == 1  ) {
  
            switch ( *ids ) {

                case 2: {

                    /* user 2: single policy & groups beyond the redline */
                    for ( uint32_t i=1; i<MAX_TITAX_GROUP_POLICY+10; ++i ){

                        if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                            add_row__( rs, "2", sbuf, "1", "f" );
                        }
                    }

                    return true;
                }

                case 4: {

                    /* user 4 : 1 policy & 64 groups & inherited true */
                    for ( uint32_t i=1; i< (MAX_TITAX_GROUP_POLICY>>1) ; ++i ){

                        if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                            add_row__( rs, "4", sbuf, "1", "t" );
                        }
                    }

                    return true;
                }

                default: break;
            }

            return false;
        }

        if ( ids_sz == 2 ) {

            if ( ids[0] == 1 && ids[1] == 3 ) {

                /* parent */
                add_row__( rs, "1", VANULL, "1", "f" );


                /* child */
                for ( uint32_t i=1; i< (MAX_TITAX_GROUP_POLICY>>1) ; ++i ){

                    if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                        add_row__( rs, "3" , sbuf, "1", "f" );
                    }
                }

                for ( uint32_t i=(MAX_TITAX_GROUP_POLICY>>1); i<MAX_TITAX_GROUP_POLICY+1 ; ++i ){

                    if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                        add_row__( rs, "3", sbuf, "2", "f" );
                    }
                }

                for ( uint32_t i=MAX_TITAX_GROUP_POLICY+1; i<MAX_TITAX_GROUP_POLICY+30 ; ++i ){

                    if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                        add_row__( rs, "3" , sbuf, "3", "f" );
                    }
                }

                return true;
            }

            if ( ids[0] == 1 && ids[1] == 4 ) {

                /* parent */
                add_row__( rs, "1", VANULL, "1", "f" );

                /* user 4 : 1 policy & 64 groups & inherited true */
                for ( uint32_t i=1; i< (MAX_TITAX_GROUP_POLICY>>1) ; ++i ){

                    if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                        add_row__( rs, "4", sbuf, "1", "t" );
                    }
                }

                return true;
            }

            if ( ids[0] == 1 && ids[1] == 5 ) {

                /* parent */
                add_row__( rs, "1", VANULL, "1", "f" );
                add_row__( rs, "5", "2", "1", "f" );
                add_row__( rs, "5", "3", "2", "f" );
                add_row__( rs, "5", "4", "1", "f" );
                add_row__( rs, "5", "5", "2", "f" );
                add_row__( rs, "5", "6", "1", "f" );
                add_row__( rs, "5", "7", "2", "f" );

                return true;
            }
        }

        if ( ids_sz == 3 ) {

            if ( ids[0] == 1 && ids[1] == 3 &&  ids[2] == 4 ) {

                /* parent */
                add_row__( rs, "1", VANULL, "1", "f" );

                /* child 3 */
                for ( uint32_t i=1; i< (MAX_TITAX_GROUP_POLICY>>1) ; ++i ){

                    if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {
                        
                        add_row__( rs, "3" , sbuf, "1", "f" );
                    }
                }

                for ( uint32_t i=(MAX_TITAX_GROUP_POLICY>>1); i<MAX_TITAX_GROUP_POLICY+1 ; ++i ){

                    if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                        add_row__( rs, "3", sbuf, "2", "f" );
                    }
                }

                for ( uint32_t i=MAX_TITAX_GROUP_POLICY+1; i<MAX_TITAX_GROUP_POLICY+30 ; ++i ){

                    if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                        add_row__( rs, "3" , sbuf, "3", "f" );
                    }
                }

                /* child 4 : 1 policy & 64 groups & inherited true */
                for ( uint32_t i=1; i< (MAX_TITAX_GROUP_POLICY>>1) ; ++i ){

                    if ( tx_safe_snprintf(sbuf,sizeof(sbuf),"%u",i) ) {

                        add_row__( rs, "4", sbuf, "1", "t" );
                    }
                }

                return true;
            }
        }
    }

    return false;
}

static PGresult* mock_query_(const char * const restrict q)
{
   t_qtype qr={};
   scan_query(q,&qr);
   if (INVALID_<qr.ctx && INVALID_<qr.id){

      PGresult* const rs=alloc_columns_(qr.ctx);
      switch (qr.id){
         case 0: if (mock_TNPQ_TEST_SQL1(rs)) return rs; break;
         case 1: if (mock_TNPQ_TEST_SQL2(rs)) return rs; break;
         case 2: if (mock_TNPQ_TEST_SQL3()) return rs; break;
         case 3: if (mock_TNPQ_TEST_SQL4(rs)) return rs; break;
         case 4: if (mock_TNPQ_TEST_SQL5(rs)) return rs; break;
         case 10: if (mock_TITAXLIB_QS_PING(rs)) return rs; break;
         case 11: if (mock_TITAXLIB_QS_T_FILTERING(rs)) return rs; break;
         case 13: if (mock_TITAXLIB_QS_T_GROUPS(rs)) return rs; break;
         case 14: if (mock_TITAXLIB_QS_T_POLICIES(rs)) return rs; break;
         case 15: if (mock_TITAXLIB_QS_T_POLICYNONWORKINGHOURS(rs)) return rs; break;
         case 16: if (mock_TITAXLIB_QS_T_POLICYFLAGS(rs)) return rs; break;
         case 17: if (mock_TITAXLIB_QS_T_POLICYNOTIFICATIONS(rs)) return rs; break;
         case 18: if (mock_TITAXLIB_QS_T_POLICYSAFESEARCH(rs)) return rs; break;
         case 19: if (mock_TITAXLIB_QS_T_KEYWORDS(rs)) return rs; break;
         case 20: if (mock_TITAXLIB_QS_T_AUTHPOLICY(rs)) return rs; break;
         case 21: if (mock_TITAXLIB_QS_T_NETWORKING(rs)) return rs; break;
         case 22: if (mock_TITAXLIB_QS_T_CACHE(rs)) return rs; break;
         case 23: if (mock_TITAXLIB_QS_T_URLCATEGORIES_1(rs)) return rs; break;
         case 24: if (mock_TITAXLIB_QS_T_URLCATEGORIES_2()) return rs; break;
         case 25: if (mock_TITAXLIB_QS_T_REDIRECTIONS(rs)) return rs; break;
         case 26: if (mock_TITAXLIB_QS_T_KEYWORD_POLICIES_AUTH(rs)) return rs; break;
         case 27: if (mock_TITAXLIB_QS_T_KEYWORD_POLICIES_FILTER(rs)) return rs; break;
         case 28: if (mock_TITAXLIB_QS_T_KEYWORD_POLICIES_BLOCK(rs)) return rs; break;
         case 29: if (mock_TITAXLIB_QS_F_USERS_LIST_TYPE(rs)) return rs; break;
         case 30: if (mock_TITAXLIB_QS_V_USERS(rs)) return rs; break;
         case 31: if (mock_TITAXLIB_QS_T_USERGROUPS_DISPLAY(rs)) return rs; break;
         case 32: if (mock_TITAXLIB_QS_T_USERGROUPS_EFFECTIVE(rs)) return rs; break;
         case 33: if (mock_TITAXLIB_QS_V_LOCATIONS(rs)) return rs; break;
         case 34: if (mock_TITAXLIB_QS_V_USERS_CKEY_COUNTS(rs)) return rs; break;
         case 35: if (mock_TITAXLIB_QS_V_ACTIVE_USED_BYPASS_TOKENS_SHORT(rs)) return rs; break;
         case 36: if (mock_TITAXLIB_QS_T_USERS_BANDWIDTH(rs)) return rs; break;
         case 37: if (mock_TITAXLIB_QS_T_UPDATE_TIMES(rs)) return rs; break;
         case 38: if (mock_TITAXLIB_QS_V_DP_FLAGS(rs)) return rs; break;
         case 39: if (mock_TITAXLIB_QS_T_LDAPSERVERS_DOMAINS()) return rs; break;
         case 40: if (mock_TITAXLIB_QS_V_TOP_USERS(rs)) return rs; break;
         case 41: if (mock_TITAXLIB_QS_T_TOP_POLICIES(rs)) return rs; break;
         case 42: if (mock_TITANLIB_TEST_QS_ALL_EFFECTIVE_POLCIES(rs)) return rs; break;
         case 43: {
            const bool is_ok = (    qr.args_sz                                                      && 

                                    qr.args                                                         && 

                                    mock_TITANLIB_TEST_QS_EFFECTIVE_POLCIES_FOR_IDS(    rs,
                                                                                        qr.args_sz, 
                                                                                        qr.args     )   );
            if ( qr.args ) {

                free(qr.args);
            }

            if ( is_ok ) {

                return rs;
            }

         } break;
      }

      if ( rs ) {
        free(rs);
      }
   }

   return NULL;
}

#endif
//------------------------------------------------------------------------------

////////////////////////////////////////////////////////////////////////////////
/**
 * Diagnostic Instrumentation 
 * TODO: consider use of macros 
 */

static unsigned int g_PGresult_instances_c = 0;
static unsigned int g_PGresult_instances_d = 0;
unsigned int get_PGresult_active_instances()
{
    return ( g_PGresult_instances_c - g_PGresult_instances_d );
}
////////////////////////////////////////////////////////////////////////////////

TX_INTERNAL_INLINE 
PGresult* pq_get_rset_no_error_(PGconn* const  db, const char* const q){
   if (db && q){
#ifndef TTN_ATESTS
      return PQexec(db, q);
#else
   /* mock */
      pctx_=0;
      params_=0;
      return mock_query_(q);
#endif
   }
   return NULL;
}

TX_INTERNAL_INLINE 
void txpq_reset_(PGresult *const  res){
   PQclear(res);
   /* DI */
   g_PGresult_instances_d++;
}

TX_INTERNAL_INLINE 
size_t txpq_row_count_(PGresult *const  res){
   int r_=0;
   if (res && (r_=PQntuples(res))>0 ){
      return (size_t)r_;
   }
   return 0;
}

TX_INTERNAL_INLINE
PGresult* pq_get_rset_(PGconn* const db, const char* const q){
   PGresult* const rset = pq_get_rset_no_error_(db, q);
   if (rset){
         const ExecStatusType stat=PQresultStatus(rset);
         if (stat==PGRES_COMMAND_OK || stat==PGRES_TUPLES_OK){
            /* DI */
            g_PGresult_instances_c++;
            return rset;
         }
         #ifndef TTN_ATESTS
         fprintf(stderr, "DB query error: %s, %s\n", PQerrorMessage(db), q);
         #endif
         txpq_reset_(rset);
   } 
   else {

      #ifndef TTN_ATESTS
      fprintf(stderr, "DB query error: %s, %s\n", PQerrorMessage(db), q);
      #endif
   }

   return NULL;
}

TX_INTERNAL_INLINE
char * txpq_cv_str_(const PGresult * const pR,const  size_t pRN, const  size_t pCN){
#ifndef TTN_ATESTS
   return (!PQgetisnull(pR, (int)pRN, (int)pCN)?PQgetvalue(pR, (int)pRN, (int)pCN):NULL);
#else
   return PQgetvalue(pR, (int)pRN,(int) pCN);
#endif
}

TX_INTERNAL_INLINE
int txpq_cv_int_(const PGresult * const pR,const size_t pRN,const  size_t pCN){
   int r=0;
   return (tx_safe_atoi(txpq_cv_str_(pR, pRN, pCN),&r)?r:0);
}

TX_INTERNAL_INLINE
bool pq_conn_isactive_(const PGconn* const db){
#ifndef TTN_ATESTS
   if (db && PQstatus(db) == CONNECTION_OK) return true;
   const char * const msg=(db?PQerrorMessage(db):"<NULL>");
   fprintf(stderr, "DB error: %s", ((msg && msg[0])?msg:"closed"));
   return false;
#else
   #if ( ! defined ( __clang_analyzer__ ) ) 
   if(db  && (int)db->status==1024){
      return true;
   }
   #endif
   return false;
#endif
}

TX_INTERNAL_INLINE
int pq_get_int_(PGconn* const  db, const char* const  q){
   PGresult* const rset = pq_get_rset_(db, q);
   if (rset){
      if (txpq_row_count_(rset)){
         const int r=txpq_cv_int_(rset, 0, 0);
         txpq_reset_(rset);
         return r;
      }
      txpq_reset_(rset);
   }
   return 0;
}

//------------------------------------------------------------------------------
bool pq_conn_isactive(const PGconn* const restrict db){
   return pq_conn_isactive_(db);
}

//------------------------------------------------------------------------------
bool pq_conn_close(PGconn* const restrict db){
#ifndef TTN_ATESTS
   if(db) PQfinish(db);
   return true;
#else
   #if ( ! defined ( __clang_analyzer__ ) ) 
   if(db  && (int)db->status==1024){
      db->status=0;
      tx_safe_free(db);
      return true;
   }
   #endif
   return false;
#endif
}

//------------------------------------------------------------------------------
PGconn* pq_conn(const char* const restrict cinfo){
#ifndef TTN_ATESTS
   PGconn* const db = PQconnectdb(cinfo);
   if (db){
      if (pq_conn_isactive_(db)) return db;
      pq_conn_close(db);
   }
   return (NULL);
#else
   #if ( ! defined ( __clang_analyzer__ ) ) 
   if (!strcmp(cinfo,TNPQ_TEST_CONSTR)){
      PGconn * const conn = (PGconn *)tx_safe_malloc(sizeof(PGconn));
      conn->status=(ConnStatusType)1024;
      return (conn);
   }
   #endif
   return (NULL);
#endif
}

//------------------------------------------------------------------------------
bool pq_conn_reset(PGconn* const restrict db){
#ifndef TTN_ATESTS
   if (db){
      PQreset(db);
      return pq_conn_isactive_(db);
   }
   return false;
#else 
   return pq_conn_isactive_(db);
#endif
}

//------------------------------------------------------------------------------
PGresult* pq_get_rset_with_params(  PGconn* const restrict db, 
                                    const char* const restrict q,
                                    const int pctx,
                                    const char *const * restrict params ){
   if (db && q){

   #ifndef TTN_ATESTS

      return ( PQexecParams(    db,
                                q,
                                pctx,
                                NULL,
                                params,
                                NULL,
                                NULL,
                                0       ) );
   #else

      /* mock */
      pctx_=pctx;
      params_=params;
      PGresult* const r_=mock_query_(q);
      pctx_=0;
      params_=0;
      return (r_);

   #endif

   }
   return (NULL);
}

//------------------------------------------------------------------------------
PGresult* pq_get_rset(PGconn* const restrict db, const char* const restrict q){
   return pq_get_rset_(db,q);
}

//------------------------------------------------------------------------------
PGresult* pq_get_rset_no_error(PGconn* const restrict db, const char* const restrict q){
   return (pq_get_rset_no_error_(db, q));
}

//------------------------------------------------------------------------------
bool pq_do(PGconn* const restrict db, const char* const restrict q){
   PGresult* const rset = pq_get_rset_(db, q);
   const bool res = (rset!=NULL);
   txpq_reset_(rset);
   return res;
}

//------------------------------------------------------------------------------
size_t txpq_row_count(PGresult *const restrict res){
   return txpq_row_count_(res);
}

//------------------------------------------------------------------------------

bool txpq_is_row_in_rset( PGresult *const restrict res, const size_t rn )
{
   return UWITHIN_( txpq_row_count_(res), rn ) ;
}

//------------------------------------------------------------------------------
void txpq_reset(PGresult *const restrict res){
   txpq_reset_(res);
}

//------------------------------------------------------------------------------
int pq_get_int(PGconn* const restrict  db, const char* const restrict  q){
   return pq_get_int_(db,q);
}

//------------------------------------------------------------------------------
unsigned long pq_get_ulong(PGconn* const restrict db, const char* const restrict q){
   unsigned long r=0;
   PGresult* const rset = pq_get_rset_(db, q);
   if (rset){
      if (txpq_row_count_(rset)>0 && tx_safe_atoul(txpq_cv_str_(rset, 0, 0),&r)){
         txpq_reset(rset);
         return r;
      }
      txpq_reset(rset);
   }
   return 0;
}

//------------------------------------------------------------------------------
bool pq_is_alive(PGconn* const restrict db){
   #ifndef TTN_ATESTS
      return (pq_conn_isactive_(db) && pq_get_int_(db, TITAXLIB_QS_PING) == 1);
   #else
      return pq_conn_isactive_(db);
   #endif
}

//------------------------------------------------------------------------------
char * txpq_cv_str(const PGresult * const restrict pR,const  size_t pRN, const  size_t pCN){
   return txpq_cv_str_(pR,pRN,pCN);
}

//------------------------------------------------------------------------------
bool txpq_cv_bool(const PGresult * const restrict pR,const size_t pRN, const size_t pCN){
   const char * const s_=txpq_cv_str_(pR, pRN, pCN);
   return (s_ && s_[0] && (s_[0]=='T' || s_[0]=='t'));
}

//------------------------------------------------------------------------------
int txpq_cv_int(const PGresult * const restrict pR,const size_t pRN,const  size_t pCN){
   return txpq_cv_int_(pR, pRN, pCN);
}

//------------------------------------------------------------------------------
unsigned int txpq_cv_uint(const PGresult * const restrict pR,const size_t pRN,const  size_t pCN){
   unsigned int r=0;
   return (tx_safe_atoui(txpq_cv_str_(pR, pRN, pCN),&r)?r:0);
}

//------------------------------------------------------------------------------
long txpq_cv_long(const PGresult * const restrict pR,const  size_t pRN, const  size_t pCN){
   long r=0;
   return (tx_safe_atol(txpq_cv_str_(pR, pRN, pCN),&r)?r:0);
}

//------------------------------------------------------------------------------
unsigned long txpq_cv_ulong(const PGresult * const restrict pR,const  size_t pRN, const  size_t pCN){
   unsigned long r=0;
   return (tx_safe_atoul(txpq_cv_str_(pR, pRN, pCN),&r)?r:0);
}

//------------------------------------------------------------------------------
long long  txpq_cv_longlong(const PGresult *const restrict pR,const  size_t pRN, const  size_t pCN){
   long long r=0;
   return (tx_safe_atoll(txpq_cv_str_(pR, pRN, pCN),&r)?r:0);
}

//------------------------------------------------------------------------------
bool txpq_is_null( const PGresult * const restrict rs_ , const size_t r_ , const  size_t c_ ) 
{
   return PQgetisnull( rs_, (int)r_, (int)c_ );
}


//------------------------------------------------------------------------------

bool check_raw_dbconn(PGconn** db_conn, const size_t max_tries,db_connect_t reconnect){
   const int tid = pthread_getthreadid_np();  
   if (db_conn && max_tries && reconnect){
      size_t tries=0;
      while ( max_tries > tries++ ){

        if (    !(*db_conn)                 &&  

                !((*db_conn) = reconnect())     ){

                titax_log(  LOG_ERROR,
                            "%s:%s:%d::@%d:DB::unable to connect, (%zu/%zu) waiting for %d sec\n",
                            __FILE__,
                            __func__,
                            __LINE__,
                            tid,
                            tries,
                            max_tries,
                            DEF_DB_CON_TTL  );

                (void)sleep(DEF_DB_CON_TTL);
                continue;
        }

        if (    !pq_is_alive((*db_conn))    && 

                !pq_conn_reset((*db_conn))      ){


            /* potentially it is an invalid conn ptr */
            titax_log(  LOG_ERROR,
                        "%s:%s:%d::th:%d:DB::unable to reset [%s], (%zu/%zu) waiting for %d sec\n",
                        __FILE__,
                        __func__,
                        __LINE__,
                        tid,
                        (   (*db_conn)                  ?
                            PQerrorMessage((*db_conn))  :
                            "<INVALID>"                     ),
                        tries,
                        max_tries,
                        DEF_DB_CON_TTL  );


            if ( (*db_conn) )
                pq_conn_close((*db_conn));

            (*db_conn)=NULL;
            (void)sleep(DEF_DB_CON_TTL);
            continue;
        }

        return (NULL!=(*db_conn));
      }
   }
   return false;
}
char * txpq_escape_literal(   PGconn* const restrict conn,
                              const char * const restrict in_str,
                              const size_t in_str_sz                 ){

   if (  conn        &&
         in_str      &&
         in_str_sz   ){

            return PQescapeLiteral(conn, in_str, in_str_sz);
   }

   return NULL;

}

void txpq_free(char * p){

   if (p)
      PQfreemem(p);
}

bool txpq_is_field_null(   const PGresult * const restrict rs,
                           const  size_t rn, 
                           const  size_t fn                    ){

   return PQgetisnull(rs,(int)rn,(int)fn);
}

/* vim: set ts=4 sw=4 et : */

