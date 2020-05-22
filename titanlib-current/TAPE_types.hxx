/**
 * $Id$
 */

#ifndef TAPE_TYPES_HXX
#define TAPE_TYPES_HXX

#include "TAPE.h"
#include <unordered_set>

namespace titan_v3
{
    using namespace cidr;

    constexpr const char DEFAULT_COOKIE_DELIM[] = "; ";

    // macro to generate the index into the ss_policy array
    // don't change this to true and falso it may looke like
    // it should be but its an index.

    namespace safe_search
    {
        #ifndef SS_INDEX
            #define SS_INDEX(engine)   ( ( sse_grp_moderate & engine ) ? 1 : 0 )
        #endif

        namespace google
        {
            constexpr const char signature[]                = "google.";

            constexpr const char key[]                      = "safe=";

            constexpr const char val[]                      = "active";

            constexpr const char video[]                    = "video.";

            constexpr const char trends[]                   = "trends.";
        }

        namespace youtube
        {
            constexpr const char signature[]                = "nocookie.";

            extern const std::unordered_set<std::string>    signatures;

            constexpr const char * const header_values[2] { "Strict", 
                                                            "Moderate"  };

            constexpr const char key[]                      = "PREF";

            constexpr const char sub_key[]                  = "f2";

            constexpr const char sub_val[]                  = "8000000";

            constexpr const char sub_key_val[]              = "f2=8000000";

            constexpr const char key_sub_key_val[]          = "PREF=f2=8000000";
        }

        namespace yahoo
        {
            constexpr const char signature[]                = "yahoo.";

            constexpr const char key[]                      = "vm";

            constexpr const char * const val[2]             { "r", "i" };
        }

        namespace bing
        {
            constexpr const char signature[]                = "bing.";

            constexpr const char key[]                      = "SRCHHPGUSR";

            constexpr const char sub_key[]                  = "ADLT";

            constexpr const char key_sub_key[]              = "SRCHHPGUSR=ADLT=";

            constexpr const char* const sub_val[2]          {   "STRICT", 
                                                                "DEMOTE"    };
        }

    } /* safe_search ns */

    namespace restrict_access 
    {
        namespace microsoft 
        {
            extern std::unordered_set<std::string>    signatures;
        }
    } /* safe_search */

    constexpr const char H100CONTINUE[]         = "HTTP/1.1 100 Continue\r\n\r\n";

//------------------------------------------------------------------------------

  constexpr size_t READ_RQ_TRY_MAX            = 64;

//------------------------------------------------------------------------------      
    enum class request_state {

        dunno =         -1,

        deny =          0,

        allow =         1,

        auth_req =      2,

        read_sched =    3

        //irq_state_read_sched=3

    };
//------------------------------------------------------------------------------   

    enum class search_identity_by {

        none =  0x00,//anonymous

        ip =    0x02,

        uname = 0x04,

        uid =   0x08,

        lid =   0x10,

        _max=(none | ip | uname | uid | lid )

    };

//------------------------------------------------------------------------------   

    enum class block_actions {

        none =              0x00,

        block =             0x01,

        detect =            0x02,

        magic =             0x03,

        route_to_backend =  0x04,

        drop =              0x14

    };

//------------------------------------------------------------------------------

    struct IHRequestFlags;

    struct TaTag;

    class TaPE;

//------------------------------------------------------------------------------
    extern std::ostream &operator<<(std::ostream&, const t_proto_types);

    extern std::ostream &operator<<(std::ostream&, const BlockReason&);

    extern std::ostream &operator<<(std::ostream&, const t_method_type);

    extern std::ostream &operator<<(std::ostream&, const uint128_t&);

    extern std::ostream &operator<<(std::ostream&, const POLICY_FLAGS&) noexcept;

    extern std::ostream &operator<<(std::ostream&, const search_identity_by&);

    extern std::ostream &operator<<(std::ostream&, const t_meta_data &) noexcept;

    extern std::ostream &operator<<(std::ostream&, const POLICY &) noexcept;

//------------------------------------------------------------------------------
   //this is straight copy from the RequestFlags
    struct IHRequestFlags{

        IHRequestFlags(){

            (void)zm(this,sizeof(IHRequestFlags));

        }

        // true if the response to this request may not be READ from cache
        bool noCache :1;
        // request is if-modified-since
        bool ims :1;
        // request is authenticated
        bool auth :1;
        // he response to the request may be stored in the cache
        bool cachable :1;
        // the request can be forwarded through the hierarchy
        bool hierarchical :1;
        // a loop was detected on this request
        bool loopDetected :1;
        // the connection can be kept alive
        bool proxyKeepalive :1;
        // this should be killed, also in httpstateflags
        bool proxying :1;
        // content has expired, need to refresh it
        bool refresh :1;
        // request was redirected by redirectors
        bool redirected :1;
        // the requested object needs to be validated. See client_side_reply.cc
        // for further information.
        bool needValidation :1;
        // whether we should fail if validation fails
        bool failOnValidationError :1;
        // reply is stale if it is a hit
        bool staleIfHit :1;
        // request to override no-cache directives
        //always use noCacheHack() for reading.
        //\note only meaningful if USE_HTTP_VIOLATIONS is defined at build time
        bool nocacheHack :1;
        // this request is accelerated (reverse-proxy)
        bool accelerated :1;
        // if set, ignore Cache-Control headers
        bool ignoreCc :1;
        // set for intercepted requests
        bool intercepted :1;
        // set if the Host: header passed verification
        bool hostVerified :1;
        /// Set for requests handled by a "tproxy" port.
        bool interceptTproxy :1;
        /// The client IP address should be spoofed when connecting to the web server.
        /// This applies to TPROXY traffic that has not had spoofing disabled through
        /// the spoof_client_ip squid.conf ACL.
        bool spoofClientIp :1;
        // set if the request is internal (\see ClientHttpRequest::flags.internal)
        bool internal :1;
        // set for internally-generated requests
        //XXX this is set in in clientBeginRequest, but never tested.
        bool internalClient :1;
        // if set, request to try very hard to keep the connection alive
        bool mustKeepalive :1;
        // set if the rquest wants connection oriented auth
        bool connectionAuth :1;
        // set if connection oriented auth can not be supported
        bool connectionAuthDisabled :1;
        // Request wants connection oriented auth
        // XXX This is set in clientCheckPinning but never tested
        bool connectionProxyAuth :1;
        // set if the request was sent on a pinned connection
        bool pinned :1;
        // Authentication was already sent upstream (e.g. due tcp-level auth)
        bool authSent :1;
        // Deny direct forwarding unless overriden by always_direct
        //Used in accelerator mode
        bool noDirect :1;
        // Reply with chunked transfer encoding
        bool chunkedReply :1;
        // set if stream error has occured
        bool streamError :1;
        // internal ssl-bump request to get server cert
        bool sslPeek :1;
        // set if X-Forwarded-For checking is complete
        // do not read directly; use doneFollowXff for reading
        bool done_follow_x_forwarded_for :1;
        // set for ssl-bumped requests
        bool sslBumped :1;
        bool ftpNative:1;
        bool destinationIpLookedUp:1;
        // request to reset the TCP stream
        bool resetTcp:1;
        // set if the request is ranged
        bool isRanged :1;
        // bool ttn_transparent :1; //TODO: do we need this flag
        bool ttn_has_been_logged:1;
        bool ttn_has_been_processed:1;
        bool ttn_log_not_block:1;
        bool ttn_request_is_blocked:1;//TODO: find a way to remove this flag
        bool ttn_is_local_request:1;
        bool ttn_client_dst_passthru:1;  //Avoid squid to set the target IP to the original when
                                      //we want to redirect to our internal server
        bool ttn_do_not_check:1; //Do not check current request against TaPE or to fetch_missing_info
        bool ttn_rreply_100_continue:1; //currently only used only with wada
        bool ttn_explicitly_allowed:1; //currently only used only to bypass the ICAP
        bool ttn_session_started:1; //cloud keys session started
        bool ttn_ssl_error:1; //for whatever reason client is unable to establish an encrypted connection
        bool ttn_is_host_numeric:1;
        //bool ttn_blocked_by_icap:1; 

        friend 
        std::ostream &operator<<(   std::ostream & out,
                                    const IHRequestFlags & fl   )  {

            out<<"[FLAGS]:\n";
            out<<"\tttn_has_been_logged:{"<<fl.ttn_has_been_logged<<"}\n";
            out<<"\tttn_has_been_processed:{"<<fl.ttn_has_been_processed<<"}\n";
            out<<"\tttn_log_not_block:{"<<fl.ttn_log_not_block<<"}\n";
            out<<"\tttn_request_is_blocked:{"<<fl.ttn_request_is_blocked<<"}\n";
            out<<"\tttn_is_local_request:{"<<fl.ttn_is_local_request<<"}\n";
            out<<"\tttn_client_dst_passthru:{"<<fl.ttn_client_dst_passthru<<"}\n";
            out<<"\tttn_do_not_check:{"<<fl.ttn_do_not_check<<"}\n";
            out<<"\tttn_rreply_100_continue:{"<<fl.ttn_rreply_100_continue<<"}\n";
            out<<"\tttn_session_started:{"<<fl.ttn_session_started<<"}\n";
            out<<"\tttn_ssl_error:{"<<fl.ttn_ssl_error<<"}\n";
            out<<"\tttn_is_host_numeric:{"<<fl.ttn_is_host_numeric<<"}\n";
            //out<<"\tttn_blocked_by_icap:{"<<fl.ttn_blocked_by_icap<<"}\n";

            out<<"\tnative:noCache:{"<<fl.noCache<<"}\n";
            out<<"\tnative:ims:{"<<fl.ims<<"}\n";
            out<<"\tnative:auth:{"<<fl.auth<<"}\n";
            out<<"\tnative:cachable:{"<<fl.cachable<<"}\n";
            out<<"\tnative:hierarchical:{"<<fl.hierarchical<<"}\n";
            out<<"\tnative:loopDetected:{"<<fl.loopDetected<<"}\n";
            out<<"\tnative:proxyKeepalive:{"<<fl.proxyKeepalive<<"}\n";
            out<<"\tnative:proxying:{"<<fl.proxying<<"}\n";
            out<<"\tnative:refresh:{"<<fl.refresh<<"}\n";
            out<<"\tnative:redirected:{"<<fl.redirected<<"}\n";
            out<<"\tnative:needValidation:{"<<fl.needValidation<<"}\n";
            out<<"\tnative:failOnValidationError:{"<<fl.failOnValidationError<<"}\n";
            out<<"\tnative:staleIfHit:{"<<fl.staleIfHit<<"}\n";
            out<<"\tnative:nocacheHack:{"<<fl.nocacheHack<<"}\n";
            out<<"\tnative:accelerated:{"<<fl.accelerated<<"}\n";
            out<<"\tnative:ignoreCc:{"<<fl.ignoreCc<<"}\n";
            out<<"\tnative:intercepted:{"<<fl.intercepted<<"}\n";
            out<<"\tnative:hostVerified:{"<<fl.hostVerified<<"}\n";
            out<<"\tnative:interceptTproxy:{"<<fl.interceptTproxy<<"}\n";
            out<<"\tnative:spoofClientIp:{"<<fl.spoofClientIp<<"}\n";
            out<<"\tnative:internal:{"<<fl.internal<<"}\n";
            out<<"\tnative:internalClient:{"<<fl.internalClient<<"}\n";
            out<<"\tnative:mustKeepalive:{"<<fl.mustKeepalive<<"}\n";
            out<<"\tnative:connectionAuth:{"<<fl.connectionAuth<<"}\n";
            out<<"\tnative:connectionAuthDisabled:{"<<fl.connectionAuthDisabled<<"}\n";
            out<<"\tnative:connectionProxyAuth:{"<<fl.connectionProxyAuth<<"}\n";
            out<<"\tnative:pinned:{"<<fl.pinned<<"}\n";
            out<<"\tnative:authSent:{"<<fl.authSent<<"}\n";
            out<<"\tnative:noDirect:{"<<fl.noDirect<<"}\n";
            out<<"\tnative:chunkedReply:{"<<fl.chunkedReply<<"}\n";
            out<<"\tnative:streamError:{"<<fl.streamError<<"}\n";
            out<<"\tnative:sslPeek:{"<<fl.sslPeek<<"}\n";
            out<<"\tnative:done_follow_x_forwarded_for:{"<<fl.done_follow_x_forwarded_for<<"}\n";
            out<<"\tnative:sslBumped:{"<<fl.sslBumped<<"}\n";
            out<<"\tnative:ftpNative:{"<<fl.ftpNative<<"}\n";
            out<<"\tnative:destinationIpLookedUp:{"<<fl.destinationIpLookedUp<<"}\n";
            out<<"\tnative:resetTcp:{"<<fl.resetTcp<<"}\n";
            out<<"\tnative:isRanged:{"<<fl.isRanged<<"}\n";

            return out;
        }

    }; /* IHRequestFlags */

//------------------------------------------------------------------------------

    struct TaTag {

        friend struct IHRequest;

        t_meta_data    dns_meta_data{};

        struct identity_t
        {

            TitaxUser   parent = make_anonymous_user();

            TitaxUser   child = make_anonymous_user();

            struct
            {
                locations::location_t      location{};

                AccessControl              control{};

                BlockReason                reason{};

                POLICY                     combined_policy{};

                std::string                uri{};

                std::string                cloud_key{};

                std::string                redirection_host{};

                globals::strings_t         combined_group_names{};

                globals::strings_t         category_names{};

                globals::strings_t         category_numbers{};

                globals::strings_t         notifications{};

                TitaxUser*                 user{};

                t_wbl_actions              global_wbl_actions{};

                t_wbl_actions              combined_wbl_actions{};

                bool                       global_wbl_actions_checked{};

            }           eph{};

            inline void clear_category() noexcept 
            {
                  eph.category_numbers.clear();
                  eph.category_names.clear();
                  eph.control = {};
            }

            inline void clear_combined_policy() noexcept 
            {
               // mbThreashold set to ULONG_MAX coz threre's most/least restrictive related rule.
               // most restrictive -> smallest number which is not 0, if there's only 0 then 0.
               // least restrictive -> if there's a 0 then 0, if there's no 0 then biggest number.
               eph.combined_policy = { .flags.mbThreshold = ULONG_MAX };
            }

            inline void clear_all() noexcept
            {
                  clear_category();

                  clear_combined_policy();

                  /* clear reason */
                  eph.reason = {};
                  eph.reason.major=MAJ_REASON_UNKNOWN;

                  /* clear location */
                  eph.location.zero();

                  eph.uri.clear();
                  eph.redirection_host.clear();
                  eph.cloud_key.clear();
                  eph.combined_group_names.clear();
                  eph.notifications.clear();
                  eph.global_wbl_actions = t_wbl_actions::wba_none;
                  eph.combined_wbl_actions = t_wbl_actions::wba_none;
                  eph.global_wbl_actions_checked = false;

                  eph.user = nullptr;
                  parent = make_anonymous_user();
                  child = make_anonymous_user();
                  eph.user = &child;

                  #ifndef TTN_VTEST

                     eph.category_names.reserve( 32 );
                     eph.category_numbers.reserve( 32 );
                     eph.combined_group_names.reserve( 32 );
                     eph.notifications.reserve( 32 );

                  #endif
            }

            inline void make_child_anonymous(void) noexcept
            {
                child = make_anonymous_user();
            }

            inline identity_t & operator = (identity_t const & other_) noexcept
            {
               //clear_all();
               child = other_.child;

               parent = other_.parent;

               eph = other_.eph;
               
               if ( const TitaxUser * const o_user_ = other_.eph.user ) {

                  /* prevents the stale pointer use */
                  if (  o_user_->id == child.id                &&
 
                        o_user_->parent_id == child.parent_id        ) {

                     eph.user = &child; 
                  }
                  else {

                     eph.user = &parent;
                  }
               }

               return *this;
            }

            protected:

               static constexpr TitaxUser make_anonymous_user() noexcept
               {
                    return { .name = TITAX_ANON_DEFAULT_USER_NAME, .invalid_user = true, .anonymous = true };
               }


        }              identity{};
        
        char           clean_uri[CLEAN_URI_SZ]={};

        std::chrono::system_clock::time_point  timestamp_{};
        
        size_t         id_{};

        size_t         magic_type{};

        ssize_t        consumed_body_sz{};

        size_t         request_error_ctx{};

        size_t         clean_uri_sz{};

        struct s_http_status_{

            std::string       status_msg{};

            t_status_codes    status_code{};

        }              http{};

        std::string    app_args{};

        std::string    ck_session_id{};    //Cloud keys' session id

        block_actions  block_action{};

        t_txapp_cmds   app_type{};

        ttn_md5        magic_id{};

        TaTag();

        ~TaTag();

        void reset() noexcept;

        inline bool user_found() const noexcept
        {

            return (    identity.eph.user                       &&

                        !(  identity.eph.user->invalid_user     ||

                            identity.eph.user->anonymous    )       );
        }

        inline t_category category_get() const noexcept
        {
            return ( identity.eph.control.categoryE ?: identity.eph.control.categoryD );
        }

        inline void category_clear() noexcept 
        {
            identity.clear_category();
        }

        std::string category_getnames(std::string sep={','}) const;

        inline void meta_data_clear() noexcept 
        {
             tx_safe_free( dns_meta_data.raw_ptr.c );

             zm( &dns_meta_data, sizeof(t_meta_data) );
        }

        inline void make_child_anonymous() noexcept
        {
            identity.make_child_anonymous();
        }

        inline void user_clear() noexcept
        {
            identity.clear_all();
        }

        bool is_ts(const raw_ipaddr_t&, const cfg::TCFGInfo &);

        inline void combined_policy_clear() noexcept 
        {
            this->identity.clear_combined_policy();
        }

        void clear() noexcept;

        inline TaTag &operator =(TaTag const & other_) noexcept 
        {
            this->clear();

            this->identity = other_.identity;

            this->dns_meta_data = other_.dns_meta_data;

            return *this;
        }

        std::string get_timestamp() const;

        /**
        * @name setScheduledContext
        * @abstract set RequestContext, when set the TaTag owns given pointer,
        * previous pointer (if set/owned) will be deleted
        * @param context[in] ptr
        * @note see http://en.cppreference.com/w/cpp/memory/unique_ptr
        */
        inline
        void setScheduledContext(RequestContext* context)   {
            scheduled_context.reset(context);
        }

        inline
        void setScheduledContext(RequestContext_uptr_t context)  {
            scheduled_context=std::move(context);
        }

        /**
        * @name isScheduledContextSet
        * @abstract check if scheduled_context is set
        * @return t/f
        */
        inline
        bool isScheduledContextSet() const  { 
            return (static_cast<bool>(scheduled_context)); 
        }

        /**
        * @name getScheduledContext
        * @abstract return and release.
        * @warning Don't use this method to check if TaTag owns the RequestContext ptr
        * use isScheduledContextSet instead
        * @return RequestContext*
        * @note see http://en.cppreference.com/w/cpp/memory/unique_ptr
        */
        inline
        RequestContext_uptr_t getScheduledContext()  {
            return std::move(scheduled_context);
        }

        /**
        * @name clearScheduledContext
        * @abstract delete owned ptr
        * @note see http://en.cppreference.com/w/cpp/memory/unique_ptr
        */
        inline void clearScheduledContext() noexcept
        {
            scheduled_context.reset();
        }

         inline
         void copy_scheduled_data(void) 
         {
            if ( scheduled_context ) {
               /* add try catch */
               // we could set ip user_id here 
               if ( UserContext* const uc = dynamic_cast<UserContext*const>( scheduled_context.get() ) ) {

                  if ( uc->isSuccess() ) {

                     uc->copy_data( identity.parent, identity.child );
                  }
               }
            }
         }

        friend std::ostream &operator<<(std::ostream&, const TaTag &);

        protected:
            RequestContext_uptr_t                  scheduled_context{};

            bool                                   default_parent_set_{};

            void init_() noexcept;

    }; /* TaTag */

//------------------------------------------------------------------------------
    struct ICacheInfo{

        using t_cache = struct {

            size_t      msec{};

            size_t      requestSize{};

            size_t      replySize{};

            size_t      highOffset{};

            size_t      objectSize{};

            bool        cached{};

            bool        blocked{};

        };

        virtual void operator()(t_cache *const)=0;

        virtual ~ICacheInfo()=default;

    };

    //Abstract 
    struct ACacheInfo: ICacheInfo{

        void operator()(ICacheInfo::t_cache * const) override;

   };

//------------------------------------------------------------------------------
    struct IBodyPipe{

        virtual uint64_t get_BodySize()const=0;

        virtual const char *get_BodyContent() const=0;

        virtual bool consume(size_t)=0;

        virtual ~IBodyPipe()=default;

    };
//------------------------------------------------------------------------------
    struct IConnStateData{

        virtual bool readMoreDataNow(const bool use_bsockets=false)=0;

        virtual bool writeRawDataNow(const char * const, const uint32_t)const=0;

        virtual int get_cli_fd()const=0;

        virtual ~IConnStateData()=default;

    };
//------------------------------------------------------------------------------   
    struct IACLChecklist{

        virtual bool keepMatching() const=0;

        virtual bool Update(const request_state, const char *const)=0;

        virtual void markFinished(const request_state, const char *const)=0;

        virtual ~IACLChecklist()=default;

    };

    typedef request_state (t_check_authentication_method)(IACLChecklist * const);

//------------------------------------------------------------------------------

    struct IHRequest
    {
        TaTag ttag{};
        const t_wbl_actions & combined_wbl_actions;
        int processing_step{};

        virtual std::string headers_get_all(std::string sep={}) = 0;
        virtual void set_host(const std::string&) = 0;
        virtual void set_path(const std::string&) = 0;
        virtual void headers_put(const t_http_hdr_types,const std::string&) = 0;
        virtual std::string get_host() const = 0;
        virtual bool is_host_numeric() const = 0;
        virtual t_proto_types get_protocol() const = 0;
        virtual bool set_protocol(const t_proto_types) = 0;
        virtual std::string get_path() const = 0;
        virtual std::string get_canonical() = 0;
        virtual unsigned short get_port() const = 0;
        virtual void set_port(const size_t) = 0;
        virtual raw_ipaddr_t get_client_addr() = 0;
        virtual bool set_client_addr(const raw_ipaddr_t&) = 0;
        virtual raw_ipaddr_t get_indirect_client_addr() = 0;
        virtual std::string  get_x_forwarded_for_iterator() const = 0;
        virtual std::string  get_extacl_user() const = 0;
        virtual std::string  get_extacl_passwd() const = 0;
        virtual std::string  get_extacl_log() const = 0;
        virtual std::string  get_extacl_message() const = 0;
        virtual int headers_has(const t_http_hdr_types) const = 0;
        virtual std::string headers_get(const t_http_hdr_types) = 0;
        virtual std::string headers_getex(const t_http_hdr_types) = 0;
        virtual int headers_del(const t_http_hdr_types) = 0;
        virtual void headers_clear() = 0;
        virtual int get_authenticateUserAuthenticated() const = 0;
        virtual std::string get_auth_user_request_username() const = 0;
        virtual IHRequestFlags & get_flags() = 0;
        virtual bool serialize(const t_err_type err_type);
        virtual IBodyPipe * get_bodypipe() const = 0 ;
        virtual t_method_type get_method() const = 0 ;
        virtual bool set_method(const t_method_type) = 0;
        virtual int64_t get_content_length() const = 0;
        virtual bool is_target_server() const = 0;
        virtual std::string get_sni() const = 0;
        virtual bool can_report_errors() const = 0;

        virtual void set_icap_error(std::string);
        bool detect_magid(const std::string &);
        bool detect_cloud_key_state();
        virtual bool redirect2bp(const t_err_type err_type,const bp_backed_http_t &);
        t_wbl_actions check_global_wbl_actions() noexcept;

        inline 
        bool is_request_valid() const  {
            return (this->ttag.default_parent_set_);
        }

        friend 
        std::ostream& operator<<( std::ostream& out, IHRequest & obj ) {

            obj.dump(out);

            return out;

        }

        friend 
        std::ostream& operator<<(std::ostream& out , IHRequest * const obj ) {

            if ( obj ) {

                obj->dump(out);
            }

            return out;

        }

        IHRequest() :   combined_wbl_actions(ttag.identity.eph.combined_wbl_actions)
                        {}


        virtual ~IHRequest()=default;

        protected:
            raw_ipaddr_t   cli_ip_{};

            bool           cli_ip_man_set_{};

            virtual bool dump(std::ostream&)  ;

            std::string get_host_magid();

    }; /* IHRequest */

//------------------------------------------------------------------------------

    //Abstract 
    struct ARequest : IHRequest
    {
        protected:
            IHRequestFlags flags{};

        public:
            virtual void set_canonical(std::string);
            std::string headers_get_all(std::string sep={}) override;
            void set_host(const std::string&) override;
            void set_path(const std::string&) override;
            void headers_put(const t_http_hdr_types,const std::string&) override;
            unsigned short get_port() const override;
            void set_port(const size_t) override;
            std::string get_host() const override;
            std::string get_canonical() override;
            bool is_host_numeric() const override;
            t_proto_types get_protocol() const override;
            bool set_protocol(const t_proto_types) override;
            std::string get_path() const override;
            raw_ipaddr_t get_client_addr() override;
            bool set_client_addr(const raw_ipaddr_t&) override;
            raw_ipaddr_t get_indirect_client_addr() override;
            std::string get_x_forwarded_for_iterator() const override;
            std::string  get_extacl_user() const override;
            std::string  get_extacl_passwd() const override;
            std::string  get_extacl_log() const override;
            std::string  get_extacl_message() const override;
            int  headers_has(const t_http_hdr_types) const override;
            std::string headers_get(const t_http_hdr_types) override;
            std::string headers_getex(const t_http_hdr_types) override;
            int headers_del(const t_http_hdr_types) override;
            void headers_clear() override;
            int get_authenticateUserAuthenticated() const override;
            std::string get_auth_user_request_username() const override;
            IHRequestFlags & get_flags() override;
            IBodyPipe * get_bodypipe() const override;
            t_method_type get_method() const override;
            bool set_method(const t_method_type) override;
            int64_t get_content_length() const override;
            virtual std::string get_scheme() const;
            virtual bool reset();
            bool is_target_server() const override;
            std::string get_sni() const override;
            bool can_report_errors() const override;

    }; /* ARequest */

   //------------------------------------------------------------------------------

    template <typename T>
    struct TTCAp: TCAp{

        TTCAp(){

            this->check=&T::check_request_;

            this->shutdown=&T::shutdown_;

        }
    };

    struct TapDNS: TTCAp<TapDNS>{

        TapDNS(const bool,const bool,const t_txpe_output_type ltype_=t_txpe_output_type::ot_uds);

        virtual ~TapDNS();

        //don't call this directly 
        static bool check_request_(t_anyarg * const );

        static void shutdown_(void);

    };

    struct TapPE: TTCAp<TapPE>{

        TapPE(const bool,const bool,const t_txpe_output_type ltype_=t_txpe_output_type::ot_uds);

        //don't call this directly
        static bool check_request_(t_anyarg * const );

        static void shutdown_(void);
    };

    enum class urldb_simple_stats_t
    {
        disabled  = 0x00,

        error,

        unknown,

        ok
    };

    
} /* titan_v3 ns */

#endif /* TAPE_TYPES_HXX */

/* vim: set ts=4 sw=4 et : */

