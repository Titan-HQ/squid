/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HTTPMSG_H
#define SQUID_HTTPMSG_H

#include <map>

#include "base/Lock.h"
#include "BodyPipe.h"
#include "http/ProtocolVersion.h"
#include "http/StatusCode.h"
#include "HttpHeader.h"
#include "HttpRequestMethod.h"

/// common parts of HttpRequest and HttpReply
class HttpMsg : public RefCountable
{
public:
   uint64_t _id;
   mutable std::map<uint32_t,std::string> _locks;   
   virtual void lock(const char * const,const uint32_t) const;    
   //virtual void lock(void) const;
   virtual uint32_t unlock(const char * const,const uint32_t) const;
   void trace(const char * const _place,const uint32_t _no,const std::string _msg="") const;
public:
    typedef RefCount<HttpMsg> Pointer;

    HttpMsg(http_hdr_owner_type owner);
    virtual ~HttpMsg();

    virtual void reset() = 0; // will have body when http*Clean()s are gone

    void packInto(Packer * p, bool full_uri) const;

    ///< produce a message copy, except for a few connection-specific settings
    virtual HttpMsg *clone() const = 0; ///< \todo rename: not a true copy?

    /// [re]sets Content-Length header and cached value
    void setContentLength(int64_t clen);

    /**
     * \retval true  the message sender asks to keep the connection open.
     * \retval false the message sender will close the connection.
     *
     * Factors other than the headers may result in connection closure.
     */
    bool persistent() const;

public:
    /// HTTP-Version field in the first line of the message.
    /// see RFC 7230 section 3.1
    Http::ProtocolVersion http_ver;

    HttpHeader header;

    HttpHdrCc *cache_control;

    /* Unsupported, writable, may disappear/change in the future
     * For replies, sums _stored_ status-line, headers, and <CRLF>.
     * Also used to report parsed header size if parse() is successful */
    int hdr_sz;

    int64_t content_length;

    HttpMsgParseState pstate;   /* the current parsing state */

    BodyPipe::Pointer body_pipe; // optional pipeline to receive message body

    /// copies Cache-Control header to this message
    void putCc(const HttpHdrCc *otherCc);

    // returns true and sets hdr_sz on success
    // returns false and sets *error to zero when needs more data
    // returns false and sets *error to a positive Http::StatusCode on error
    bool parse(MemBuf *buf, bool eol, Http::StatusCode *error);

    bool parseCharBuf(const char *buf, ssize_t end);

    int httpMsgParseStep(const char *buf, int len, int atEnd);

    virtual int httpMsgParseError();

    virtual bool expectingBody(const HttpRequestMethod&, int64_t&) const = 0;

    void firstLineBuf(MemBuf&);

    virtual bool inheritProperties(const HttpMsg *aMsg) = 0;


    //titan lib / ttnPe
    std::string status_msg{};
protected:
    /**
     * Validate the message start line is syntactically correct.
     * Set HTTP error status according to problems found.
     *
     * \retval true   Status line has no serious problems.
     * \retval false  Status line has a serious problem. Correct response is indicated by error.
     */
    virtual bool sanityCheckStartLine(MemBuf *buf, const size_t hdr_len, Http::StatusCode *error) = 0;

    virtual void packFirstLineInto(Packer * p, bool full_uri) const = 0;

    virtual bool parseFirstLine(const char *blk_start, const char *blk_end) = 0;

    virtual void hdrCacheInit();

};

int httpMsgIsolateHeaders(const char **parse_start, int len, const char **blk_start, const char **blk_end);

typedef std::map<uint64_t,HttpMsg*const> t_HttpRmap;
#define HTTPMSGUNLOCK(a) if (a) {if (!(a)->unlock(__FUNCTION__,__LINE__)) delete (a); (a)=NULL; }
#define HTTPMSGLOCK(a) if (a) {(a)->lock(__FUNCTION__,__LINE__);}
#define HTTPMSGTRACE(a) if (a) {(a)->trace(__FUNCTION__,__LINE__);}
#define HTTPMSGTRACE_MSG(a,m) if (a) {(a)->trace(__FUNCTION__,__LINE__,m);}
#ifndef WTRACE_MSG
   #define WTRACE_MSG(m)
   //#define WTRACE_MSG(m) std::cout<<__FUNCTION__<<":"<<__LINE__<<":"<<m<<std::endl
#endif

#endif /* SQUID_HTTPMSG_H */

