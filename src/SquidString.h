/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

/* DEBUG: section 67    String */

#ifndef SQUID_STRING_H
#define SQUID_STRING_H

#include <ostream>

/* squid string placeholder (for printf) */
#ifndef SQUIDSTRINGPH
#define SQUIDSTRINGPH "%.*s"
#define SQUIDSTRINGPRINT(s) (s).psize(),(s).rawBuf()
#endif /* SQUIDSTRINGPH */

class String
{

public:
    _SQUID_INLINE_ String();
    String(char const * const );
    String(String const &);
    ~String();

    typedef size_t size_type; //storage size intentionally unspecified
    const static size_type npos = static_cast<size_type>(-1);

    String &operator =(char const *const);
    String &operator =(String const &);
    bool operator ==(String const &) const;
    bool operator !=(String const &) const;

    /**
     * Retrieve a single character in the string.
     \param pos Position of character to retrieve.
     */
    _SQUID_INLINE_ char operator [](unsigned int pos) const;

    _SQUID_INLINE_ size_type size() const;
    /// variant of size() suited to be used for printf-alikes.
    /// throws when size() > MAXINT
    int psize() const;

    /**
     * Returns a raw pointer to the underlying backing store. The caller has been
     * verified not to make any assumptions about null-termination
     */
    _SQUID_INLINE_ char const * const rawBuf() const;
    /**
     * Returns a raw pointer to the underlying backing store.
     * The caller requires it to be null-terminated.
     */
    _SQUID_INLINE_ char const * const termedBuf() const;
    void limitInit(const char *const str,const int len); // TODO: rename to assign()
    void clean();
    void reset(char const *const str);
    void append(char const *const buf,const int len);
    void append(char const *const buf);
    void append(char const);
    void append(String const &);
    void absorb(String &old);
    const char * const pos(char const *const aString) const;
    const char * const pos(char const ch) const;
    ///offset from string start of the first occurrence of ch
    /// returns String::npos if ch is not found
    size_type find(char const ch) const;
    size_type find(char const *const aString) const;
    const char * const rpos(char const ch) const;
    size_type rfind(char const ch) const;
    _SQUID_INLINE_ int cmp(char const *const) const;
    _SQUID_INLINE_ int cmp(char const *const , const size_type count) const;
    _SQUID_INLINE_ int cmp(String const &) const;
    _SQUID_INLINE_ int caseCmp(char const *const) const;
    _SQUID_INLINE_ int caseCmp(char const *const,const  size_type count) const;
    _SQUID_INLINE_ int caseCmp(String const &) const;

    String substr(size_type from, size_type to) const;

    _SQUID_INLINE_ void cut(size_type newLength);

private:
    void allocAndFill(const char *const str,const int len);
    void allocBuffer(size_type sz);
    void setBuffer(char *const buf, const size_type sz);

    bool defined() const {return buf_!=NULL;}
    bool undefined() const {return !defined();}

    _SQUID_INLINE_ bool nilCmp(bool, bool, int &) const;

    /* never reference these directly! */
    size_type size_; /* buffer size; 64K limit */

    size_type len_;  /* current length  */

    char *buf_;

    _SQUID_INLINE_ void set(char const *const loc, char const ch);
    _SQUID_INLINE_ void cutPointer(char const *loc);

};

_SQUID_INLINE_ std::ostream & operator<<(std::ostream& os, String const &aString);

_SQUID_INLINE_ bool operator<(const String &a, const String &b);

#if _USE_INLINE_
#include "String.cci"
#endif

const char *const checkNullString(const char *const p);
int stringHasWhitespace(const char *const);
int stringHasCntl(const char *const);
char *const strwordtok(const char *const buf, char **const t);

#endif /* SQUID_STRING_H */

