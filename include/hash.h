/*
 * Copyright (C) 1996-2016 The Squid Software Foundation and contributors
 *
 * Squid software is distributed under GPLv2+ license and includes
 * contributions from numerous individuals and organizations.
 * Please see the COPYING and CONTRIBUTORS files for details.
 */

#ifndef SQUID_HASH_H
#define SQUID_HASH_H

typedef void HASHFREE(void *const);
typedef int HASHCMP(const void *, const void *);
typedef unsigned int HASHHASH(const void *const, unsigned int);

class hash_link {
public:
    void *key;
    hash_link *next;
    hash_link():key(NULL),next(NULL){};
    virtual ~hash_link(){
       this->next=NULL;
    };
    virtual void release(void){
       //intentionally left empty ... no one should call it
    };

};

class hash_table {
public:
    hash_link **buckets;
    HASHCMP *cmp;
    HASHHASH *hash;
    unsigned int size;
    unsigned int current_slot;
    hash_link *next;
    int count;
};

SQUIDCEXTERN hash_table *const hash_create(HASHCMP *const, int, HASHHASH *const);
SQUIDCEXTERN void hash_join(hash_table *const, hash_link *const);
SQUIDCEXTERN void hash_remove_link(hash_table *const, hash_link *const);
SQUIDCEXTERN int hashPrime(const int n);
SQUIDCEXTERN hash_link *const hash_lookup(hash_table *const, const void *const);
SQUIDCEXTERN void hash_first(hash_table *const);
SQUIDCEXTERN hash_link *const hash_next(hash_table *const );
SQUIDCEXTERN void hash_last(hash_table *const );
SQUIDCEXTERN hash_link *const hash_get_bucket(const hash_table *const , const unsigned int);
SQUIDCEXTERN void hashFreeMemory(const hash_table *const );
SQUIDCEXTERN void hashFreeItems(hash_table *const , HASHFREE *const);
SQUIDCEXTERN HASHHASH hash_string;
SQUIDCEXTERN HASHHASH hash4;
SQUIDCEXTERN const char *const hashKeyStr(const hash_link *const );

/*
 *  Here are some good prime number choices.  It's important not to
 *  choose a prime number that is too close to exact powers of 2.
 *
 *  HASH_SIZE 103               // prime number < 128
 *  HASH_SIZE 229               // prime number < 256
 *  HASH_SIZE 467               // prime number < 512
 *  HASH_SIZE 977               // prime number < 1024
 *  HASH_SIZE 1979              // prime number < 2048
 *  HASH_SIZE 4019              // prime number < 4096
 *  HASH_SIZE 6037              // prime number < 6144
 *  HASH_SIZE 7951              // prime number < 8192
 *  HASH_SIZE 12149             // prime number < 12288
 *  HASH_SIZE 16231             // prime number < 16384
 *  HASH_SIZE 33493             // prime number < 32768
 *  HASH_SIZE 65357             // prime number < 65536
 */
#define  DEFAULT_HASH_SIZE 7951 /* prime number < 8192 */

#endif /* SQUID_HASH_H */

