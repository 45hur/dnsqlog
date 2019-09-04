	#pragma once

#ifndef THREAD_SHARED_H
#define THREAD_SHARED_H

#include <stdio.h> 
#include <stdint.h>
#include <pthread.h>

#include "lmdb.h"

struct shared
{
	pthread_mutex_t mutex;
	MDB_env* mdb_env;
	MDB_dbi mdb_dbi;
	int refcount;
};

struct shared *thread_shared;

struct ipaddr
{
	uint16_t family : 16;
	uint32_t ipv4_sin_addr : 32;
	uint64_t ipv6_sin_addr_hi : 64;
	uint64_t ipv6_sin_addr_low : 64;
};

struct ip_addr
{
	unsigned int family;
	unsigned int ipv4_sin_addr;
	unsigned char ipv6_sin_addr[16];
};

struct PrimeHeader
{
	uint32_t action : 32;
	uint32_t buffercount : 32;
	uint64_t headercrc : 64;
};

struct MessageHeader
{
	uint64_t length : 64;
	uint64_t msgcrc : 64;
};

enum
{
	bufferType_swapcache = 0,
	bufferType_domainCrcBuffer = 1,
	bufferType_domainAccuracyBuffer = 2,
	bufferType_domainFlagsBuffer = 3,
	bufferType_iprangeipfrom = 4,
	bufferType_iprangeipto = 5,
	bufferType_iprangeidentity = 6,
	bufferType_iprangepolicyid = 7,
	bufferType_policyid = 8,
	bufferType_policystrategy = 9,
	bufferType_policyaudit = 10,
	bufferType_policyblock = 11,
	bufferType_identitybuffer = 12,
	bufferType_identitybufferwhitelist = 13,
	bufferType_identitybufferblacklist = 14,
	bufferType_identitybufferpolicyid = 15,
	bufferType_freeswaps = 16,
	bufferType_loadfile = 17,
	bufferType_identitybuffercount = 18,
	bufferType_identitybufferflush = 19,
	bufferType_iprangecrc = 20,
} bufferType;

#endif