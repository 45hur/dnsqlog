/* Convenience macro to declare module API. */
/* Convenience macro to declare module API. */
#define C_MOD_DNSQLOG "\x07""dnsqlog"

#include "program.h"

#include <dirent.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <sys/mman.h> 
#include <sys/stat.h> 
#include <sys/types.h> 
#include <unistd.h>

#include "crc64.h"
#include "log.h"
#include "lmdb.h"
#include "thread_shared.h" 

#define E(expr) CHECK((rc = (expr)) == MDB_SUCCESS, #expr)
#define RES(err, expr) ((rc = expr) == (err) || (CHECK(!rc, #expr), 0))
#define CHECK(test, msg) ((test) ? (void)0 : ((void)debugLog("%s:%d: %s: %s\n", __FILE__, __LINE__, msg, mdb_strerror(rc)), abort()))

int loop = 1;
MDB_env *mdb_env = 0;

int create(void **args)
{
	MDB_dbi dbi;
	MDB_txn *txn = 0;
	int rc = 0;
	int fd = shm_open(C_MOD_MUTEX, O_CREAT | O_TRUNC | O_RDWR, 0600);
	if (fd == -1)
		return fd;

	E(ftruncate(fd, sizeof(struct shared)));

	thread_shared = (struct shared*)mmap(0, sizeof(struct shared), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (thread_shared == NULL)
		return -1;

	thread_shared->sharedResource = 0;
    pthread_mutexattr_t shared;
    pthread_mutexattr_init(&shared);
    pthread_mutexattr_setpshared(&shared, PTHREAD_PROCESS_SHARED);

    pthread_mutex_init(&(thread_shared->mutex), &shared);

	E(mdb_env_create(&mdb_env));
	E(mdb_env_set_maxreaders(mdb_env, 16));
	E(mdb_env_set_maxdbs(mdb_env, 4));
	size_t max = 1073741824;
	E(mdb_env_set_mapsize(mdb_env, max)); //1GB
	E(mdb_env_open(mdb_env, "/var/whalebone/dnsqlog", /*MDB_FIXEDMAP | MDB_NOSYNC*/ 0, 0664));

	E(mdb_txn_begin(mdb_env, 0, 0, &txn));
	E(mdb_dbi_open(txn, "cache", MDB_CREATE, &dbi));
	E(mdb_txn_commit(txn));
	mdb_close(mdb_env, dbi);

	//init();

	//pthread_t thr_id;
	//loop = 1;
	//E(pthread_create(&thr_id, NULL, &threadproc, NULL));

	//*args = (void *)thr_id;

	debugLog("\"method\":\"create\",\"message\":\"created\"");

	return 0;
}

int destroy(void *args)
{
	int rc = 0;
	loop = 0;

	mdb_env_close(mdb_env);
	mdb_env = NULL;

	/*void *res = NULL;
	pthread_t thr_id = (pthread_t)args;
	E(pthread_join(thr_id, res));*/

	munmap(thread_shared, sizeof(struct shared*));
    shm_unlink(C_MOD_MUTEX);

	debugLog("\"method\":\"destroy\",\"message\":\"destroyed\"");

	return 0;
}

int search(const char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, int rrtype, char * originaldomain, char * logmessage)
{
	char message[2048] = {};
	unsigned long long crc = crc64(0, (const char*)domainToFind, strlen(domainToFind));
	unsigned long long crcIoC = crc64(0, (const char*)domainToFind, strlen(originaldomain));
	//debugLog("\"method\":\"search\",\"message\":\"entry\",\"ioc=\"%s\",\"crc\":\"%llx\",\"crcioc\":\"%llx\"", domainToFind, crc, crcIoC);

	fileLog("\"method\":\"search\",\"message\":\"detected ioc '%s' at domain '%s' from ip '%s'\"", domainToFind, originaldomain, userIpAddressString);

	return 0;
}

int explode(char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, int rrtype)
{
	char logmessage[2048] = { 0 };
	char *ptr = domainToFind;
	ptr += strlen(domainToFind);
	int result = 0;
	int found = 0;
	while (ptr-- != (char *)domainToFind)
	{
		if (ptr[0] == '.')
		{
			if (++found > 1)
			{
				debugLog("\"method\":\"explode\",\"message\":\"search %s\"", ptr + 1);
				if ((result = search(ptr + 1, userIpAddress, userIpAddressString, rrtype, domainToFind, logmessage)) != 0)
				{
					if (logmessage[0] != '\0')
					{
						fileLog(logmessage);
					}
					return result;
				}
			}
		}
		else
		{
			if (ptr == (char *)domainToFind)
			{
				debugLog("\"method\":\"explode\",\"message\":\"search %s\"", ptr);
				if ((result = search(ptr, userIpAddress, userIpAddressString, rrtype, domainToFind, logmessage)) != 0)
				{
					if (logmessage[0] != '\0')
					{
						fileLog(logmessage);
					}
					return result;
				}
			}
		}
	}
	if (logmessage[0] != '\0')
	{
		fileLog(logmessage);
	}

	return 0;
}


#ifdef NOKRES 

static int usage()
{
	fprintf(stdout, "Available commands: ");
	fprintf(stdout, "\n");
	fprintf(stdout, "exit\n");
	return 0;
}

static int userInput()
{
	char command[80] = { 0 };
	fprintf(stdout, "\nType command:");
	scanf("%79s", command);

	if (strcmp("exit", command) == 0)
	{
		return 0;
	} 
	else
	{
		usage();
	}

	return 1;
}

int main()
{
	int err = 0;
	int thr_id = 0;
	if ((err = create((void *)&thr_id)) != 0)
	{
		debugLog("\"%s\":\"%s\"", "message", "error in create");
		return err;
	}

	usage();
	while (userInput());

	if ((err = destroy((void *)&thr_id)) != 0)
	{
		debugLog("\"%s\":\"%s\"", "message", "error in destroy");
		return err;
	}

	return err;
}

#endif