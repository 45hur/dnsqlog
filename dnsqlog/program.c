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

int create(void **args)
{
	MDB_env *mdb_env = NULL;
	MDB_dbi dbi;
	MDB_txn *txn = NULL;
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
	E(mdb_env_set_maxreaders(mdb_env, 127));
	E(mdb_env_set_maxdbs(mdb_env, 16));
	size_t max = 1073741824;
	E(mdb_env_set_mapsize(mdb_env, max)); //1GB
	E(mdb_env_open(mdb_env, C_MOD_LMDB_PATH, /*MDB_FIXEDMAP | MDB_NOSYNC*/ 0, 0664));

	E(mdb_txn_begin(mdb_env, 0, 0, &txn));
	E(mdb_dbi_open(txn, "cache", MDB_CREATE, &dbi));
	E(mdb_txn_commit(txn));
	mdb_close(mdb_env, dbi);
	
	mdb_env_close(mdb_env);
	mdb_env = NULL;

	debugLog("\"method\":\"create\",\"message\":\"created\"");

	return 0;
}

int destroy(void *args)
{
	int rc = 0;
	loop = 0;

	munmap(thread_shared, sizeof(struct shared*));
    shm_unlink(C_MOD_MUTEX);

	debugLog("\"method\":\"destroy\",\"message\":\"destroyed\"");

	return 0;
}

int increment(const char *client, const char *query, const char *answer, const int type)
{
	MDB_env *mdb_env = NULL;
	MDB_dbi dbi;
	MDB_val key, data;
	MDB_txn *txn = NULL;
	int rc = 0;
	char bkey[8] = { 0 };
	time_t rawtime = 0;

	char combokey[8192] = { 0 };
	sprintf((char *)&combokey, "%s:%s:%s:%d", client, query, answer, type);

	debugLog(combokey);

	unsigned long long crc = crc64(0, combokey, strlen(combokey));
	memcpy(&bkey, &crc, 8);

	//Init LMDB
	E(mdb_env_create(&mdb_env));
	E(mdb_env_set_maxreaders(mdb_env, 127));
	E(mdb_env_set_maxdbs(mdb_env, 16));
	size_t max = 1073741824;
	E(mdb_env_set_mapsize(mdb_env, max)); //1GB

	//Get data, if any
	E(mdb_txn_begin(mdb_env, 0, MDB_TXN_FULL, &txn));
	debugLog("open");
	if ((rc = mdb_dbi_open(txn, "cache", 0, &dbi)) == 0)
	{
		key.mv_size = sizeof(unsigned long long);
		key.mv_data = (void *)bkey;

		debugLog("get");

		if ((rc = mdb_get(txn, dbi, &key, &data)) == 0)
		{
			memcpy(&rawtime, data.mv_data, data.mv_size);
		}
		E(mdb_txn_commit(txn));
	}
	else
	{
		mdb_txn_abort(txn);
	}
	txn = NULL;
	mdb_close(mdb_env, dbi);

	//Modify data
	if (rawtime == 0)
	{
		debugLog("time = 0");

		time(&rawtime);

		txn = 0;
		E(mdb_txn_begin (mdb_env, 0, 0, &txn));
		E(mdb_dbi_open(txn, "cache", 0, &dbi));
		key.mv_size = sizeof(unsigned long long);
		key.mv_data = (void *)bkey;
		data.mv_size = sizeof(time_t);
		data.mv_data = (void *)&rawtime;
		E(mdb_put(txn, dbi, &key, &data, 0));

		E(mdb_txn_commit(txn));
		mdb_close(mdb_env, dbi);
		txn = NULL;

		mdb_env_close(mdb_env);
		mdb_env = NULL;

		return 1;
	}

	time_t now;
	time(&now);

	int secs = difftime(now, rawtime);

	debugLog("diff = %d seconds", secs);
	
	//Update data
	txn = 0;
	E(mdb_txn_begin(mdb_env, 0, 0, &txn));
	E(mdb_dbi_open(txn, "cache", 0, &dbi));
	key.mv_size = sizeof(unsigned long long);
	key.mv_data = (void *)bkey;
	data.mv_size = sizeof(time_t);
	data.mv_data = (void *)&now;
	E(mdb_put(txn, dbi, &key, &data, 0));

	E(mdb_txn_commit(txn));
	mdb_close(mdb_env, dbi);
	txn = NULL;

	mdb_env_close(mdb_env);
	mdb_env = NULL;

	if (secs > 86400) // one day
	{
		return 1;
	}

	return 0;
}

#ifdef NOKRES 

static int usage()
{
	fprintf(stdout, "Available commands: ");
	fprintf(stdout, "\n"); 
	fprintf(stdout, "inc\n");
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
	else if (strcmp("inc", command) == 0)
	{
		increment("127.0.0.1", "google.com", "172.217.23.238", 1);
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