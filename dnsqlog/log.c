
#include "log.h"

#include <pthread.h>
#include <sys/time.h>
#include <time.h>

void debugLog(const char *format, ...)
{
#ifdef DEBUG
	va_list dbgargptr;
	va_start(dbgargptr, format);
	vfprintf(stdout, format, dbgargptr);
	va_end(dbgargptr);
#endif

	if (getenv("DEBUGLOG") == NULL)
		return;

	char text[3840] = { 0 };
	va_list argptr;
	va_start(argptr, format);
	vsprintf(text, format, argptr);
	va_end(argptr);

	FILE *fh = 0;
	char message[4096] = { 0 };
	char timebuf[30] = { 0 };

	struct timeval tv;
	time_t curtime;

	gettimeofday(&tv, NULL);
	curtime = tv.tv_sec;

	strftime(timebuf, 30, "%m-%d-%Y %T.", localtime(&curtime));

	sprintf(message, "{\"timestamp\":\"%s%ld\",\"tid\":\"%lx\",\"msg\":\"%s\"}\n", timebuf, tv.tv_usec, pthread_self(), text);

	fprintf(stdout, "%s", message);

	pthread_mutex_lock(&(thread_shared->mutex));
	if (fh == 0)
	{
		fh = fopen(C_MOD_LOGDEBUG, "at");
		if (!fh)
		{
			fh = fopen(C_MOD_LOGDEBUG, "wt");
		}
		if (!fh)
		{
			goto end;
		}
	}

	fputs(message, fh);
	fflush(fh);
	fclose(fh);
end:
	pthread_mutex_unlock(&(thread_shared->mutex));
}

void fileLog(const char *format, ...)
{
	char text[3840] = { 0 };
	va_list argptr;
	va_start(argptr, format);
	vsprintf(text, format, argptr);
	va_end(argptr);

	FILE *fh = 0;
	char message[4096] = { 0 };
	char timebuf[30] = { 0 };
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",%s}\n", timebuf, text);

	fprintf(stdout, "%s", message);

	pthread_mutex_lock(&(thread_shared->mutex));
	if (fh == 0)
	{
		fh = fopen(C_MOD_LOGFILE, "at");
		if (!fh)
		{
			fh = fopen(C_MOD_LOGFILE, "wt");
		}
		if (!fh)
		{
			goto end;
		}
	}

	fputs(message, fh);
	fflush(fh);
	fclose(fh);
end:
	pthread_mutex_unlock(&(thread_shared->mutex));	
}