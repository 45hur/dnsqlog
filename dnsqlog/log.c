
#include "log.h"

#include <pthread.h>

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
	time_t rawtime;
	struct tm * timeinfo;

	time(&rawtime);
	timeinfo = localtime(&rawtime);
	strftime(timebuf, 26, "%Y/%m/%d %H:%M:%S", timeinfo);
	sprintf(message, "{\"timestamp\":\"%s\",\"tid\":\"%lu\",%s}\n", timebuf, pthread_self(), text);

	fprintf(stdout, "%s", message);

	if (fh == 0)
	{
		fh = fopen(C_MOD_LOGDEBUG, "at");
		if (!fh)
		{
			fh = fopen(C_MOD_LOGDEBUG, "wt");
		}
		if (!fh)
		{
			return;
		}
	}

	fputs(message, fh);
	fflush(fh);
	fclose(fh);
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

	if (fh == 0)
	{
		fh = fopen(C_MOD_LOGFILE, "at");
		if (!fh)
		{
			fh = fopen(C_MOD_LOGFILE, "wt");
		}
		if (!fh)
		{
			return;
		}
	}

	fputs(message, fh);
	fflush(fh);
	fclose(fh);
}

void auditLog(const char *format, ...)
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

	if (fh == 0)
	{
		fh = fopen(C_MOD_LOGAUDIT, "at");
		if (!fh)
		{
			fh = fopen(C_MOD_LOGAUDIT, "wt");
		}
		if (!fh)
		{
			return;
		}
	}

	fputs(message, fh);
	fflush(fh);
	fclose(fh);
}