#pragma once

#ifndef LOG_H
#define LOG_H

#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

#include "thread_shared.h"

#define C_MOD_MUTEX "mutex.dnsqlog.kres.module\0"
#define C_MOD_LOGFILE "/var/log/whalebone/dnsqlog.log\0"
#define C_MOD_LOGDEBUG "/var/log/whalebone/dnsqlogdebug.log\0"
#define C_MOD_LOGAUDIT "/var/log/whalebone/dnsqlogaudit.log\0"
#define C_MOD_LMDB_PATH "/mnt/c/var/whalebone/dnsqlog\0"
//#define C_MOD_LMDB_PATH "/var/whalebone/dnsqlog\0"

void debugLog(const char *format, ...);
void fileLog(const char *format, ...);

#endif