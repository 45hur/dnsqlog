#pragma once

#include <fcntl.h> 

#include "thread_shared.h"

#ifndef PROGRAM_H
#define PROGRAM_H

int ftruncate(int fd, off_t length);

int create(void **args);
int destroy();
int search(const char * querieddomain, struct ip_addr * userIpAddress, const char * userIpAddressString, int rrtype, char * originaldomain, char * logmessage);
int explode(char * domainToFind, struct ip_addr * userIpAddress, const char * userIpAddressString, int rrtype);

void* threadproc(void *arg);

#endif