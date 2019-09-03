#pragma once

#include <fcntl.h> 

#include "thread_shared.h"

#ifndef PROGRAM_H
#define PROGRAM_H

int ftruncate(int fd, off_t length);

int create(void **args);
int destroy();

//void* threadproc(void *arg);

#endif