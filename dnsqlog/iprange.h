#pragma once

#ifndef IPRANGE_H
#define IPRANGE_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> //inet_addr

#include "thread_shared.h"

int is_ip_in_range(const struct ip_addr *ip, const struct ip_addr *from, const struct ip_addr *to);

#endif