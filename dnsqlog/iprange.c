#include <string.h>

#include "iprange.h"

int is_ip_in_range(const struct ip_addr *ip, const struct ip_addr *from, const struct ip_addr *to)
{

int result = 0;
if (ip->family != from->family || ip->family != to->family)
return result;

switch (ip->family) {
case AF_INET: {
	unsigned int addr_ip = __builtin_bswap32(ip->ipv4_sin_addr);
	unsigned int addr_fr = from->ipv4_sin_addr;
	unsigned int addr_to = to->ipv4_sin_addr;

	result = (addr_ip >= addr_fr) && (addr_ip <= addr_to);
	//printf("%08x => %08x <= %08x -- %d\n",
	//	addr_fr,
	//	addr_ip,
	//	addr_to,
	//	result
	//);
	break;
}
case AF_INET6: {
	unsigned char *addr6_ip = ip->ipv6_sin_addr;
	unsigned char *addr6_fr = from->ipv6_sin_addr;
	unsigned char *addr6_to = to->ipv6_sin_addr;

	//printf("iplo=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\niphi=>%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\nips=> %02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X%02X\n\n",
	//(addr6_fr)[0],  (addr6_fr)[1],  (addr6_fr)[2],  (addr6_fr)[3],
	//(addr6_fr)[4],  (addr6_fr)[5],  (addr6_fr)[6],  (addr6_fr)[7],
	//(addr6_fr)[8],  (addr6_fr)[9],  (addr6_fr)[10], (addr6_fr)[11],
	//(addr6_fr)[12], (addr6_fr)[13], (addr6_fr)[14], (addr6_fr)[15],
	//(addr6_to)[0],  (addr6_to)[1],  (addr6_to)[2],  (addr6_to)[3],
	//(addr6_to)[4],  (addr6_to)[5],  (addr6_to)[6],  (addr6_to)[7],
	//(addr6_to)[8],  (addr6_to)[9],  (addr6_to)[10], (addr6_to)[11],
	//(addr6_to)[12], (addr6_to)[13], (addr6_to)[14], (addr6_to)[15],
	//(addr6_ip)[0],  (addr6_ip)[1],  (addr6_ip)[2],  (addr6_ip)[3],
	//(addr6_ip)[4],  (addr6_ip)[5],  (addr6_ip)[6],  (addr6_ip)[7],
	//(addr6_ip)[8],  (addr6_ip)[9],  (addr6_ip)[10], (addr6_ip)[11],
	//(addr6_ip)[12], (addr6_ip)[13], (addr6_ip)[14], (addr6_ip)[15]
	//);
	//
	int r1 = memcmp(addr6_ip, addr6_fr, 16);
	int r2 = memcmp(addr6_ip, addr6_to, 16);
	result = r1 >= 0 && r2 <= 0;
	break;
}
default:
{
	printf("wrong ip address\n");
	break;
}
}

return result;
}