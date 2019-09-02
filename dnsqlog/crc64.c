#include "crc64.h"

uint64_t crc64(uint64_t crc, const char *s, uint64_t l)
{
 uint64_t j;

 for (j = 0; j < l; j++) {
	 uint8_t byte = (unsigned char)s[j];
	 crc = crc64_tab[(uint8_t)crc ^ byte] ^ (crc >> 8);
 }
 return crc;
}