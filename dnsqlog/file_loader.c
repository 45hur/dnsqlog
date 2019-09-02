#include <string.h>

#include "crc64.h"
#include "file_loader.h"
#include "thread_shared.h"
#include "log.h"
#include "program.h"

void load_file(char *filename)
{
	debugLog("\"method\":\"load_file\",\"message\":\"started loading file\",\"file\":\"%s\"", filename);

	//filename = "/mnt/c/var/whalebone/data/21658d0c-e2e6-4aea-8ea0-8753fffe6cd7.dat";
	//Get the socket descriptor /mnt/c/var/whalebone/data/
	int read_result;
	char client_message[4096];
	struct PrimeHeader primeHeader;
	struct MessageHeader messageHeader;
	int bytesRead = 0;
	FILE * file;
	file = fopen(filename, "rb");
	if (!file)
	{
		debugLog("\"method\":\"load_file\",\"error\":\"unable to open .dat file\"");
		return;
	}

	char *bufferPtr = (char *)&primeHeader;
	char *bufferXPtr;
	while ((read_result = fread(client_message, sizeof(struct PrimeHeader), 1, file)) > 0)
	{
		memcpy(bufferPtr, client_message, sizeof(struct PrimeHeader));

		uint64_t crc = crc64(0, (const char *)&primeHeader, sizeof(struct PrimeHeader) - sizeof(uint64_t));
		sprintf(client_message, (primeHeader.headercrc == crc) ? "1" : "0");
		if (primeHeader.headercrc != crc)
		{
			goto flush;
		}

		for (int i = 0; i < primeHeader.buffercount; i++)
		{
			bufferXPtr = (char *)&messageHeader;
			bytesRead = 0;
			if (fread(client_message, sizeof(struct MessageHeader), 1, file) == 0)
			{
				goto flush;
			}
			memcpy(bufferXPtr, client_message, sizeof(struct MessageHeader));

			char *bufferMsg = (char *)calloc(1, messageHeader.length + 1);
			if (messageHeader.length == 0)
			{
				debugLog("\"method\":\"load_file\",\"message\":\"empty message\"");
				sprintf(client_message, "1");
			}
			else
			{
				if (bufferMsg == NULL)
				{
					debugLog("\"method\":\"load_file\",\"message\":\"not enough memory to create message buffer\"");
					return;
				}

				char *bufferMsgPtr = bufferMsg;
				bytesRead = 0;
				int bytesToRead = messageHeader.length;
				if (messageHeader.length > 4096)
				{
					bytesToRead = 4096;
				}
				while ((read_result = fread(client_message, bytesToRead, 1, file)) > 0)
				{
					bytesRead += bytesToRead;
					memcpy(bufferMsgPtr, client_message, bytesToRead);
					bufferMsgPtr += bytesToRead;

					if (bytesRead + bytesToRead > messageHeader.length)
					{
						bytesToRead = messageHeader.length % 4096;
					}

					if (bytesRead >= messageHeader.length)
					{
						break;
					}
				}

				crc = crc64(0, (const char *)bufferMsg, messageHeader.length);
				sprintf(client_message, (messageHeader.msgcrc == crc) ? "1" : "0");
				if (messageHeader.msgcrc != crc)
				{
					if (bufferMsg)
					{
						free(bufferMsg);
						bufferMsg = NULL;
					}
					
					goto flush;
				}
			}

			//printf("action: %d\n", primeHeader.action);
			switch (primeHeader.action)
			{
				/// Domain
			case bufferType_domainCrcBuffer:
			{
				swapdomain_crc = (unsigned long long *)bufferMsg;
				swapdomain_crc_len = messageHeader.length / sizeof(unsigned long long);

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_domainAccuracyBuffer:
			{
				swapdomain_accuracy = (short *)bufferMsg;
				swapdomain_accuracy_len = messageHeader.length / sizeof(short);

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_domainFlagsBuffer:
			{
				swapdomain_flags = (unsigned long long *)bufferMsg;
				swapdomain_flags_len = messageHeader.length / sizeof(unsigned long long);

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}

			case bufferType_iprangecrc:
			{
				swapiprange_crc = (unsigned long long *)bufferMsg;
				swapiprange_crc_len = messageHeader.length / sizeof(unsigned long long);

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			/// IP Ranges
			case bufferType_iprangeipfrom:
			{
				if (swapiprange_low == NULL)
				{
					swapiprange_low = (struct ip_addr **)malloc(sizeof(struct ip_addr *) * primeHeader.buffercount);
				}
				//unsigned char* p = (unsigned char*)&primeHeader;
				//struct ip_addr *x = (struct ip_addr *)&bufferMsg;
				//printf("%08x\n", x->family);
				//printf("%08x\n", x->ipv4_sin_addr);
				//printf("%08x\n", x->ipv6_sin_addr);

				swapiprange_low[swapiprange_low_len++] = (struct ip_addr *)bufferMsg;

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_iprangeipto:
			{
				if (swapiprange_high == NULL)
				{
					swapiprange_high = (struct ip_addr **)malloc(sizeof(struct ip_addr *) * primeHeader.buffercount);
				}

				swapiprange_high[swapiprange_high_len++] = (struct ip_addr *)bufferMsg;

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_iprangeidentity:
			{
				if (swapiprange_identity == NULL)
				{
					swapiprange_identity = (char **)malloc(sizeof(char *) * primeHeader.buffercount);
				}

				swapiprange_identity[swapiprange_identity_len++] = bufferMsg;
				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_iprangepolicyid:
			{
				swapiprange_policy_id = (int *)bufferMsg;
				swapiprange_policy_id_len = messageHeader.length / sizeof(int);

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}

			//Policies
			case bufferType_policyid:
			{
				swappolicy_policy_id = (int *)bufferMsg;
				swappolicy_policy_id_len = messageHeader.length / sizeof(int);

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_policystrategy:
			{
				swappolicy_strategy = (int *)bufferMsg;
				swappolicy_strategy_len = messageHeader.length / sizeof(int);

				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_policyaudit:
			{
				swappolicy_audit = (int *)bufferMsg;
				swappolicy_audit_len = messageHeader.length / sizeof(int);
				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_policyblock:
			{
				swappolicy_block = (int *)bufferMsg;
				swappolicy_block_len = messageHeader.length / sizeof(int);
				if (bufferMsg)
				{
					bufferMsg = NULL;
				}

				break;
			}

			//Custom list
			case bufferType_identitybuffercount:
			{
				if (temp_customlist == NULL)
				{
					int *count = (int*)bufferMsg;
					temp_customlist = cache_customlist_init(*count);
					if (temp_customlist == NULL)
					{
						debugLog("\"method\":\"load_file\",\"error\":\"custom list init failed\"");
					}
				}

				if (bufferMsg != NULL)
				{
					free(bufferMsg);
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_identitybuffer:
			{
				if (swapcustomlist_identity)
				{
					debugLog("\"method\":\"load_file\",\"error\":\"swapcustomlist_identity not freed\"");
				}

				swapcustomlist_identity = (char *)bufferMsg;
				bufferMsg = NULL;
				break;
			}
			case bufferType_identitybufferwhitelist:
			{
				if (swapcustomlist_whitelist)
				{
					debugLog("\"method\":\"load_file\",\"error\":\"swapcustomlist_whitelist not freed\"");
				}

				//debugLog("whitelist init %d", messageHeader.length);
				swapcustomlist_whitelist = cache_domain_init_ex2((unsigned long long *)bufferMsg, messageHeader.length / sizeof(unsigned long long));
				bufferMsg = NULL;
				break;
			}
			case bufferType_identitybufferblacklist:
			{
				if (swapcustomlist_blacklist)
				{
					debugLog("\"method\":\"load_file\",\"error\":\"swapcustomlist_blacklist not freed\"");
				}

				//debugLog("blacklist init %d", messageHeader.length);
				swapcustomlist_blacklist = cache_domain_init_ex2((unsigned long long *)bufferMsg, messageHeader.length / sizeof(unsigned long long));
				bufferMsg = NULL;
				break;
			}
			case bufferType_identitybufferpolicyid:
			{
				swapcustomlist_policyid = (int *)bufferMsg;
				if (bufferMsg != NULL)
				{
					bufferMsg = NULL;
				}

				if (cache_customlist_add(temp_customlist, swapcustomlist_identity, swapcustomlist_whitelist, swapcustomlist_blacklist, swapcustomlist_policyid) != 0)
				{
					debugLog("\"method\":\"load_file\",\"error\":\"customlist add failed\"");
				}

				if (swapcustomlist_identity)
				{
					free(swapcustomlist_identity);
					swapcustomlist_identity = NULL;
				}
				if (swapcustomlist_whitelist)
				{
					cache_domain_destroy(swapcustomlist_whitelist);
					free(swapcustomlist_whitelist);
					swapcustomlist_whitelist = NULL;
				}
				if (swapcustomlist_blacklist)
				{
					cache_domain_destroy(swapcustomlist_blacklist);
					free(swapcustomlist_blacklist);
					swapcustomlist_blacklist = NULL;
				}
				if (swapcustomlist_policyid)
				{
					free(swapcustomlist_policyid);
					swapcustomlist_policyid = NULL;
				}

				break;
			}
			case bufferType_identitybufferflush:
			{
				cache_customlist *old_customlist = cached_customlist;
				cached_customlist = temp_customlist;
				temp_customlist = NULL;
				cache_customlist_destroy(old_customlist);
				if (old_customlist)
				{
					free(old_customlist);
					old_customlist = NULL;
				}

				if (bufferMsg)
				{
					free(bufferMsg);
					bufferMsg = NULL;
				}

				break;
			}
			case bufferType_loadfile:
			{
				//char *file = (char *)bufferMsg;

				if (bufferMsg != NULL)
				{
					free(bufferMsg);
					bufferMsg = NULL;
				}


				break;
			}
			}

			if (bufferMsg)
			{
				debugLog("\"method\":\"load_file\",\"message\":\"bufferMsg not NULL\"");
			}
		}

		if (primeHeader.action == bufferType_swapcache)
		{
			if ((swapdomain_crc_len != swapdomain_accuracy_len) || (swapdomain_crc_len != swapdomain_flags_len))
			{
				debugLog("\"method\":\"load_file\",\"message\":\"domain cache is corrupted %llu %llu %llu\"", swapdomain_crc_len, swapdomain_accuracy_len, swapdomain_flags_len);
				goto flush;
			}
			debugLog("\"method\":\"load_file\",\"message\":\"domain init %llu items\"", swapdomain_crc_len);
			if ((swapiprange_identity_len != swapiprange_high_len) || (swapiprange_low_len != swapiprange_high_len) || (swapiprange_low_len != swapiprange_policy_id_len))
			{
				debugLog("\"method\":\"load_file\",\"message\":\"iprange cache is corrupted\n identity=%llu\n high=%llu\n low=%llu\n policy=%llu\"",
					swapiprange_identity_len,
					swapiprange_high_len,
					swapiprange_low_len,
					swapiprange_policy_id_len);
				goto flush;
			}
			debugLog("\"method\":\"load_file\",\"message\":\"iprange init %llu items\"", swapiprange_identity_len);
			if ((swappolicy_policy_id_len != swappolicy_strategy_len) || (swappolicy_strategy_len != swappolicy_audit_len) || (swappolicy_audit_len != swappolicy_block_len))
			{
				debugLog("\"method\":\"load_file\",\"message\":\"policy cache is corrupted\n policy_id=%llu\n strategy=%llu\n audit=%llu\n block=%llu\"",
					swappolicy_policy_id_len,
					swappolicy_strategy_len,
					swappolicy_audit_len,
					swappolicy_block_len);
				goto flush;
			}
			
			debugLog("\"method\":\"load_file\",\"message\":\"policy init %llu items\"", swappolicy_policy_id_len);

			/*if ((swapcustomlist_identity_len != swapcustomlist_whitelist_len) || (swapcustomlist_whitelist_len != swapcustomlist_blacklist_len))
			{
				sprintf(message, "\"message\":\"ignoring error, customlist cache is corrupted\n identity=%llu\n whitelist=%llu\n blacklist=%llu\"",
					swapcustomlist_identity_len,
					swapcustomlist_whitelist_len,
					swapcustomlist_blacklist_len);
				debugLog(message);
				goto flush;
			}
			sprintf(message, "\"message\":\"customlist init %llu items\"", swapcustomlist_identity_len);
			debugLog(message);*/

			if (swapdomain_crc_len > 0)
			{
				debugLog("\"method\":\"load_file\",\"message\":\"initex domain %llu\"", swapdomain_crc_len);

				cache_domain *old_domain = cached_domain;
				cached_domain = cache_domain_init_ex(swapdomain_crc, swapdomain_accuracy, swapdomain_flags, swapdomain_crc_len);
				if (cached_domain == NULL)
				{
					debugLog("\"method\":\"load_file\",\"message\":\"unable to init domain\"");
				}

				debugLog("\"method\":\"load_file\",\"message\":\"destroy old domain\"");
				cache_domain_destroy(old_domain);
				if (old_domain)
				{
					free(old_domain);
					old_domain = NULL;
				}
			}
			else
			{
				debugLog("\"method\":\"load_file\",\"message\":\"initex domain has no items\"");
			}

			if (swapiprange_high_len > 0)
			{
				debugLog("\"method\":\"load_file\",\"message\":\"initex iprange %llu\"", swapiprange_high_len);

				cache_iprange *old_iprange = cached_iprange;
				cached_iprange = cache_iprange_init_ex(swapiprange_crc, swapiprange_low, swapiprange_high, swapiprange_identity, swapiprange_policy_id, swapiprange_high_len);
				if (cached_iprange == NULL)
				{
					debugLog("\"method\":\"load_file\",\"message\":\"unable to init iprange\"");
				}

				debugLog("\"method\":\"load_file\",\"message\":\"destroy old iprange\"");
				cache_iprange_destroy(old_iprange);
				if (old_iprange)
				{
					free(old_iprange);
					old_iprange = NULL;
				}
			}
			else
			{
				debugLog("\"method\":\"load_file\",\"message\":\"initex iprange has no items\"");
			}

			if (swappolicy_policy_id_len > 0)
			{
				debugLog("\"method\":\"load_file\",\"message\":\"initex policy %llu\"", swappolicy_policy_id_len);

				cache_policy *old_policy = cached_policy;
				cached_policy = cache_policy_init_ex(swappolicy_policy_id, swappolicy_strategy, swappolicy_audit, swappolicy_block, swappolicy_policy_id_len);
				if (cached_policy == NULL)
				{
					debugLog("\"method\":\"load_file\",\"message\":\"unable to init policy\"");
				}

				debugLog("\"method\":\"load_file\",\"message\":\"destroy old policy\"");
				cache_policy_destroy(old_policy);
				if (old_policy)
				{
					free(old_policy);
					old_policy = NULL;
				}
			}
			else
			{
				debugLog("\"method\":\"load_file\",\"message\":\"initex policy has no items\"");
			}

			//if (swapcustomlist_identity_len > 0)
			//{
			//	sprintf(message, "\"message\":\"initex customlist %llu\"", swapcustomlist_identity_len);
			//	debugLog(message);

			//	cache_customlist *old_customlist = cached_customlist;
			//	cached_customlist = cache_customlist_init_ex(swapcustomlist_identity, swapcustomlist_whitelist, swapcustomlist_blacklist, swapcustomlist_policyid, swapcustomlist_identity_len);

			//	sprintf(message, "\"message\":\"destroy old customlist\"");
			//	cache_customlist_destroy(old_customlist);
			//}
			//else
			//{
			//	sprintf(message, "\"message\":\"initex customlist has no items\"");
			//	debugLog(message);
			//}

			swapdomain_crc = NULL;
			swapdomain_accuracy = NULL;
			swapdomain_flags = NULL;
			swapdomain_crc_len = 0;
			swapdomain_accuracy_len = 0;
			swapdomain_flags_len = 0;

			swapiprange_crc = NULL;
			swapiprange_low = NULL;
			swapiprange_high = NULL;
			swapiprange_identity = NULL;
			swapiprange_policy_id = NULL;
			swapiprange_crc_len = 0;
			swapiprange_low_len = 0;
			swapiprange_high_len = 0;
			swapiprange_identity_len = 0;
			swapiprange_policy_id_len = 0;

			swappolicy_policy_id = NULL;
			swappolicy_strategy = NULL;
			swappolicy_audit = NULL;
			swappolicy_block = NULL;
			swappolicy_policy_id_len = 0;
			swappolicy_strategy_len = 0;
			swappolicy_audit_len = 0;
			swappolicy_block_len = 0;

			swapcustomlist_identity = NULL;
			swapcustomlist_whitelist = NULL;
			swapcustomlist_blacklist = NULL;
			swapcustomlist_identity_len = 0;
			swapcustomlist_whitelist_len = 0;
			swapcustomlist_blacklist_len = 0;

		}
		if (primeHeader.action == bufferType_freeswaps)
		{
			//printf("free\n");

			// Domains        
			if (swapdomain_crc != NULL)
			{
				//printf(" domain crc\n");
				free(swapdomain_crc);
				swapdomain_crc = NULL;
				swapdomain_crc_len = 0;
			}
			if (swapdomain_accuracy != NULL)
			{
				//printf(" domain accuracy\n");
				free(swapdomain_accuracy);
				swapdomain_accuracy = NULL;
				swapdomain_accuracy_len = 0;
			}
			if (swapdomain_flags != NULL)
			{
				//printf(" domain flags\n");
				free(swapdomain_flags);
				swapdomain_flags = NULL;
				swapdomain_flags_len = 0;
			}

			// IP Ranges
			if (swapiprange_crc != NULL)
			{
				//printf(" domain crc\n");
				free(swapiprange_crc);
				swapiprange_crc = NULL;
				swapiprange_crc_len = 0;
			}
			if (swapiprange_low != NULL)
			{
				//printf(" iprange low\n");
				for (int i = 0; i < swapiprange_low_len; i++)
				{
					free(swapiprange_low[i]);
				}

				free(swapiprange_low);
				swapiprange_low = NULL;
				swapiprange_low_len = 0;
			}
			if (swapiprange_high != NULL)
			{
				//printf(" iprange high\n");  
				for (int i = 0; i < swapiprange_high_len; i++)
				{
					free(swapiprange_high[i]);
				}

				free(swapiprange_high);
				swapiprange_high = NULL;
				swapiprange_high_len = 0;
			}
			if (swapiprange_identity != NULL)
			{
				//printf(" iprange identity\n");
				for (int i = 0; i < swapiprange_identity_len; i++)
				{
					if (swapiprange_identity[i])
					{
						free(swapiprange_identity[i]);
						swapiprange_identity[i] = NULL;
					}
				}

				free(swapiprange_identity);
				swapiprange_identity = NULL;
				swapiprange_identity_len = 0;
			}
			if (swapiprange_policy_id != NULL)
			{
				//printf(" iprange policy_id\n");
				free(swapiprange_policy_id);
				swapiprange_policy_id = NULL;
				swapiprange_policy_id_len = 0;
			}

			// Policy
			if (swappolicy_policy_id != NULL)
			{
				//printf(" policy policy_id\n");
				free(swappolicy_policy_id);
				swappolicy_policy_id = NULL;
				swappolicy_policy_id_len = 0;
			}
			if (swappolicy_strategy != NULL)
			{
				//printf(" policy strategy\n");
				free(swappolicy_strategy);
				swappolicy_strategy = NULL;
				swappolicy_strategy_len = 0;
			}
			if (swappolicy_audit != NULL)
			{
				//printf(" policy audit\n");
				free(swappolicy_audit);
				swappolicy_audit = NULL;
				swappolicy_audit_len = 0;
			}
			if (swappolicy_block != NULL)
			{
				//printf(" policy blopraock\n");
				free(swappolicy_block);
				swappolicy_block = NULL;
				swappolicy_block_len = 0;
			}

			// Customlist
			if (swapcustomlist_identity != NULL)
			{
				//printf(" customlist identity\n");
				free(swapcustomlist_identity);
				swapcustomlist_identity = NULL;
				swapcustomlist_identity_len = 0;
			}
			if (swapcustomlist_whitelist != NULL)
			{
				//printf(" customlist whitelist\n");
				free(swapcustomlist_whitelist);
				swapcustomlist_whitelist = NULL;
				swapcustomlist_whitelist_len = 0;
			}
			if (swapcustomlist_blacklist != NULL)
			{
				//printf(" customlist blacklist\n");
				free(swapcustomlist_blacklist);
				swapcustomlist_blacklist = NULL;
				swapcustomlist_blacklist_len = 0;
			}
			//if (swapcustomlist_policyid != NULL)
			//{
			//	//printf(" customlist blacklist\n");
			//	//free(swapcustomlist_policyid);
			//	swapcustomlist_policyid = NULL;
			//	swapcustomlist_policyid_len = 0;
			//}
		}
	}

flush:
	fclose(file);

	debugLog("\"method\":\"load_file\",\"message\":\"finished loading file\",\"file\":\"%s\"", filename);

	return;
}