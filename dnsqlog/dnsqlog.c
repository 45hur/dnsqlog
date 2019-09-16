#define C_MOD_DNSQLOG "\x07""dnsqlog"

#include "log.h"
#include "program.h"
#include "dnsqlog.h"

#ifndef NOKRES

#include <arpa/inet.h>

int begin(kr_layer_t *ctx)
{
	debugLog("\"%s\":\"%s\"", "debug", "begin");

	return process(ctx);
}

int consume(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	debugLog("\"%s\":\"%s\"", "debug", "consume");
	
	return process(ctx);
}

int produce(kr_layer_t *ctx, knot_pkt_t *pkt)
{
	debugLog("\"%s\":\"%s\"", "debug", "produce");

	return process(ctx);
}

int finish(kr_layer_t *ctx)
{
	debugLog("\"%s\":\"%s\"", "debug", "finish");

	return process(ctx);
}


int process(kr_layer_t *ctx)
{
	char userIpAddressString[256] = { 0 };
	int err = 0;
	struct ip_addr userIpAddress = { 0 };

	if ((err = getip(ctx, (char *)&userIpAddressString, &userIpAddress)) != 0)
	{
		//return err; generates log message --- [priming] cannot resolve '.' NS, next priming query in 10 seconds
		//we do not care about no address sources
		debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "process", "getip", err);

		return ctx->state;
	}

	char qname_str[KNOT_DNAME_MAXLEN] = { 0 };
	int rr = 0;
	if ((err = checkDomain((char *)&qname_str, &rr, ctx, &userIpAddress, (char *)&userIpAddressString)) != 0)
	{
		if (err == 1) //redirect
		{
			//debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "process", "redirect", err);
			//return redirect(ctx, rr, (char *)&qname_str);
		}
		else
		{
			debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "process", "getdomain", err);
			ctx->state = KR_STATE_FAIL;
		}
	}

	return ctx->state;
}

int checkDomain(char * qname_Str, int * r, kr_layer_t *ctx, struct ip_addr *userIpAddress, const char *userIpAddressString)
{
	struct kr_request *request = (struct kr_request *)ctx->req;
	struct kr_rplan *rplan = &request->rplan;

	if (rplan->resolved.len > 0)
	{
		//bool sinkit = false;
		//uint16_t rclass = 0;
		/*struct kr_query *last = */
		//array_tail(rplan->resolved);
		const knot_pktsection_t *ns = knot_pkt_section(request->answer, KNOT_ANSWER);

		if (ns == NULL)
		{
			debugLog("\"method\":\"getdomain\",\"message\":\"ns = NULL\"");
			return -1;
		}

		if (ns->count == 0)
		{
			//debugLog("\"method\":\"getdomain\",\"message\":\"query has no asnwer\"");

			const knot_pktsection_t *au = knot_pkt_section(request->answer, KNOT_AUTHORITY);
			for (unsigned i = 0; i < au->count; ++i)
			{
				const knot_rrset_t *rr = knot_pkt_rr(au, i);

				if (rr->type == KNOT_RRTYPE_SOA)
				{
					char querieddomain[KNOT_DNAME_MAXLEN] = {};
					knot_dname_to_str(querieddomain, rr->owner, KNOT_DNAME_MAXLEN);

					int domainLen = strlen(querieddomain);
					if (querieddomain[domainLen - 1] == '.')
					{
						querieddomain[domainLen - 1] = '\0';
					}

					//debugLog("\"method\":\"getdomain\",\"message\":\"authority for %s\"", querieddomain);

					return 0; // explode((char *)&querieddomain, userIpAddress, userIpAddressString, rr->type);
				}
				else
				{
					//debugLog("\"method\":\"getdomain\",\"message\":\"authority rr type is not SOA [%d]\"", (int)rr->type);
				}
			}
		}

		const knot_pktsection_t *an = knot_pkt_section(request->answer, KNOT_ANSWER);
		//debugLog("\"method\":\"getdomain\",\"message\":\"an count [%d]", (int)an->count);
		for (unsigned i = 0; i < an->count; ++i)
		{
			const knot_rrset_t *rr = knot_pkt_rr(an, i);
			
			size_t buflen = 8192;
			char *buf = calloc(buflen, 1);
			knot_dump_style_t style = {0};
			style.verbose = true;
			style.show_class = true;
			for (uint16_t j = 0; j < rr->rrs.count; j++) 
			{			
				while (knot_rrset_txt_dump_data(rr, j, buf, buflen, &style) < 0) 
				{
					buflen += 4096;
					if (buflen > 100000) {
						//WARN("can't print whole section\n");
						break;
					}

					char *newbuf = realloc(buf, buflen);
					if (newbuf == NULL) {
						//WARN("can't print whole section\n");
						break;
					}

					buf = newbuf;
				}

				if (strlen(buf) <= 3)
				{
					free (buf);
					buflen = 8192;
					buf = calloc(buflen, 1);
					while (knot_rrset_txt_dump(rr, buf, buflen, &style) < 0)
					{
						buflen += 4096;
						if (buflen > 100000) {
							//WARN("can't print whole section\n");
							break;
						}

						char *newbuf = realloc(buf, buflen);
						if (newbuf == NULL) {
							//WARN("can't print whole section\n");
							break;
						}

						buf = newbuf;
					}
				}

				char querieddomain[KNOT_DNAME_MAXLEN];
				knot_dname_to_str(querieddomain, rr->owner, KNOT_DNAME_MAXLEN);

				int domainLen = strlen(querieddomain);
				if (querieddomain[domainLen - 1] == '.')
				{
					querieddomain[domainLen - 1] = '\0';
				}

				if (increment(userIpAddressString, querieddomain, buf, rr->type) == 1)
				{
					if (rr->type == KNOT_RRTYPE_A)
					{
						fileLog("\"client\":\"%s\",\"query\":\"%s\",\"type\":\"A\",\"answer\":\"%s\",\"ttl\":\"%d\"", userIpAddressString, querieddomain, buf, rr->ttl);
					}
					else if (rr->type == KNOT_RRTYPE_AAAA)
					{
						fileLog("\"client\":\"%s\",\"query\":\"%s\",\"type\":\"AAAA\",\"answer\":\"%s\",\"ttl\":\"%d\"", userIpAddressString, querieddomain, buf, rr->ttl);
					}
					else if (rr->type == KNOT_RRTYPE_CNAME)
					{
						fileLog("\"client\":\"%s\",\"query\":\"%s\",\"type\":\"CNAME\",\"answer\":\"%s\",\"ttl\":\"%d\"", userIpAddressString, querieddomain, buf, rr->ttl);
					}
					else
					{
						fileLog("\"client\":\"%s\",\"query\":\"%s\",\"type\":\"%d\",\"answer\":\"%s\",\"ttl\":\"%d\"", userIpAddressString, querieddomain, rr->type, buf, rr->ttl);
					}
				}
			}
		}

		for (unsigned i = 0; i < ns->count; ++i)
		{
			const knot_rrset_t *rr = knot_pkt_rr(ns, i);

			if (rr->type == KNOT_RRTYPE_A || rr->type == KNOT_RRTYPE_AAAA || rr->type == KNOT_RRTYPE_CNAME || rr->type == KNOT_RRTYPE_TXT)
			{
				char querieddomain[KNOT_DNAME_MAXLEN];
				knot_dname_to_str(querieddomain, rr->owner, KNOT_DNAME_MAXLEN);

				int domainLen = strlen(querieddomain);
				if (querieddomain[domainLen - 1] == '.')
				{
					querieddomain[domainLen - 1] = '\0';
				}

				//debugLog("\"method\":\"getdomain\",\"message\":\"query for %s type %d", querieddomain, rr->type);
				strcpy(qname_Str, querieddomain);
				*r = rr->type;
				return 0; //explode((char *)&querieddomain, userIpAddress, userIpAddressString, rr->type);
			}
			else
			{
				debugLog("\"method\":\"getdomain\",\"message\":\"rr type is not A, AAAA, TXT or CNAME [%d]\"", (int)rr->type);
			}
		}
	}
	else
	{
		debugLog("\"method\":\"getdomain\",\"message\":\"query has no resolve plan\"");
	}

	debugLog("\"method\":\"getdomain\",\"message\":\"return\"");

	return 0;
}

int getip(kr_layer_t *ctx, char *address, struct ip_addr *req_addr)
{
	struct kr_request *request = (struct kr_request *)ctx->req;

	if (!request->qsource.addr) {
		debugLog("\"%s\":\"%s\"", "error", "no source address");

		return -1;
	}

	const struct sockaddr *res = request->qsource.addr;
	switch (res->sa_family)
	{
	case AF_INET:
	{
		struct sockaddr_in *addr_in = (struct sockaddr_in *)res;
		inet_ntop(AF_INET, &(addr_in->sin_addr), address, INET_ADDRSTRLEN);
		req_addr->family = AF_INET;
		memcpy(&req_addr->ipv4_sin_addr, &(addr_in->sin_addr), 4);
		break;
	}
	case AF_INET6:
	{
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)res;
		req_addr->family = AF_INET6;
		memcpy(&req_addr->ipv6_sin_addr, &(addr_in6->sin6_addr), 16);
		memset((unsigned char *)&req_addr->ipv6_sin_addr + 8, 0, 8); 
		inet_ntop(AF_INET6, &req_addr->ipv6_sin_addr, address, INET6_ADDRSTRLEN);
		break;
	}
	default:
	{
		debugLog("\"%s\":\"%s\"", "error", "qsource invalid");

		return -1;
	}
	}

	return 0;
}

int parse_addr_str(struct sockaddr_storage *sa, const char *addr) 
{
	int family = strchr(addr, ':') ? AF_INET6 : AF_INET;
	memset(sa, 0, sizeof(struct sockaddr_storage));
	sa->ss_family = family;
	char *addr_bytes = (char *)kr_inaddr((struct sockaddr *)sa);
	if (inet_pton(family, addr, addr_bytes) < 1) 
	{
		return kr_error(EILSEQ);
	}
	return 0;
}

KR_EXPORT 
int dnsqlog_init(struct kr_module *module)
{
	int err = 0;

	void *args = NULL;
	if ((err = create(&args)) != 0)
	{
		debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "dnsqlog_init", "create", err);
		return kr_error(err);
	}

	static kr_layer_api_t layer = {
		.finish = &finish,
	};
	layer.data = module;
	module->layer = &layer;
	module->data = (void *)args;
	
	return kr_ok();
}

KR_EXPORT 
int dnsqlog_deinit(struct kr_module *module)
{
	int err = 0;
	if ((err = destroy((void *)module->data)) != 0)
	{
		debugLog("\"%s\":\"%s\",\"%s\":\"%x\"", "error", "dnsqlog_deinit", "destroy", err);
		return kr_error(err);
	}

	return kr_ok();
}

KR_MODULE_EXPORT(dnsqlog)

#endif