#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <WinSock2.h>

typedef struct mac_address
{
	u_char byte[12];
}mac_address;

typedef struct ip_address
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

typedef struct ip_header
{
	u_char	ver_ihl;	
	u_char	tos;			
	u_short tlen;			
	u_short identification; 
	u_short flags_fo;		
	u_char	ttl;			
	u_char	proto;			
	u_short crc;			
	ip_address	saddr;		
	ip_address	daddr;		
	u_int	op_pad;			
}ip_header;

typedef struct udp_header
{
	u_short sport;			
	u_short dport;			
	u_short len;			
	u_short crc;			
}udp_header;

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);

int main()
{
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "mac and ip";
	struct bpf_program fcode;

	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "非法输入: %s\n", errbuf);
		exit(1);
	}

	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (没有可选网卡)\n");
	}

	printf("选择监听网卡 (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\n超出可选\n");

		pcap_freealldevs(alldevs);
		return -1;
	}

	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

	if ((adhandle = pcap_open_live(d->name, 65536, 1, 1000,	errbuf)) == NULL)
	{
		fprintf(stderr, "\n无法调用该网卡 %s\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\n该程序只能监听网卡\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;

	printf("\n正在监听 %s...\n", d->description);

	pcap_freealldevs(alldevs);

	pcap_loop(adhandle, 0, packet_handler, NULL);

	return 0;
}

void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	char timestr[64];
	ip_header* ih;
	udp_header* uh;
	u_int ip_len;
	u_short sport, dport;
	time_t local_tv_sec;

	(VOID)(param);

	local_tv_sec = header->ts.tv_sec;
	ltime = localtime(&local_tv_sec);
	strftime(timestr, sizeof timestr, "%Y-%m-%d %H:%M:%S", ltime);

	
	printf("%s,", timestr);

	
	ih = (ip_header*)(pkt_data + 14); 

	mac_address ic;
	strncpy(ic.byte, pkt_data, 12);
	
	ip_len = (ih->ver_ihl & 0xf) * 4;
	uh = (udp_header*)((u_char*)ih + ip_len);

	
	sport = ntohs(uh->sport);
	dport = ntohs(uh->dport);

	int tot = 0;
	
	printf("%02X-%02X-%02X-%02X-%02X-%02X,%d.%d.%d.%d,%02X-%02X-%02X-%02X-%02X-%02X,%d.%d.%d.%d\n",
		ic.byte[tot++], ic.byte[tot++], ic.byte[tot++], ic.byte[tot++], ic.byte[tot++], ic.byte[tot++],
		ih->saddr.byte1,
		ih->saddr.byte2,
		ih->saddr.byte3,
		ih->saddr.byte4,
		ic.byte[tot++], ic.byte[tot++], ic.byte[tot++], ic.byte[tot++], ic.byte[tot++], ic.byte[tot++],
		ih->daddr.byte1,
		ih->daddr.byte2,
		ih->daddr.byte3,
		ih->daddr.byte4
		);
}
