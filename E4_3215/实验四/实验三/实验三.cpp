#include <bits/stdc++.h>
#include <pcap.h>
using namespace std;

ofstream out("mark.txt");

map<string, string[3]> ftp;
bool flag;

typedef struct mac_header
{
	u_char dest_addr[6];
	u_char src_addr[6];
	u_char type[2];
} mac_header;


/* IPv4 首部 ,20字节*/
typedef struct ip_header 
{
	u_char  ver_ihl, tos;       
	u_short tlen, identification, flags_fo;   
	u_char  ttl, proto; 
	u_short crc; 
	u_char  saddr[4], daddr[4]; 
	u_int   op_pad;  
}ip_header;


void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data);
string get_request_m_ip_message(const u_char* pkt_data);
string get_response_m_ip_message(const u_char* pkt_data);
void print(const struct pcap_pkthdr* header, string m_ip_message);
string get_time();


int main()
{
	flag = false;
	pcap_if_t* alldevs;
	pcap_if_t* d;
	int inum;
	int i = 0;
	pcap_t* adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_int netmask;
	char packet_filter[] = "tcp";
	struct bpf_program fcode;

	/* 获得设备列表 */
	if (pcap_findalldevs_ex((char*)PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
	{
		fprintf(stderr, "找不到设备: %s\n", errbuf);
		exit(1);
	}

	/* 打印列表 */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (没有可用设备)\n");
	}

	if (i == 0)
	{
		printf("\n找不到接口！确保已安装WinPcap。\n");
		return -1;
	}

	printf("输入接口号 （1-%d）:", i);
	scanf_s("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\n接口号超出范围。\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* 打开适配器 */
	for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);
	if ((adhandle = pcap_open(d->name, 65536, PCAP_OPENFLAG_PROMISCUOUS, 1000, NULL, errbuf)) == NULL)
	{
		fprintf(stderr, "\n无法打开适配器。WinPcap不支持%s\n", d->name);
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_datalink(adhandle) != DLT_EN10MB)
	{
		fprintf(stderr, "\n这个程序只在以太网上运行。\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (d->addresses != NULL)
		netmask = ((struct sockaddr_in*)(d->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask = 0xffffff;


	//编译过滤器  
	if (pcap_compile(adhandle, &fcode, packet_filter, 1, netmask) < 0)
	{
		fprintf(stderr, "\n无法编译包筛选器。请检查语法。\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	if (pcap_setfilter(adhandle, &fcode) < 0)
	{
		fprintf(stderr, "\n设置筛选器时出错。\n");
		pcap_freealldevs(alldevs);
		return -1;
	}

	printf("\n正在监听%s...\n", d->description);

	pcap_freealldevs(alldevs);

	/* 开始捕捉 */
	pcap_loop(adhandle, 0, packet_handler, NULL);
	return 0;
}

string get_time()
{
	time_t timep;
	time(&timep);
	char ret[64];
	strftime(ret, sizeof(ret), "%Y-%m-%d %H:%M:%S", localtime(&timep));
	return ret;
}

/*帧格式处理*/
void packet_handler(u_char* param, const struct pcap_pkthdr* header, const u_char* pkt_data)
{
	struct tm* ltime;
	string timestr = get_time();
	ip_header* ih;
	u_int ip_len;
	u_short sport, dport;

	int head = 54;
	string com;
	for (int i = 0; i < 4; i++) com += (char)pkt_data[head + i];

	if (com == "USER")
	{
		string m_ip_message = get_request_m_ip_message(pkt_data);
		string user;
		ostringstream sout;
		for (int i = head + 5; pkt_data[i] != 13; i++) sout << pkt_data[i];
		user = sout.str();
		ftp[m_ip_message][0] = user;
	}
	else if (com == "PASS")
	{
		string m_ip_message = get_request_m_ip_message(pkt_data);
		string pass;
		ostringstream sout;

		for (int i = head + 5; pkt_data[i] != 13; i++) 
			sout << pkt_data[i];
		
		pass = sout.str();
		ftp[m_ip_message][1] = pass;
	}

	if (com == "230 ")
	{
		string m_ip_message = get_response_m_ip_message(pkt_data);
		ftp[m_ip_message][2] = "SUCCEED";
		print(header, m_ip_message);
	}
	else if (com == "530 ")
	{
		string m_ip_message = get_response_m_ip_message(pkt_data);
		ftp[m_ip_message][2] = "FAILD";
		print(header, m_ip_message);
	}
}

string get_request_m_ip_message(const u_char* pkt_data)
{
	mac_header* mh;
	ip_header* ih;
	string m_ip_message;
	ostringstream sout;
	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));

	for (int i = 0; i < 5; i++)
		sout << hex << (int)(mh->src_addr[i]) << "-";
	sout << (int)(mh->src_addr[5]) << ",";

	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->saddr[i]) << ".";
	sout << (int)(ih->saddr[3]) << ",";

	for (int i = 0; i < 5; i++)
		sout << hex << (int)(mh->dest_addr[i]) << "-";
	sout << (int)(mh->dest_addr[5]) << ",";

	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->daddr[i]) << ".";
	sout << (int)(ih->daddr[3]);

	m_ip_message = sout.str();
	return m_ip_message;
}

string get_response_m_ip_message(const u_char* pkt_data)
{
	mac_header* mh;
	ip_header* ih;
	string m_ip_message;
	ostringstream sout;
	int length = sizeof(mac_header) + sizeof(ip_header);
	mh = (mac_header*)pkt_data;
	ih = (ip_header*)(pkt_data + sizeof(mac_header));

	for (int i = 0; i < 5; i++)
		sout << hex << (int)(mh->dest_addr[i]) << "-";
	sout << (int)(mh->dest_addr[5]) << ",";

	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->daddr[i]) << ".";
	sout << (int)(ih->daddr[3]) << ",";

	for (int i = 0; i < 5; i++)
		sout << hex << (int)(mh->src_addr[i]) << "-";
	sout << (int)(mh->src_addr[5]) << ",";

	for (int i = 0; i < 3; i++)
		sout << dec << (int)(ih->saddr[i]) << ".";
	sout << (int)(ih->saddr[3]);

	m_ip_message = sout.str();
	return m_ip_message;
}

/*打印时间戳*/
void print(const struct pcap_pkthdr* header, string m_ip_message)
{
	struct tm* ltime;
	string timestr = get_time();

	cout << timestr << ",";
	cout << m_ip_message << ",";
	for (int i = 0; i < 2; i++)
		cout << ftp[m_ip_message][i] << ",";
	cout << ftp[m_ip_message][2] << endl;

	string ftp_ip(m_ip_message, 44);
	out << "FTP:" << ftp_ip << "	USR:" << ftp[m_ip_message][0]
		<< "	PAS:" << ftp[m_ip_message][1] << "	STA:" << ftp[m_ip_message][2] << endl;
}