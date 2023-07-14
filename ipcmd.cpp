// ipcmd.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#define MAXPACKETSIZE 65540
#define SIO_RCVALL _WSAIOW(IOC_VENDOR,1)


int numpackets;

void EXITMSG(int code)
{
	printf("\npicked up %d packets\n", numpackets);
	exit(0);
}

int usage (char * argv)
{
	printf("\n%s version 1.6\nCoded by Ansar Mohammed\n",argv);
	printf("email: ansarm@microsoft.com\n");
	printf("Version date: January 2003\n");
	printf("comments are welcome!!!\n\n");
	printf("%s displays information about packets moving within an IP subnet\n\n", argv);
	printf("usage:\n");
	printf("%s ipaddr [-ftcp] [-fudp] [-fsyn] [-dx] [-dc] [-dp destport] [-t]\n\n ",argv);
	printf("ipaddr\t\t :local ip address on subnet\n",argv);
	printf("-ftcp\t\t :only tcp packets\n");
	printf("-fudp\t\t :only udp packets\n");
	printf("-fsyn\t\t :only syn packets\n");
	printf("-dx\t\t :dump data(packet minus ip header) in hex\n");
	printf("-dc\t\t :dump data(packet minus ip header) in char\n");
	printf("-p\t port\t :filter by destination/port udp/tcp port\n");
	printf("-t\t\t :print date and time of packets\n");
	return 0;
}

int main(int argc, char* argv[])
{
	
	IP_HDR *ipHdr;
	TCP_IP_HDR * tcpipHdr;
	UDP_IP_HDR * udpipHdr;
	SOCKET s;
	char  buffer[MAXPACKETSIZE];
	int loop, port;
	DWORD 	ioctl_in=1, outbytes;
	SOCKADDR_IN localaddr;
	in_addr * sourceaddr,* destaddr;
	char ip[20];
	WSADATA wsaData;
	int dont_log_packets=1, 
		got_filter_syn=0,
		got_filter_tcp=0,
		got_filter_udp=0,
		log_data_in_hex=0,
		log_data_in_char=0,
		got_get_all_packets=1,
		filter_ports=0,
		got_time=0;

	__time64_t thetime;
	
	signal(SIGINT,EXITMSG);

	numpackets=0;

	if (argc <2)
	{
		usage(argv[0]);
		return (0);
	}
	else
	{
		strcpy(ip, argv[1]);
		if (inet_addr(ip)==INADDR_NONE)
		{	
			printf("Invalid IP\n");
			return (0);
		}
		for(loop=1;loop<argc;loop++)
			{
				if (stricmp(argv[loop], "-ftcp")==0)
					got_filter_tcp=1;
				if (stricmp(argv[loop], "-fudp")==0)
					got_filter_udp=1;

				if (stricmp(argv[loop], "-dx")==0)
					log_data_in_hex=1;
				
				if (stricmp(argv[loop], "-dc")==0)
					log_data_in_char=1;
				
				if (stricmp(argv[loop], "-t")==0)
					got_time=1;
				
				if (stricmp(argv[loop], "-fsyn")==0)
				{
					got_filter_syn=1;
					got_filter_tcp=1;
				}
				if (stricmp(argv[loop],"-p")==0)
				{
					filter_ports=1;
					port=atoi(argv[loop+1]);
				}
			}
	}
	if ((got_filter_syn==1) || (got_filter_tcp==1) ||
		(got_filter_udp==1))
		got_get_all_packets=0;
				
	ZeroMemory(buffer,MAXPACKETSIZE);
	
	WSAStartup(MAKEWORD(2,2), &wsaData);
	s=WSASocket(AF_INET,SOCK_RAW, 0, 0,0,0);
	
	localaddr.sin_family=AF_INET;
	localaddr.sin_addr.s_addr = inet_addr (ip);
	localaddr.sin_port=7000;
	bind(s,(SOCKADDR*)&localaddr, sizeof(localaddr));
	WSAIoctl(s, SIO_RCVALL ,&ioctl_in,sizeof(ioctl_in), NULL, NULL, &outbytes, NULL, NULL);
	if ((log_data_in_hex==0) && (	log_data_in_char ==0))
	{
		if (got_time==1)
            printf("SrcIP\t\tDestIP\t\tsize\tProt\tSrcport\tDstport\tControl\tTime\n");
		else
			printf("SrcIP\t\tDestIP\t\tsize\tProt\tSrcport\tDstport\tControl\n");
	}
	while(true)
	{
		recvfrom(s, buffer, MAXPACKETSIZE, 0, NULL,NULL);
		ipHdr = (IP_HDR *)buffer;
		if (ipHdr->ip_protocol ==6)
		{
			if ((got_filter_tcp==1) ||
				(got_get_all_packets==1))
			{ 
				tcpipHdr =(TCP_IP_HDR*)buffer;
				if (((filter_ports==1)&&((ntohs(tcpipHdr->tcpHdr.source)==port)||
					(ntohs(tcpipHdr->tcpHdr.dest)==port)))|| (filter_ports==0))
				{
					if ((got_filter_syn==1) &&((tcpipHdr->tcpHdr.control & 0x02)==0x02) || (got_filter_syn==0))
					{
						sourceaddr = (in_addr*)(&tcpipHdr->ipHdr.ip_srcaddr);
						destaddr = (in_addr*)(&tcpipHdr->ipHdr.ip_destaddr);
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nSource Address: ");
						printf("%s\t", inet_ntoa(*sourceaddr));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nDestiniation Address: ");
						printf("%s\t", inet_ntoa(*destaddr));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nIP Packet Length: ");
						printf("%d\t",ntohs( tcpipHdr->ipHdr.ip_totallength));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nIP Protocol: ");
						printf("%d\t",tcpipHdr->ipHdr.ip_protocol);
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nSource Port: ");
						printf("%d\t", htons(tcpipHdr->tcpHdr.source));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nDestination Port: ");
						printf("%d\t", htons(tcpipHdr->tcpHdr.dest));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nControl: ");
						if ((tcpipHdr->tcpHdr.control & FIN )== FIN)
							printf(" FIN");
						if ((tcpipHdr->tcpHdr.control & SYN )== SYN)
							printf(" SYN");
						if ((tcpipHdr->tcpHdr.control & ACK )== ACK)
							printf(" ACK");
						if ((tcpipHdr->tcpHdr.control & PSH )== PSH)
							printf(" PSH");
						if ((tcpipHdr->tcpHdr.control & URG )== URG)
							printf(" URG");
						if ((tcpipHdr->tcpHdr.control & RST )== RST)
							printf(" RST");
						printf("\t");
						if (got_time==1)
						{
							if ((log_data_in_hex==1) || (	log_data_in_char ==1))
								printf("\nTime: ");
							_time64(&thetime);
							printf("%s ", _ctime64(&thetime));
						}
						else
							printf("\n");
						numpackets++;
					}
				}
			}
		}
		else
			if (ipHdr->ip_protocol ==17)
			{	
				if ((got_filter_udp==1) ||
				(got_get_all_packets==1))
				{
					udpipHdr = (UDP_IP_HDR*)buffer;	
					if (((filter_ports==1)&&((ntohs(udpipHdr->udpHdr.src_portno)==port)||
						(ntohs(udpipHdr->udpHdr.dst_portno)==port)))|| (filter_ports==0))
					{
						sourceaddr = (in_addr*)(&udpipHdr->ipHdr.ip_srcaddr);
						destaddr = (in_addr*)(&udpipHdr->ipHdr.ip_destaddr);
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nSource Address: ");
						printf("%s\t", inet_ntoa(*sourceaddr));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nDestination Address: ");
						printf("%s\t", inet_ntoa(*destaddr));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nIP Packet Length: ");
						printf("%d\t",ntohs( udpipHdr->ipHdr.ip_totallength));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nIP Protocol: ");
						printf("%d\t",udpipHdr->ipHdr.ip_protocol);
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nSource Port: ");
						printf("%d\t", htons(udpipHdr->udpHdr.src_portno));
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nDestination Port: ");
						printf("%d\t", htons(udpipHdr->udpHdr.dst_portno));
						if (got_time==1)
						{
							if ((log_data_in_hex==1) || (	log_data_in_char ==1))
								printf("\nTime: ");
							_time64(&thetime);
							printf("\t%s ", _ctime64(&thetime));
						}
						else
							printf("\n");
						numpackets++;
		
					}
				}
			}
			else
				if ((got_get_all_packets==1))
				{
					ipHdr = (IP_HDR *)buffer;
					sourceaddr = (in_addr*)(&ipHdr->ip_srcaddr);
					destaddr = (in_addr*)(&ipHdr->ip_destaddr);
					if ((log_data_in_hex==1) || (	log_data_in_char ==1))
						printf("\nSource Address: ");
					printf("%s\t", inet_ntoa(*sourceaddr) );
					if ((log_data_in_hex==1) || (	log_data_in_char ==1))
						printf("\nDestination Address: ");
					printf("%s\t", inet_ntoa(*destaddr) );
					if ((log_data_in_hex==1) || (	log_data_in_char ==1))
						printf("\nIP Packet Length: ");
					printf("%d\t",ntohs( ipHdr->ip_totallength));
					if ((log_data_in_hex==1) || (	log_data_in_char ==1))
						printf("\nIP Protocol: ");
					printf("%d\t",ipHdr->ip_protocol);
					if (got_time==1)
					{
						if ((log_data_in_hex==1) || (	log_data_in_char ==1))
							printf("\nTime: ");
						_time64(&thetime);
						printf("\t\t\t%s ", _ctime64(&thetime));
					}
					else
						printf("\n");
					numpackets++;
				}
		if (log_data_in_hex==1) 
		{
			printf("Packet Data:\n");
			for (loop=(sizeof(IP_HDR)); loop<(ntohs(ipHdr->ip_totallength)); loop++)
				printf("%02x ",(unsigned char)buffer[loop]);			
			printf("\n");		
		}
		if (log_data_in_char ==1) 
		{
			printf("Packet Data:\n");
			for (loop=(sizeof(IP_HDR)); loop<(ntohs(ipHdr->ip_totallength)); loop++)
				printf("%c",(unsigned char)buffer[loop]);			
			printf("\n");
		}
		ZeroMemory(buffer,MAXPACKETSIZE);
	}
	return 0;
}