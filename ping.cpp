#define _WINSOCK_DEPRECATED_NO_WARNINGS
#pragma comment(lib, "ws2_32.lib")
#include   "winsock2.h"
#include   "stdlib.h"
#include   "stdio.h"
#define ICMP_ECHO 8 
#define ICMP_ECHOREPLY 0 
#define ICMP_MIN 8 // minimum 8 byte icmp packet (just header) 
/* The IP header */
typedef struct iphdr
{
	unsigned int h_len : 4; // length of the header 
	unsigned int version : 4; // Version of IP 
	unsigned char tos; // Type of service 
	unsigned short total_len; // total length of the packet 
	unsigned short ident; // unique identifier 
	unsigned short frag_and_flags; // flags 
	unsigned char ttl;
	unsigned char proto; // protocol (TCP, UDP etc) 
	unsigned short checksum; // IP checksum 
	unsigned int sourceIP;
	unsigned int destIP;
}IpHeader;
// 
// ICMP header 
// 
typedef struct icmphdr
{
	BYTE i_type;
	BYTE i_code; /* type sub code */
	USHORT i_cksum;
	USHORT i_id;
	USHORT i_seq;
	/* This is not the std header, but we reserve space for time */
	ULONG timestamp;
}IcmpHeader;
#define STATUS_FAILED 0xFFFF 
#define DEF_PACKET_SIZE    32
#define DEF_PACKET_NUMBER  4    /* count of packet to send */
#define MAX_PACKET 1024 
#define xmalloc(s) HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,(s)) 
#define xfree(p) HeapFree (GetProcessHeap(),0,(p)) 
void fill_icmp_data(char *, int);
USHORT checksum(USHORT *, int);
int decode_resp(char *, int, struct sockaddr_in *);
void Usage(char *progname) {
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "%s [number of packets] [data_size]\n", progname);
	fprintf(stderr, "datasize can be up to 1Kb\n");
	ExitProcess(STATUS_FAILED);
}
int main(int argc, char **argv) {
	WSADATA wsaData;
	SOCKET sockRaw;
	struct sockaddr_in dest, from;
	struct hostent * hp;
	int bread, datasize, times;
	int fromlen = sizeof(from);
	int timeout = 1000;
	int statistic = 0;  /* for statistic */
	char *dest_ip;
	char *icmp_data;
	char *recvbuf;
	unsigned int addr = 0;
	USHORT seq_no = 0;
	if (WSAStartup(MAKEWORD(2, 1), &wsaData) != 0) {
		fprintf(stderr, "WSAStartup failed: %d\n", GetLastError());
		ExitProcess(STATUS_FAILED);
	}
	if (argc <2) {
		Usage(argv[0]);
	}
	sockRaw = WSASocket(AF_INET, SOCK_RAW, IPPROTO_ICMP, NULL, 0, WSA_FLAG_OVERLAPPED);
	//
	//×¢£ºWSA_FLAG_OVERLAPPED ! important
	// 
	if (sockRaw == INVALID_SOCKET) {
		fprintf(stderr, "WSASocket() failed: %d\n", WSAGetLastError());
		ExitProcess(STATUS_FAILED);
	}
	bread = setsockopt(sockRaw, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout,
		sizeof(timeout));
	if (bread == SOCKET_ERROR) {
		fprintf(stderr, "failed to set recv timeout: %d\n", WSAGetLastError());
		ExitProcess(STATUS_FAILED);
	}
	timeout = 1000;
	bread = setsockopt(sockRaw, SOL_SOCKET, SO_SNDTIMEO, (char*)&timeout,
		sizeof(timeout));
	if (bread == SOCKET_ERROR) {
		fprintf(stderr, "failed to set send timeout: %d\n", WSAGetLastError());
		ExitProcess(STATUS_FAILED);
	}
	memset(&dest, 0, sizeof(dest));
	hp = gethostbyname(argv[1]);
	if (!hp) {
		addr = inet_addr(argv[1]);
	}
	if ((!hp) && (addr == INADDR_NONE)) {
		fprintf(stderr, "Unable to resolve %s\n", argv[1]);
		ExitProcess(STATUS_FAILED);
	}
	if (hp != NULL)
		memcpy(&(dest.sin_addr), hp->h_addr, hp->h_length);
	else
		dest.sin_addr.s_addr = addr;
	if (hp)
		dest.sin_family = hp->h_addrtype;
	else
		dest.sin_family = AF_INET;
	dest_ip = inet_ntoa(dest.sin_addr);
	// 
	//  int atoi( const char *string );
	//  The return value is 0 if the input cannot be converted to an integer !
	//
	if (argc>2) {
		times = atoi(argv[2]);
		if (times == 0)
			times = DEF_PACKET_NUMBER;
	}
	else
		times = DEF_PACKET_NUMBER;
	if (argc >3) {
		datasize = atoi(argv[3]);
		if (datasize == 0)
			datasize = DEF_PACKET_SIZE;
		if (datasize >1024)   /* the giving packet size is too big */
		{
			fprintf(stderr, "WARNING : data_size is too large !\n");
			datasize = DEF_PACKET_SIZE;
		}
	}
	else
		datasize = DEF_PACKET_SIZE;
	datasize += sizeof(IcmpHeader);
	icmp_data = (char*)xmalloc(MAX_PACKET);
	recvbuf = (char*)xmalloc(MAX_PACKET);
	if (!icmp_data) {
		fprintf(stderr, "HeapAlloc failed %d\n", GetLastError());
		ExitProcess(STATUS_FAILED);
	}
	memset(icmp_data, 0, MAX_PACKET);
	fill_icmp_data(icmp_data, datasize);
	//
	// print information
	//
	fprintf(stdout, "\nPinging %s ....\n\n", dest_ip);
	for (int i = 0; i<DEF_PACKET_NUMBER; i++) {
		int bwrote;
		((IcmpHeader*)icmp_data)->i_cksum = 0;
		((IcmpHeader*)icmp_data)->timestamp = GetTickCount();
		((IcmpHeader*)icmp_data)->i_seq = seq_no++;
		((IcmpHeader*)icmp_data)->i_cksum = checksum((USHORT*)icmp_data, datasize);
		bwrote = sendto(sockRaw, icmp_data, datasize, 0, (struct sockaddr*)&dest, sizeof(dest));
		if (bwrote == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAETIMEDOUT) {
				printf("Request timed out.\n");
				continue;
			}
			fprintf(stderr, "sendto failed: %d\n", WSAGetLastError());
			ExitProcess(STATUS_FAILED);
		}
		if (bwrote < datasize) {
			fprintf(stdout, "Wrote %d bytes\n", bwrote);
		}
		bread = recvfrom(sockRaw, recvbuf, MAX_PACKET, 0, (struct sockaddr*)&from, &fromlen);
		if (bread == SOCKET_ERROR) {
			if (WSAGetLastError() == WSAETIMEDOUT) {
				printf("Request timed out.\n");
				continue;
			}
			fprintf(stderr, "recvfrom failed: %d\n", WSAGetLastError());
			ExitProcess(STATUS_FAILED);
		}
		if (!decode_resp(recvbuf, bread, &from))
			statistic++;
		Sleep(1000);
	}
	/*
	Display the statistic result
	*/
	fprintf(stdout, "\nPing statistics for %s \n", dest_ip);
	fprintf(stdout, "    Packets: Sent = %d,Received = %d, Lost = %d (%2.0f%% loss)\n", times,
		statistic, (times - statistic), (float)(times - statistic) / times * 100);
	WSACleanup();
	return 0;
}
/*
The response is an IP packet. We must decode the IP header to locate
the ICMP data
*/
int decode_resp(char *buf, int bytes, struct sockaddr_in *from) {
	IpHeader *iphdr;
	IcmpHeader *icmphdr;
	unsigned short iphdrlen;
	iphdr = (IpHeader *)buf;
	iphdrlen = (iphdr->h_len) * 4; // number of 32-bit words *4 = bytes 
	if (bytes < iphdrlen + ICMP_MIN) {
		printf("Too few bytes from %s\n", inet_ntoa(from->sin_addr));
	}
	icmphdr = (IcmpHeader*)(buf + iphdrlen);
	if (icmphdr->i_type != ICMP_ECHOREPLY) {
		fprintf(stderr, "non-echo type %d recvd\n", icmphdr->i_type);
		return 1;
	}
	if (icmphdr->i_id != (USHORT)GetCurrentProcessId()) {
		fprintf(stderr, "someone else''s packet!\n");
		return 1;
	}
	printf("%d bytes from %s:", bytes, inet_ntoa(from->sin_addr));
	printf(" icmp_seq = %d. ", icmphdr->i_seq);
	printf(" time: %d ms ", GetTickCount() - icmphdr->timestamp);
	printf("\n");
	return 0;
}
USHORT checksum(USHORT *buffer, int size) {
	unsigned long cksum = 0;
	while (size >1) {
		cksum += *buffer++;
		size -= sizeof(USHORT);
	}
	if (size) {
		cksum += *(UCHAR*)buffer;
	}
	cksum = (cksum >> 16) + (cksum & 0xffff);
	cksum += (cksum >> 16);
	return (USHORT)(~cksum);
}
/*
Helper function to fill in various stuff in our ICMP request.
*/
void fill_icmp_data(char * icmp_data, int datasize) {
	IcmpHeader *icmp_hdr;
	char *datapart;
	icmp_hdr = (IcmpHeader*)icmp_data;
	icmp_hdr->i_type = ICMP_ECHO;
	icmp_hdr->i_code = 0;
	icmp_hdr->i_id = (USHORT)GetCurrentProcessId();
	icmp_hdr->i_cksum = 0;
	icmp_hdr->i_seq = 0;
	datapart = icmp_data + sizeof(IcmpHeader);
	// 
	// Place some junk in the buffer. 
	// 
	memset(datapart, 22, datasize - sizeof(IcmpHeader));
}
