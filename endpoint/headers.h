#ifndef _HEADERS_H
#define _HEADERS_H

/*structure of an ethernet header */

/* Ethernet header is 14 bytes (2xADDR_LEN, plus 2 byte type) */
#define ETHER_LEN 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

#define SEC_TRAILER 12
#define SEC_MAC SEC_TRAILER + 4
#define SEC_SNSELECT SEC_TRAILER + 6
#define SEC_SN SEC_TRAILER + 8

/* Ethernet header */
struct ethernet {
	unsigned char  dhost[ETHER_ADDR_LEN]; /* Destination host address */
	unsigned char  shost[ETHER_ADDR_LEN]; /* Source host address */
	unsigned short type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct ip {
	unsigned            hlength:4;    /*little-endian*/
	unsigned            version:4;
	unsigned char       tos;
	unsigned short      total_length;
	unsigned short      id;
	unsigned short      flags;  /* 3-bit flags + 13-bit frag offset */
	unsigned char       ttl;
	unsigned char       protocol;
	unsigned short      checksum;
	unsigned int        source;
	unsigned int        dest;
};

/* ICMP header */
struct icmp {
	unsigned char       type;
	unsigned char       code;
	unsigned short      checksum;
};

/* UDP header */
struct udp {
	unsigned short		source_port;
	unsigned short		dest_port;
	unsigned short		length;
	unsigned short		checksum;
};

/* TCP header */
struct tcp {
	unsigned short      source_port;
	unsigned short      dest_port;
	unsigned int        seqno;
	unsigned int        ackno;
	//unsigned short      flags;
	unsigned short      res1:4,     /*little-endian*/
						hlength:4,
						fin:1,
						syn:1,
						rst:1,
						psh:1,
						ack:1,
						urg:1,
						res2:2;
	unsigned short      winsize;
	unsigned short      checksum;
	unsigned short      urgent;
};

struct hostinfo{
	unsigned int goodpackets;
	unsigned int totalpackets;
	unsigned int SN[100];
	unsigned int SNcnt;
};

struct host{
	unsigned int ip_addr;
	unsigned char mac_addr[ETHER_ADDR_LEN];
	struct hostinfo * info;
};
/*********************EOF***********************************/
#endif
