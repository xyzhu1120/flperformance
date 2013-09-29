#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include "headers.h"
#include "packet.h"
#include "util.h"
#include "debug.h"
#include "crypto.h" /* crypto.h already include config.h */
#include <omp.h>

unsigned int SN = 0;
unsigned int send_counter;
unsigned int packetcnt;
unsigned int badpacketcnt;
//int randomfd = open("/dev/urandom", O_RDONLY);

const unsigned char seckey[24] = {
	0x2C , 0x9F , 0xDF , 0x20 , 0x6A , 0x87 , 0xC5 , 0x78 , 
	0x31 , 0x4A , 0x5E , 0xBE , 0x98 , 0xB2 , 0xB8 , 0x88 , 
	0x6B , 0x7A , 0xA6 , 0xFB , 0xE0 , 0xB8 , 0x22,  0xA9	};


/*********  Useful Functions  *********/

// Extract the upper byte (in big-endian format) of a short 
#define NET_UPPER_BYTE(x) ((unsigned char) (htons(x) & 0x00ff))

// Extract the lower byte (in big-endian format) of a short
#define NET_LOWER_BYTE(x) ((unsigned char) ((htons(x) >> 8) & 0x00ff))

// Extract the upper short (in little-endian format) of a network int
#define HOST_UPPER_SHORT(x) ((unsigned short) ((ntohl(x) >> 16) & 0x0000ffff))

// Extract the lower short (in little-endian format) of a network int
#define HOST_LOWER_SHORT(x) ((unsigned short) (ntohl(x) & 0x0000ffff))

// Convert two bytes into a network short
#define MAKE_NET_SHORT(h,l) ((unsigned short) (((unsigned short) l) << 8) | (unsigned short) h)

// Convert two bytes into a network short
#define MAKE_HOST_SHORT(h,l) ((unsigned short) (0xff00 & (((unsigned short) h) << 8)) | (unsigned short) l)

/*********  Lots of Functions ********/
void printPacket(struct ip *ipHead, int PacketLen)
{
	printf("print the content of the packet\n");
	int i = 0;
	if(PacketLen > 100)
		return;
	for( ;i < PacketLen / 4; ++i) {
		printf("%x ", *((unsigned int*)ipHead + i));
	}
	printf("\n");
}

/* 
 * Updates the IP/TCP/UDP checksum given the previous
 * header field value and the new header field value.
 * Expects all values to be in host-endian form 
 */
unsigned short updateChecksum(unsigned short oldChecksum, unsigned short oldVal, 
		unsigned short newVal) {
	unsigned short oldChecksumI = ~oldChecksum;
	unsigned short oldValI = ~oldVal;

	unsigned int tmp = (unsigned int) oldChecksumI + oldValI + newVal;
	unsigned short newChecksum = ~( (unsigned short) (tmp >> 16) + (tmp & 0xffff));

	return newChecksum;
}


/* 
 * Updates the IP/TCP/UDP checksum to include an array of new values
 * that were not previously present.
 * Expects all values to be in host-endian form 
 */
unsigned short updateChecksumArray(unsigned short oldChecksum, 
		unsigned short *newVals, int numVals) {
	unsigned short oldChecksumI = ~oldChecksum;
	unsigned short oldValI = ~0x0000;
	unsigned int newSum = 0;
	int i;

	for (i = 0; i < numVals; i++) {
		newSum += htons(newVals[i]);
	}

	unsigned int tmp = (unsigned int) oldChecksumI + (numVals * oldValI) + newSum;
	unsigned short newChecksum = ~( (unsigned short) (tmp >> 16) + (tmp & 0xffff));

	return newChecksum;
}

/*
 * Computes a fresh checksum as the 16-bit one's complement on the one's complement sum
 * of the bytes in packet
 * For TCP and UDP, chksum includes the pseudoheader
 * Accounts for odd lengths
 * protoclLen is the total length of the packet's protocol header and body in bytes
 */
unsigned short computeChecksum(int protocol, struct ip* ipHead, 
		unsigned char *packet, unsigned short protocolLen) {
	int i = 0;
	unsigned int chksum = 0;
	unsigned short chksum16 = 0; 
	unsigned short prot = 0;

	DEBUGMSG(2,"Calculating new checksum over %d bytes\n",protocolLen);

	if (protocol == TCP || protocol == UDP) { // Add the psedo header
		/* Start with the pseudo header */
		// Source and dst IP
		chksum += (unsigned int) HOST_LOWER_SHORT(ipHead->source);
		chksum += (unsigned int) HOST_UPPER_SHORT(ipHead->source);
		chksum += (unsigned int) HOST_LOWER_SHORT(ipHead->dest);
		chksum += (unsigned int) HOST_UPPER_SHORT(ipHead->dest);

		// Set the correct protocol number
		switch(protocol) {
			case TCP:
				prot = 0x06;  // In host order
				break;
			case UDP:
				prot = 0x11;  // In host order
				break;
			default:
				fprintf(stderr, "Invalid protocol for checksum computation\n");
				return 0;
		}

		chksum += (unsigned int) prot;
		chksum += (unsigned int) protocolLen;
	}

	if(protocolLen % 2 ==1)
		packet[protocolLen++]=0;
	/* Now compute over the actual packet */
	for (i = 0; i < protocolLen; i+=2) {
		// First byte is the high byte, second is the low byte
		chksum += (unsigned int) MAKE_HOST_SHORT(packet[i], packet[i+1]);
	}

	if (protocolLen % 2 == 1) { // Odd length, so pad with a pseudo byte
		DEBUGMSG(2,"Odd length packet!!!\n");
		//chksum += (unsigned int) MAKE_HOST_SHORT(0x00,packet[protocolLen - 1]);
		chksum += (unsigned int)(packet[protocolLen - 1]);
	}

	DEBUGMSG(2,"Intermediate checksum: %2x\n", chksum);

	// Fold the carry bits (the top half of chksum) into the main sum
	while (chksum >> 16) {
		chksum = (chksum & 0xffff) + (chksum >> 16);
	}

	// and invert to get the 1's complement version
	chksum16 = (unsigned short) (~chksum);

	return chksum16; 
}

/* 
 * Test function to analyze the various fields in a packet 
 */
void analyzePacket(unsigned char* buffer, int len) {
	struct ethernet* etherHead;
	struct ip* ipHead;
	//struct tcp* tcpHead;

	int sizeIPhead = 0;
	short IPtype = 0x0800;

	/* Align the headers */
	etherHead = (struct ethernet*) buffer;
	ipHead = (struct ip*) (buffer + sizeof(struct ethernet));

#ifdef DEBUG
	printf("Ether Src:\n");
	dumpBytes(etherHead->shost, ETHER_ADDR_LEN);
	printf("Ether Dest:\n");
	dumpBytes(etherHead->dhost, ETHER_ADDR_LEN);

	printf("Ether-header offset is %d\n", sizeof(struct ethernet));

	printf("### checking if it is an IP or TCP packet\n");
	printf("### Is IP? %d\n", isIP((unsigned char*)buffer));
	printf("### Is TCP? %d\n", isTCP((unsigned char*)buffer));
#endif

	if (ntohs(etherHead->type) == IPtype) {
		sizeIPhead = ipHead->hlength * 4;

#ifdef DEBUG
		printf("This is an IP packet\n");
		printf("IP version is %d\n", ipHead->version);
		printf("IP header length field is %d\n", ipHead->hlength);
		printf("IP header length is %d\n", sizeIPhead);
		printf("IP Total length (ntohs)= %d\n", ntohs(ipHead->total_length));

		if (sizeIPhead < 20) { 
			printf("Invalid IP header length: %u bytes\n\n", sizeIPhead);
			printf("Protocol = %d\n", ipHead->protocol);
		} else {
			printf("Protocol = %d\n", ipHead->protocol);
		}
#endif
	} else {

#ifdef DEBUG
		printf("Not an IP packet: %u!\n", ntohs(etherHead->type));
#endif
	}
}



/* Returns non-zero if packet is an IP packet, and 0 otherwise */
int isIP(unsigned char* buffer) {
	struct ethernet* etherHead;
	short IPtype = 0x0800;

	/* Align the header */ 
	etherHead = (struct ethernet*) buffer;

	return (ntohs(etherHead->type) == IPtype);
}

/* Returns non-zero if packet is a TCP packet (assumes the packet is IP), and 0 otherwise */
int isTCP(unsigned char* buffer) {
	struct ip* ipHead;
	unsigned char TCPtype = 0x06;

	/* Align the header */ 
	ipHead = (struct ip*) (buffer + sizeof(struct ethernet));

	return (ipHead->protocol == TCPtype);
}


int isSignal(unsigned char* buffer) {
	struct ip* ipHead;
	unsigned char TCPtype = 0x06;

	/* Align the header */ 
	ipHead = (struct ip*) (buffer + sizeof(struct ethernet));

	return (ipHead->protocol == 3);
}

int isEpochEnd(unsigned char* buffer) {


	struct ip* ipHead;
	unsigned char TCPtype = 0x06;

	/* Align the header */ 
	ipHead = (struct ip*) (buffer + sizeof(struct ethernet));
	return (ipHead->protocol == 4);
}
void ConstructSignal(unsigned char* buffer, struct host *n, struct host *localhost)
{
	struct ethernet *ether = (struct ethernet*)buffer;
	struct ip *ipHead = (struct ip*)(buffer + 14);
	 
	memcpy(ether->dhost,n->mac_addr,ETHER_ADDR_LEN);
	memcpy(ether->shost,localhost->mac_addr,ETHER_ADDR_LEN);
	ether->type = 0x0800;

	ipHead->hlength = 5;
	ipHead->version = 4;
	ipHead->total_length = sizeof(struct ip) + 4;
	ipHead->ttl = 200;
	ipHead->protocol = 3;
	//ipHead->checksum = computeChecksum(;
	ipHead->dest= n->ip_addr;
	ipHead->source= localhost->ip_addr;
	printPacket(buffer, 14 + sizeof(struct ip));
}


int ConstructEcho(unsigned char* buffer, unsigned char* incomeSig)
{
	struct ethernet *in_ether = (struct ethernet*)incomeSig;
	struct ethernet *ether = (struct ethernet*)buffer;
	struct ip *ipHead = (struct ip*)(buffer + 14);
	
	memcpy(ether->dhost,in_ether->shost,ETHER_ADDR_LEN);
	memcpy(ether->shost,in_ether->dhost,ETHER_ADDR_LEN);
	ether->type = in_ether->type;

	ipHead->hlength = 5;
	ipHead->version = 4;
	ipHead->total_length = sizeof(struct ip) + 4;
	ipHead->ttl = 200;
	ipHead->protocol = 3;
	//ipHead->checksum = computeChecksum(;
	//ipHead->dest= inet_aton("192.168.59.129");
	//ipHead->source= inet_aton("192.168.58.132");
	
	unsigned int * payload = (unsigned int *)(buffer + 14 + sizeof(struct ip));

	*payload = 100;
	return 1;
}
/* Returns non-zero if packet is a TCP or ICMP packet (assumes the packet is IP), 
 * and 0 otherwise */
int isTCPorICMP(unsigned char* buffer) {
	struct ip* ipHead;
	unsigned char TCPtype = 0x06;
	unsigned char ICMPtype = 0x01;

	/* Align the header */ 
	ipHead = (struct ip*) (buffer + sizeof(struct ethernet));

	return (ipHead->protocol == TCPtype || ipHead->protocol == ICMPtype);
}

/* Returns non-zero if packet is an ICMP echo request packet (assumes the packet is IP), 
 * and 0 otherwise */
int isEcho(unsigned char* buffer) {
	struct ip* ipHead;
	struct icmp* icmpHead;
	unsigned char ICMPtype = 0x01;
	unsigned char echoType = 0x08;

	/* Align the IP header */ 
	ipHead = (struct ip*) (buffer + sizeof(struct ethernet));
	int sizeIPhead = ipHead->hlength * 4;

	/* Align the ICMP header */
	icmpHead = (struct icmp*) (buffer + sizeof(struct ethernet) + sizeIPhead);

	return (ipHead->protocol == ICMPtype && icmpHead->type == echoType);
}


/* check packet hmac, return 0 on success */
/* XIN: return 1 on success? */

int verifyPacket(int protocol, unsigned char * packet, int * newLen)
{
	unsigned char hmac[HMAC_LEN];
	unsigned short oldPacketLen=0;
	unsigned short newPacketLen=0;
	unsigned char *packetHmac;
	int checksumOffset = 0;
	struct ip* ipHead;
	int sizeIPhead;
	struct in_addr addr;

	unsigned short oldIPChecksum, newIPChecksum;
	unsigned short newChecksum;


	/* Align the packet headers */
	ipHead = (struct ip*) (packet + ETHER_LEN);

	inet_aton("192.168.58.132",&addr);
	if(ipHead->source != addr.s_addr){
		return 1;
	}
	/* Calculate the new length of the IP packet (doesn't include Ethernet header) */
	oldPacketLen = ntohs(ipHead->total_length);
	oldIPChecksum = ntohs(ipHead->checksum);

#ifdef DEBUG > 3
	printf("#####Calculating the packet HMAC\n");
#endif
	/* Calculate packet HMAC */
	newPacketLen = oldPacketLen-EXT_LEN;

#ifndef FAKE
	ipHead->checksum = 0;
#endif
	switch (protocol) {
		case TCP:
			checksumOffset = 16; break;
		case UDP:
			checksumOffset = 6; break;
		case ICMP:
			checksumOffset = 2; break;
		default:
#ifdef DEBUG
			printf("Invalid protocol for packet extension\n");
#endif
			return 0;
	}
	sizeIPhead = ((ipHead->hlength) << 2) ;
#ifndef FAKE
	packet[ETHER_LEN+sizeIPhead+checksumOffset] = 0;
	packet[ETHER_LEN+sizeIPhead+checksumOffset+1] = 0;

	ipHead->total_length = htons(newPacketLen);
	ipHead->ttl = 0;
#endif

#if DEBUG >= 2
	printPacket(ipHead, newPacketLen);
#endif

	unsigned char testchar[22]={1};
	unsigned char testmac[24]={0};
	//MACwithKey((const unsigned char *)seckey, HMAC_KEY_LEN, testchar, 22, testmac);
	//printf("test mac is %x\n",*((unsigned short *)testmac));

	MACwithKey((const unsigned char *)seckey, HMAC_KEY_LEN, (const unsigned char *)ipHead, newPacketLen, (unsigned char *)hmac);


#ifndef FAKE
	/* Get HMAC value in the packet and verify */
	packetHmac = packet+ETHER_LEN+oldPacketLen-24+4;
	DEBUGMSG(2,"mac in packet is %x, calc is %x", *((unsigned short*)packetHmac), *((unsigned short*)hmac));
	if  (memcmp(packetHmac, hmac, 2)) {
		DEBUGMSG(2,"#### MACs is unequal\n");
	}
	/* Get rid of extension, and update packet length */
	*newLen = newPacketLen+ETHER_LEN;
#endif

	/* Update IP header checksum */
	newIPChecksum = updateChecksum(oldIPChecksum,oldPacketLen, newPacketLen);
	DEBUGMSG(2,"IP checksum old: %hu, new: %hu\n", oldIPChecksum, newIPChecksum);
#ifndef FAKE
	ipHead->checksum = htons(newIPChecksum);
#endif

	/* Update packet checksum */
	newChecksum = computeChecksum(protocol, ipHead, packet+ETHER_LEN+sizeIPhead, newPacketLen-sizeIPhead);



#ifndef FAKE
	DEBUGMSG(2,"TCP checksum old: %hu, new: %hu\n", oldIPChecksum, newIPChecksum);
	packet[ETHER_LEN + sizeIPhead + checksumOffset] = NET_UPPER_BYTE(newChecksum);
	packet[ETHER_LEN + sizeIPhead + checksumOffset + 1] = NET_LOWER_BYTE(newChecksum);
	ipHead->ttl = 63;
#ifdef DEBUG
	printf("#####will return 1\n");
#endif
	return 1;


#ifdef DEBUG
	printf("##### will return 0!");
#endif
	*newLen = oldPacketLen+ETHER_LEN;
	return 0;

#endif // ifndef FAKE
	*newLen = oldPacketLen+ETHER_LEN;

	return 1;
}

/* 
 * Adds MAC to the end of the IP body of packet
 * Returns length of entire new (Ethernet + IP + body + extension) packet
 * Returns 0 for error
 */


int extendPacket(int protocol, unsigned char* packet) 
{
	int i;
	unsigned short oldPacketLen = 0;
	unsigned short newPacketLen = 0;
	int payloadLen = 0;
	int checksumOffset = 0;
	unsigned char *payload;
	signed char *packetEnd;
	struct ip* ipHead;
	int sizeIPhead;
	int add_len;
	unsigned int tmp = 0;

	unsigned short oldIPChecksum, newIPChecksum;
	unsigned short oldChecksum = 0, newChecksum = 0;

	/* Align the packet headers */
	ipHead = (struct ip*) (packet + ETHER_LEN);
	
	/* Calculate the new length of the IP packet (doesn't include Ethernet header) */
	oldPacketLen = ntohs(ipHead->total_length);
	oldIPChecksum = ntohs(ipHead->checksum);

	DEBUGMSG(2,"extend the packet(len: %hu)!\n", oldPacketLen);

	/* Find packet end, then append HMACs and EXT_LEN */
	payload = findPacketPayload(protocol, packet, &payloadLen);
	packetEnd = payload + payloadLen;

	sizeIPhead = ((ipHead->hlength) << 2) ;
	
#ifndef FAKE
	//construct the Trailer
	*((unsigned int *)(packetEnd + SEC_TRAILER)) = ipHead->source;
	*((unsigned short*)(packetEnd + SEC_SNSELECT)) = (unsigned short)tmp;
	*((unsigned int*)(packetEnd + SEC_SN)) = SN++;
	//read(fd, &tmp, sizeof(tmp));
	ipHead->checksum = 0;
#endif
	
	switch (protocol) {
		case TCP:
			checksumOffset = 16; break;
		case UDP:
			checksumOffset = 6; break;
		case ICMP:
			checksumOffset = 2; break;
		default:
			DEBUGMSG(1,"Invalid protocol for packet extenon\n");
			return 0;
	}

#ifndef FAKE
	packet[ETHER_LEN+sizeIPhead+checksumOffset] = 0;
	packet[ETHER_LEN+sizeIPhead+checksumOffset+1] = 0;
#endif
	unsigned char mac[24]={0};
#ifndef FAKE
	ipHead->ttl = 0;
#endif
	MACwithKey((const unsigned char *)&seckey, HMAC_KEY_LEN, (const unsigned char *)ipHead, oldPacketLen, mac);
#ifndef FAKE
	ipHead->ttl = 64;
#endif
	DEBUGMSG(2,"the mac calced is %x", *((unsigned short*)(mac)));

#ifndef FAKE
	memcpy(packetEnd + SEC_MAC, mac, 2);
	memcpy(packetEnd, packetEnd + SEC_TRAILER, 12);
#endif

	newPacketLen = oldPacketLen + EXT_LEN;
	DEBUGMSG(2,"newPacket Length is %hi\n", newPacketLen);

#ifndef FAKE
	/* Update packet length */
	ipHead->total_length = htons(newPacketLen);
#endif

	/* Update IP header checksum */
	newIPChecksum = updateChecksum(oldIPChecksum,oldPacketLen, newPacketLen);
	DEBUGMSG(2,"IP checksum old: %x, new: %x\n", oldIPChecksum, newIPChecksum);

#ifndef FAKE
	ipHead->checksum = htons(newIPChecksum);
#endif
	/* Update packet checksum */


	newChecksum = computeChecksum(protocol, ipHead, packet+ETHER_LEN+sizeIPhead, newPacketLen-sizeIPhead);
#ifndef FAKE
	packet[ETHER_LEN + sizeIPhead + checksumOffset] = NET_UPPER_BYTE(newChecksum);
	packet[ETHER_LEN + sizeIPhead + checksumOffset + 1] = NET_LOWER_BYTE(newChecksum);
	DEBUGMSG(2,"TCP checksum old: %x, new: %x\n", oldChecksum, newChecksum);
#if DEBUG >= 1
	printPacket(ipHead, oldPacketLen);
#endif
	++send_counter;
	return ETHER_LEN + newPacketLen;

#endif // ifndef FAKE
	return ETHER_LEN + oldPacketLen;
	return 1;
}

/* 
 * Returns a pointer to the protocol's (e.g., TCP/UDP/ICMP) payload
 * Sets payloadLen equal to the length of the protocol's payload
 */
unsigned char* findPacketPayload(int protocol, unsigned char* packet,
		int *payloadLen) {
	struct ip* ipHead;
	struct tcp* tcpHead = NULL;

	// Align the packet header
	ipHead = (struct ip*) (packet + ETHER_LEN);

	/* Header length field specifies number of 32-bit fields, so mult by 4 to get # of bytes */
	int sizeIPhead = ipHead->hlength * 4;

	// Calculate the size (in bytes) of the protocol (TCP/UDP/ICMP) header
	int protHeaderSize = 0;
	switch (protocol) {
		case TCP:
			tcpHead = (struct tcp*) (packet + ETHER_LEN + sizeIPhead);
			protHeaderSize = tcpHead->hlength * 4;  // Header length in # of 32-bit fields, so mult by 4
			break;
		case UDP:
			protHeaderSize = 8; break;
		case ICMP:
			protHeaderSize = 4; break;
		default:
			fprintf(stderr, "Invalid protocol for packet authorization\n");
			return NULL;
	}

	// Find the protocol's payload 
	unsigned char* payload = packet + ETHER_LEN + sizeIPhead + protHeaderSize;

	// Find the size of the payload 
	unsigned short IPpacketLen = ntohs(ipHead->total_length);
	*payloadLen = IPpacketLen - sizeIPhead - protHeaderSize;

	return payload;
}
