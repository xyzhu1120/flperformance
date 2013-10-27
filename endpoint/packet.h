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

/*********  Globals ********/

#define UDP 0
#define TCP 1
#define ICMP 2 

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

/* 
 * Updates the IP/TCP/UDP checksum given the previous
 * header field value and the new header field value.
 * Expects all values to be in host-endian form 
 */
unsigned short updateChecksum(unsigned short oldChecksum, unsigned short oldVal, 
                              unsigned short newVal);

/* 
 * Updates the IP/TCP/UDP checksum to include an array of new values
 * that were not previously present.
 * Expects all values to be in host-endian form 
 */
unsigned short updateChecksumArray(unsigned short oldChecksum, 
                                   unsigned short *newVals, int numVals);

/*
 * Computes a fresh checksum as the 16-bit one's complement on the one's complement sum
 * of the bytes in packet
 * For TCP and UDP, chksum includes the pseudoheader
 * Accounts for odd lengths
 * protoclLen is the total length of the packet's protocol header and body in bytes
 */
unsigned short computeChecksum(int protocol, struct ip* ipHead, 
                               unsigned char *packet, unsigned short protocolLen); 

/* 
 * Test function to analyze the various fields in a packet 
 */
void analyzePacket(unsigned char* buffer, int len); 


/* Returns non-zero if packet is an IP packet, and 0 otherwise */
int isIP(unsigned char* buffer); 

/* Returns non-zero if packet is a TCP packet (assumes the packet is IP), and 0 otherwise */
int isTCP(unsigned char* buffer); 

/* Returns non-zero if packet is a TCP or ICMP packet (assumes the packet is IP), 
 * and 0 otherwise */
int isTCPorICMP(unsigned char* buffer);  

/* Returns non-zero if packet is an ICMP echo request packet (assumes the packet is IP), 
 * and 0 otherwise */
int isEcho(unsigned char* buffer);

/* check packet hmac, return 0 on success */
int verifyPacket(int protocol, unsigned char * packet, int * newLen);

/* 
 * Adds MAC to the end of the IP body of packet
 * Returns length of entire new (Ethernet + IP + body + extension) packet
 *
 * NOTE: packet buffer should be large enough
 */
int extendPacket(int protocol, unsigned char* packet);


/* 
 * Returns a pointer to the protocol's (e.g., TCP/UDP/ICMP) payload
 * Sets payloadLen equal to the length of the protocol's payload
 */
unsigned char* findPacketPayload(int protocol, unsigned char* packet,
                                 int *payloadLen); 
