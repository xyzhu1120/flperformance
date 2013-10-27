#include  "config.h"

/********* Packet extension related definition */
/* Length of HMAC output (we use SHA1-HMAC) */
#define  HMAC_LEN 20 
/* Length of HMAC key */
#define  HMAC_KEY_LEN 24
/* NUM of HMAC that will be pended to the packet */ 
#ifndef WE_ARE_DST
#define  HMAC_NUM PATH_LEN
#else
#define  HMAC_NUM 1
#endif
/* Length of packet extension */
//#define  EXT_LEN (2+HMAC_NUM*HMAC_LEN)
//#define  EXT_LEN HMAC_NUM
#define  EXT_LEN 24

/* Size of the packet buffer */
#define  BUFF_SIZE (1500+EXT_LEN)

/* src machine must negociate HMAC keys with all the on-path router
 * and also traffic receiver
 * 
 * dst machine only have one HMAC key
 * */
unsigned char keyPool[300];

/* Returns a MAC (currently HMAC with SHA-1) of the provided plaintext 
 * Updates hmacLen with the length of the MAC
 * NO NEED to preallocate memory for the return pointer */
void MACwithKey(const unsigned char* secKey, int secKeyLen, const unsigned char* plaintext, int plainLen, unsigned char * hmac);

/* Negociate HMAC key with on-path machines
 * FIXME: just a simulation now */
void initKeyPool();

