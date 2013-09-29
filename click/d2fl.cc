#include <click/config.h>
#include "d2fl.hh"
#include <clicknet/ip.h>
#include <click/ipaddress.hh>
#include <clicknet/tcp.h>
#include <click/confparse.hh>
#include <click/glue.hh>
#include <click/straccum.hh>
#include <click/error.hh>
#include <click/standard/alignmentinfo.hh>
#include <click/timestamp.hh>

#ifdef USE_UMAC
CLICK_CXX_PROTECT
#include <string.h>
#include <stdlib.h>
CLICK_CXX_UNPROTECT
#endif

#ifdef KERNEL_HMAC
extern "C" {
#include <net/checksum.h>
#include <linux/slab.h>
#include <linux/err.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/mm.h>
#include <linux/scatterlist.h>
#include <linux/string.h>
#include <linux/crypto.h>
#include <linux/highmem.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <asm/div64.h>
}
#endif


CLICK_DECLS

const unsigned char D2FL::seckey[24] = {
	0x2C , 0x9F , 0xDF , 0x20 , 0x6A , 0x87 , 0xC5 , 0x78 , 
	0x31 , 0x4A , 0x5E , 0xBE , 0x98 , 0xB2 , 0xB8 , 0x88 , 
	0x6B , 0x7A , 0xA6 , 0xFB , 0xE0 , 0xB8 , 0x22,  0xA9	};

#ifdef USE_HMAC
/**************************  HMAC Code *************************/
/*
   static void dumpBytes3(char *tag, unsigned char *data, int len) {
   int i;
   if(!tag) return;
   printf("%s\n", tag);

   if(!data || len < 0) return;
   for(i=0; i<len; i++) {
   printf("%02x ", data[i]);
   if(i>1 && !(i%16)) printf("\n");
   }
   }
   */
/*
 * SHA1 hash algorithm. Used in SSH-2 as a MAC, and the transform is
 * also used as a `stirring' function for the PuTTY random number
 * pool. Implemented directly from the specification by Simon
 * Tatham.
 */
typedef unsigned int word32;
typedef unsigned int uint32;
typedef struct {
	uint32 h[5];
	unsigned char block[64];
	int blkused;
	uint32 lenhi, lenlo;
} SHA_State;

static void SHA_Init(SHA_State * s);
static void SHA_Bytes(SHA_State * s, void *p, int len);
static void SHA_Final(SHA_State * s, unsigned char *output);
static void SHA_Simple(void *p, int len, unsigned char *output);

static void SHATransform(word32 * digest, word32 * data);

static void hmac_sha1_simple(void *key, int keylen, void *data, int datalen, unsigned char *output);


typedef struct {
	unsigned long hi, lo;
} uint64, int64;

typedef struct {
	uint64 h[8];
	unsigned char block[128];
	int blkused;
	uint32 len[4];
} SHA512_State;

void SHA512_Init(SHA512_State * s);
void SHA512_Bytes(SHA512_State * s, const void *p, int len);
void SHA512_Final(SHA512_State * s, unsigned char *output);
void SHA512_Simple(const void *p, int len, unsigned char *output);


/* ----------------------------------------------------------------------
 * Core SHA algorithm: processes 16-word blocks into a message digest.
 */

#define rol(x,y) ( ((x) << (y)) | (((uint32)x) >> (32-y)) )

static void SHA_Core_Init(uint32 h[5])
{
	h[0] = 0x67452301;
	h[1] = 0xefcdab89;
	h[2] = 0x98badcfe;
	h[3] = 0x10325476;
	h[4] = 0xc3d2e1f0;
}

static void SHATransform(word32 * digest, word32 * block)
{
	word32 w[80];
	word32 a, b, c, d, e;
	int t;

	for (t = 0; t < 16; t++)
		w[t] = block[t];

	for (t = 16; t < 80; t++) {
		word32 tmp = w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16];
		w[t] = rol(tmp, 1);
	}

	a = digest[0];
	b = digest[1];
	c = digest[2];
	d = digest[3];
	e = digest[4];

	for (t = 0; t < 20; t++) {
		word32 tmp =
			rol(a, 5) + ((b & c) | (d & ~b)) + e + w[t] + 0x5a827999;
		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 20; t < 40; t++) {
		word32 tmp = rol(a, 5) + (b ^ c ^ d) + e + w[t] + 0x6ed9eba1;
		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 40; t < 60; t++) {
		word32 tmp = rol(a,
				5) + ((b & c) | (b & d) | (c & d)) + e + w[t] +
			0x8f1bbcdc;
		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 60; t < 80; t++) {
		word32 tmp = rol(a, 5) + (b ^ c ^ d) + e + w[t] + 0xca62c1d6;
		e = d;
		d = c;
		c = rol(b, 30);
		b = a;
		a = tmp;
	}

	digest[0] += a;
	digest[1] += b;
	digest[2] += c;
	digest[3] += d;
	digest[4] += e;
}

/* ----------------------------------------------------------------------
 * Outer SHA algorithm: take an arbitrary length byte string,
 * convert it into 16-word blocks with the prescribed padding at
 * the end, and pass those blocks to the core SHA algorithm.
 */

static void SHA_Init(SHA_State * s)
{
	SHA_Core_Init(s->h);
	s->blkused = 0;
	s->lenhi = s->lenlo = 0;
}

static void SHA_Bytes(SHA_State * s, void *p, int len)
{
	unsigned char *q = (unsigned char *) p;
	uint32 wordblock[16];
	uint32 lenw = len;
	int i;

	/*
	 * Update the length field.
	 */
	s->lenlo += lenw;
	s->lenhi += (s->lenlo < lenw);

	if (s->blkused && s->blkused + len < 64) {
		/*
		 * Trivial case: just add to the block.
		 */
		memcpy(s->block + s->blkused, q, (unsigned) len);
		s->blkused += len;
	} else {
		/*
		 * We must complete and process at least one block.
		 */
		while (s->blkused + len >= 64) {
			memcpy(s->block + s->blkused, q, (unsigned) (64 - s->blkused));
			q += 64 - s->blkused;
			len -= 64 - s->blkused;
			/* Now process the block. Gather bytes big-endian into words */
			for (i = 0; i < 16; i++) {
				wordblock[i] =
					(((uint32) s->block[i * 4 + 0]) << 24) |
					(((uint32) s->block[i * 4 + 1]) << 16) |
					(((uint32) s->block[i * 4 + 2]) << 8) |
					(((uint32) s->block[i * 4 + 3]) << 0);
			}
			SHATransform(s->h, wordblock);
			s->blkused = 0;
		}
		memcpy(s->block, q, (unsigned) len);
		s->blkused = len;
	}
}

static void SHA_Final(SHA_State * s, unsigned char *output)
{
	int i;
	int pad;
	unsigned char c[64];
	uint32 lenhi, lenlo;

	if (s->blkused >= 56)
		pad = 56 + 64 - s->blkused;
	else
		pad = 56 - s->blkused;

	lenhi = (s->lenhi << 3) | (s->lenlo >> (32 - 3));
	lenlo = (s->lenlo << 3);

	memset(c, 0, (unsigned) pad);
	c[0] = 0x80;
	SHA_Bytes(s, &c, pad);

	c[0] = (lenhi >> 24) & 0xFF;
	c[1] = (lenhi >> 16) & 0xFF;
	c[2] = (lenhi >> 8) & 0xFF;
	c[3] = (lenhi >> 0) & 0xFF;
	c[4] = (lenlo >> 24) & 0xFF;
	c[5] = (lenlo >> 16) & 0xFF;
	c[6] = (lenlo >> 8) & 0xFF;
	c[7] = (lenlo >> 0) & 0xFF;

	SHA_Bytes(s, &c, 8);

	for (i = 0; i < 5; i++) {
		output[i * 4] = (s->h[i] >> 24) & 0xFF;
		output[i * 4 + 1] = (s->h[i] >> 16) & 0xFF;
		output[i * 4 + 2] = (s->h[i] >> 8) & 0xFF;
		output[i * 4 + 3] = (s->h[i]) & 0xFF;
	}
}

static void SHA_Simple(void *p, int len, unsigned char *output)
{
	SHA_State s;

	SHA_Init(&s);
	SHA_Bytes(&s, p, len);
	SHA_Final(&s, output);
}

/* ----------------------------------------------------------------------
 * The above is the SHA-1 algorithm itself. Now we implement the
 * HMAC wrapper on it.
 */

static void sha1_key_internal(void *handle, unsigned char *key, int len)
{
	SHA_State *keys = (SHA_State *)handle;
	unsigned char foo[64];
	int i;

	memset(foo, 0x36, 64);
	for (i = 0; i < len && i < 64; i++)
		foo[i] ^= key[i];
	SHA_Init(&keys[0]);
	SHA_Bytes(&keys[0], foo, 64);

	memset(foo, 0x5C, 64);
	for (i = 0; i < len && i < 64; i++)
		foo[i] ^= key[i];
	SHA_Init(&keys[1]);
	SHA_Bytes(&keys[1], foo, 64);

	memset(foo, 0, 64);		       /* burn the evidence */
}

static void hmac_sha1_simple(void *key, int keylen, void *data, int datalen,
		unsigned char *output) {
	SHA_State states[2];
	unsigned char intermediate[20];

	sha1_key_internal(states, (unsigned char *)key, keylen);
	//dumpBytes3("states", (unsigned char *)&states, 2*sizeof(SHA_State));
	SHA_Bytes(&states[0], data, datalen);
	SHA_Final(&states[0], intermediate);
	//dumpBytes3("\nintermediate", intermediate, 20);

	SHA_Bytes(&states[1], intermediate, 20);
	SHA_Final(&states[1], output);
}
#endif
#ifdef USE_UMAC 
/* ----------------------UMAC------------------------------------------- */
/* --- User Switches ---------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#define UMAC_STD_30       0  /* Choose one of the four */
#define UMAC_STD_60       0  /* defined UMAC options.  */
#define UMAC_MMX_15       1
#define UMAC_MMX_30       0
#define UMAC_MMX_60       0

#define ANSI_C_ONLY       1  /* If 0 then only ANSI C is used  */
                             /* If 1 then X86/MMX asm is used  */

#define RUN_TESTS         0  /* Run against known test vectors */

#if ((UMAC_STD_30 + UMAC_STD_60 + UMAC_MMX_15 + UMAC_MMX_30 + UMAC_MMX_60) != 1)
#error -- Only one UMAC option allowed
#endif

/* ---------------------------------------------------------------------- */
/* -- Global Includes --------------------------------------------------- */
/* ---------------------------------------------------------------------- */


/* ---------------------------------------------------------------------- */
/* --- Primitive Data Types ---                                           */
/* ---------------------------------------------------------------------- */

typedef char               INT8;   /* 1 byte   */
typedef unsigned char      UINT8;  /* 1 byte   */
typedef short              INT16;  /* 2 byte   */
typedef unsigned short     UINT16; /* 2 byte   */
typedef int                INT32;  /* 4 byte   */
typedef unsigned int       UINT32; /* 4 byte   */
#if _MSC_VER
typedef __int64            INT64;  /* 8 bytes  */
#else
typedef long long          INT64;  /* 8 bytes  */
#endif
typedef long               WORD;   /* Register */

/* ---------------------------------------------------------------------- */
/* --- Endian Definition ---                                              */
/* ---------------------------------------------------------------------- */

/* Message "words" are read from memory in an endian-specific manner.     */
/* For this implementation to behave correctly, __LITTLE_ENDIAN__ must    */
/* be set true if the host computer is little-endian.                     */

#if __i386__ || __INTEL__ || __alpha__ || _M_IX86
#define __LITTLE_ENDIAN__ 1
#else
#define __LITTLE_ENDIAN__ 0
#endif

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Rotation and Endian Conversion Routines ------------------------ */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* --- 32-Bit Rotation operators --- Forcing assembly on some platforms   */
/* ---------------------------------------------------------------------- */

/* Word rotation is often supported by a CPU's architecture, but there is */
/* no C operand to rotate data. Good compilers can detect when a rotate   */
/* is being constructed from bitshifting and bitwise OR and output the    */
/* assembly rotates. Other compilers require assembly or C intrinsics.    */

/* ---------------------------------------------------------------------- */
#if (( ! ANSI_C_ONLY) && __MWERKS__ && __POWERPC__)
/* ---------------------------------------------------------------------- */

#define ROTL_VAR(r,n)   __rlwnm((r), (n), 0, 31)
#define ROTL_CONST(r,n) __rlwinm((r), (n), 0, 31)

/* ---------------------------------------------------------------------- */
#elif (( ! ANSI_C_ONLY) && _MSC_VER && _M_IX86 && ! __MWERKS__)
/* ---------------------------------------------------------------------- */

static INT32 ROTL_VAR(INT32 r, const INT32 n)
{
    __asm {
        mov ecx,n
        mov eax,r
        rol eax, cl
    }
}

#define ROTL_CONST(r,n) ROTL_VAR(r,n)

/* ---------------------------------------------------------------------- */
#else /* ANSI_C_ONLY or non-specialized architecture */
/* ---------------------------------------------------------------------- */

#define ROTL_VAR(r,n)   (((r) << ((n) & 31)) | \
                         ((UINT32)(r) >> (32 - ((n) & 31))))
#define ROTL_CONST(r,n) (((r) <<  (n))       | \
                         ((UINT32)(r) >> (32 -  (n))))
               
/* ---------------------------------------------------------------------- */
#endif
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* --- Endian Conversion --- Forcing assembly on some platforms           */
/* ---------------------------------------------------------------------- */

/* PowerPC and Intel Architechture both support efficient endian          */
/* conversion, but compilers seem unable to automatically utilize the     */
/* efficient assembly opcodes. The following routines force their use.    */

/* ---------------------------------------------------------------------- */
#if (( ! ANSI_C_ONLY) && (__MRC__ || (__MWERKS__ && __POWERPC__)))
/* ---------------------------------------------------------------------- */

static INT32 LOAD_INT32_REVERSED(void *ptr)
{
    return __lwbrx(ptr, 0);
}

static void STORE_INT32_REVERSED(void *ptr, INT32 x)
{
    __stwbrx(x, ptr, 0);
}

static INT16 LOAD_INT16_REVERSED(void *ptr)
{
    return __lhbrx(ptr, 0);
}

/* ---------------------------------------------------------------------- */
#elif (( ! ANSI_C_ONLY) && __GNUC__ && __ppc__)
/* ---------------------------------------------------------------------- */

static INT32 LOAD_INT32_REVERSED(void *ptr)
{
    INT32 temp;
    asm("lwbrx %0,0,%1" : "=r" (temp) : "r" (ptr)); 
    return temp;
}

static void STORE_INT32_REVERSED(void *ptr, INT32 x)
{
    asm ("stwbrx %1,0,%0" : : "r" (ptr), "r" (x)); 
}

static INT16 LOAD_INT16_REVERSED(void *ptr)
{
    INT16 temp;
    asm("lhbrx %0,0,%1" : "=r" (temp) : "r" (ptr)); 
    return temp;
}

/* ---------------------------------------------------------------------- */
#elif (( ! ANSI_C_ONLY) && __GNUC__ && __i386__)
/* ---------------------------------------------------------------------- */

static INT32 LOAD_INT32_REVERSED(void *ptr)
{
    INT32 temp;
    asm("bswap %0" : "=r" (temp) : "0" (*(INT32 *)ptr)); 
    return temp;
}

static void STORE_INT32_REVERSED(void *ptr, INT32 x)
{
    asm("bswap %0" : "=r" (*(INT32 *)ptr) : "0" (x)); 
}

static INT16 LOAD_INT16_REVERSED(void *ptr)
{
    INT32 temp;
    asm("xchg %%bh,%%bl" : "=b" (temp) : "0" (*(INT16 *)ptr) : "ebx" ); 
    return temp;
}

/* ---------------------------------------------------------------------- */
#elif (( ! ANSI_C_ONLY) && _MSC_VER && _M_IX86 && ! __MWERKS__)
/* ---------------------------------------------------------------------- */

static INT32 LOAD_INT32_REVERSED(void *p)
{
    __asm {
        mov eax, p
        mov eax, [eax]
        bswap eax
    }
}

static void STORE_INT32_REVERSED(void *p, INT32 x)
{
    __asm {
        mov eax,x
        bswap eax
        mov ecx, p
        mov [ecx], eax
    }
}

static INT16 LOAD_INT16_REVERSED(void *p)
{
    __asm {
        mov eax, p
        mov eax, [eax]
        xchg ah,al
    }
}

/* ---------------------------------------------------------------------- */
#else /* ANSI_C_ONLY or non-specialized architecture */
/* ---------------------------------------------------------------------- */

static INT32 LOAD_INT32_REVERSED(void *ptr)
{
    UINT32 temp = *(UINT32 *)ptr;
    temp = ((temp & 0xFF000000) >> 24) | ((temp & 0x00FF0000) >> 8 )
         | ((temp & 0x0000FF00) << 8 ) | ((temp & 0x000000FF) << 24);
    return (INT32)temp;
}
               
static void STORE_INT32_REVERSED(void *ptr, INT32 x)
{
    UINT32 i = (UINT32)x;
    *(UINT32 *)ptr = ((i & 0xFF000000) >> 24) | ((i & 0x00FF0000) >> 8 )
                   | ((i & 0x0000FF00) << 8 ) | ((i & 0x000000FF) << 24);
}

static INT16 LOAD_INT16_REVERSED(void *ptr)
{
    UINT16 temp = *(UINT16 *)ptr;
    temp = (temp >> 8) | (temp << 8);
    return (INT16)temp;
}
               
/* ---------------------------------------------------------------------- */
#endif
/* ---------------------------------------------------------------------- */

static INT16 LOAD_INT16_LITTLE(void *ptr)
{
    #if ( ! __LITTLE_ENDIAN__)
    return LOAD_INT16_REVERSED(ptr);
    #else
    return *(INT16 *)ptr;
    #endif
}

static INT32 LOAD_INT32_LITTLE(void *ptr)
{
    #if ( ! __LITTLE_ENDIAN__)
    return LOAD_INT32_REVERSED(ptr);
    #else
    return *(INT32 *)ptr;
    #endif
}

static void STORE_INT32_LITTLE(void *ptr, INT32 x)
{
    #if ( ! __LITTLE_ENDIAN__)
    STORE_INT32_REVERSED(ptr,x);
    #else
    *(INT32 *)ptr = x;
    #endif
}

static void STORE_INT32_BIG(void *ptr, INT32 x)
{
    #if __LITTLE_ENDIAN__
    STORE_INT32_REVERSED(ptr, x);
    #else
    *(INT32 *)ptr = x;
    #endif
}

static void STORE_INT64_BIG(void *ptr, INT64 x)
{
    #if __LITTLE_ENDIAN__
    STORE_INT32_REVERSED((INT8 *)ptr + 0, (INT32)(x >> 32));
    STORE_INT32_REVERSED((INT8 *)ptr + 4, (INT32)x);
    #else
    *(INT64 *)ptr = x;
    #endif
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin PRF and PRG Section -------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* UMAC uses a PRF in two cases. 1) When the message being MAC'd is short */
/* the PRF acts on the message directly, and 2) If the message is longer, */
/* it is first compressed with a hash function, properly encoded and      */
/* then sent to the PRF. The output of the PRF is the MAC tag.            */
/*                                                                        */
/* The PRF provides two interfaces, one incremental and the other non-    */
/* incremental. In the incremental interface, the PRF client calls the    */
/* routine prf_update() as many times as necessary. When there is no more */
/* data to be fed to the PRF, the client calls prf_final() which          */
/* calculates the PRF output. Before beginning another PRF calculation    */
/* the prf_reset() routine must be called. The non-incremental routine,   */
/* prf(), is equivalent to the sequence of calls prf_update() and         */
/* prf_final(); however it is optimized and should be                     */
/* used whenever the incremental interface is not necessary.              */
/*                                                                        */
/* The routine prf_init() initializes the prf_ctx data structure and      */
/* must be called once, before any other PRF routine.                     */
/*                                                                        */
/* UMAC also requires a PRG for subkey generation. In most instances of   */
/* UMAC the PRF and PRG will both use the same cryptographic primitive    */
/* and so they are here together in the same section of code. The routine */
/* prg() has no preconditions and fills an arbitrary buffer with pseudo-  */
/* random bytes.                                                          */

/* ---------------------------------------------------------------------- */
/* ----- PRF/PRG Constants and PRF_CTX ---------------------------------- */
/* ---------------------------------------------------------------------- */

#if (UMAC_STD_30 || UMAC_STD_60)

#define SHA1_CHAIN_WORDS   (5)                  /* Standard SHA1 details  */
#define SHA1_CHAIN_BYTES   (4*SHA1_CHAIN_WORDS)

typedef struct SHA1_Context {      /* Structure for incremental interface */
    INT32 state[SHA1_CHAIN_WORDS];
    INT64 count;
    INT8 buffer[64];
} SHA1_CTX;

typedef struct {
    INT32 k1[SHA1_CHAIN_WORDS];    /* Structure for HMAC          */
    INT32 k2[SHA1_CHAIN_WORDS];    /* and preprocessed HMAC keys. */
    SHA1_CTX hc;
} prf_ctx;

#elif (UMAC_MMX_15 || UMAC_MMX_30 || UMAC_MMX_60)

#define RC6_KEY_BYTES    16                /* Standard RC6 details */
#define RC6_ROUNDS       20       
#define RC6_KEY_WORDS    4      
#define RC6_TABLE_WORDS  (2*RC6_ROUNDS+4)  
#define RC6_P            0xb7e15163u
#define RC6_Q            0x9e3779b9u

typedef struct {
    INT32 k1[RC6_TABLE_WORDS];            /* 3-Key CBC keys       */
    INT32 k2[RC6_TABLE_WORDS];
    INT32 k3[RC6_TABLE_WORDS];
    INT32 chain[4];           /* CBC Chaining variables            */
    INT32 k1_idx[4];          /* Preprocessed chaining variables   */
    INT32 k3_idx[4];          /* incorporating prefixed prf index  */
    INT8 buf[16];             /* Buffer for incremental interfce   */
    INT32 next_buf_pos;       /* Buffer bookeeping                 */
} prf_ctx;

#endif

/* ---------------------------------------------------------------------- */
/* ----- PRF/PRG Based on sha1 ------------------------------------------ */
/* ---------------------------------------------------------------------- */

#if (UMAC_STD_30 || UMAC_STD_60)

/* Code derived from the original by Steve Reid <steve@edmweb.com>        */
/* with optimizations derived from Bosselaers, Govaerts and Vendewalle,   */
/* "Fast Hashing on the Pentium", Crypto 1996.                            */

/* ---------------------------------------------------------------------- */
#if (( ! ANSI_C_ONLY) && __GNUC__ && __i386__)
/* ---------------------------------------------------------------------- */

#define R0(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "andl %%"#w",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "leal 0x5A827999(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "bswap %%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"
    
#define R1(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "andl %%"#w",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "leal 0x5A827999(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+8)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+32)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+52)&63)(%%ebp),%%edi\n\t" \
    "roll $1,%%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"
    
#define R2(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "xorl %%"#w",%%edi\n\t" \
    "leal 0x6ED9EBA1(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+8)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+32)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+52)&63)(%%ebp),%%edi\n\t" \
    "roll $1,%%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"
    
#define R3(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "orl %%"#w",%%edi\n\t" \
    "andl %%"#y",%%edi\n\t" \
    "movl %%"#x",%%ebp\n\t" \
    "andl %%"#w",%%ebp\n\t" \
    "orl %%ebp,%%edi\n\t" \
    "movl (%%esp),%%ebp\n\t" \
    "leal 0x8F1BBCDC(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+8)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+32)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+52)&63)(%%ebp),%%edi\n\t" \
    "roll $1,%%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"
    
#define R4(v,w,x,y,z,i) \
    "movl %%"#x",%%edi\n\t" \
    "xorl %%"#y",%%edi\n\t" \
    "xorl %%"#w",%%edi\n\t" \
    "leal 0xCA62C1D6(%%"#z",%%edi),%%"#z"\n\t" \
    "movl %%"#v",%%edi\n\t" \
    "roll $5,%%edi\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "movl (("#i"*4)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+8)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+32)&63)(%%ebp),%%edi\n\t" \
    "xorl (("#i"*4+52)&63)(%%ebp),%%edi\n\t" \
    "roll $1,%%edi\n\t" \
    "movl %%edi,(("#i"*4)&63)(%%ebp)\n\t" \
    "addl %%edi,%%"#z"\n\t" \
    "roll $30,%%"#w"\n\t"
    
/* ---------------------------------------------------------------------- */

static void sha1_transform(INT32 state_in [ 5], 
                         INT32 state_out[ 5], 
                         INT8  buffer   [64])
{
    INT32 block[16];        /* Copy data to temporary buffer for */
    memcpy(block,buffer,64); /* endian reversal required by sha1  */

    asm volatile (
        "pushl %%ebp\n\t"  /* push ebp */
        "pushl %%eax\n\t"  /* push state_out */
        "pushl %%edi\n\t"  /* push state_in */
        "pushl %%ebx\n\t"  /* push buffer */
        "movl %%ebx,%%ebp\n\t"
        "movl 0(%%edi),%%eax\n\t"
        "movl 4(%%edi),%%ebx\n\t"
        "movl 8(%%edi),%%ecx\n\t"
        "movl 12(%%edi),%%edx\n\t"
        "movl 16(%%edi),%%esi\n\t"
        R0(eax,ebx,ecx,edx,esi, 0) R0(esi,eax,ebx,ecx,edx, 1) 
        R0(edx,esi,eax,ebx,ecx, 2) R0(ecx,edx,esi,eax,ebx, 3)
        R0(ebx,ecx,edx,esi,eax, 4) R0(eax,ebx,ecx,edx,esi, 5) 
        R0(esi,eax,ebx,ecx,edx, 6) R0(edx,esi,eax,ebx,ecx, 7)
        R0(ecx,edx,esi,eax,ebx, 8) R0(ebx,ecx,edx,esi,eax, 9) 
        R0(eax,ebx,ecx,edx,esi,10) R0(esi,eax,ebx,ecx,edx,11)
        R0(edx,esi,eax,ebx,ecx,12) R0(ecx,edx,esi,eax,ebx,13) 
        R0(ebx,ecx,edx,esi,eax,14) R0(eax,ebx,ecx,edx,esi,15)
        R1(esi,eax,ebx,ecx,edx,16) R1(edx,esi,eax,ebx,ecx,17) 
        R1(ecx,edx,esi,eax,ebx,18) R1(ebx,ecx,edx,esi,eax,19)
        R2(eax,ebx,ecx,edx,esi,20) R2(esi,eax,ebx,ecx,edx,21) 
        R2(edx,esi,eax,ebx,ecx,22) R2(ecx,edx,esi,eax,ebx,23)
        R2(ebx,ecx,edx,esi,eax,24) R2(eax,ebx,ecx,edx,esi,25) 
        R2(esi,eax,ebx,ecx,edx,26) R2(edx,esi,eax,ebx,ecx,27)
        R2(ecx,edx,esi,eax,ebx,28) R2(ebx,ecx,edx,esi,eax,29) 
        R2(eax,ebx,ecx,edx,esi,30) R2(esi,eax,ebx,ecx,edx,31)
        R2(edx,esi,eax,ebx,ecx,32) R2(ecx,edx,esi,eax,ebx,33) 
        R2(ebx,ecx,edx,esi,eax,34) R2(eax,ebx,ecx,edx,esi,35)
        R2(esi,eax,ebx,ecx,edx,36) R2(edx,esi,eax,ebx,ecx,37) 
        R2(ecx,edx,esi,eax,ebx,38) R2(ebx,ecx,edx,esi,eax,39)
        R3(eax,ebx,ecx,edx,esi,40) R3(esi,eax,ebx,ecx,edx,41) 
        R3(edx,esi,eax,ebx,ecx,42) R3(ecx,edx,esi,eax,ebx,43)
        R3(ebx,ecx,edx,esi,eax,44) R3(eax,ebx,ecx,edx,esi,45) 
        R3(esi,eax,ebx,ecx,edx,46) R3(edx,esi,eax,ebx,ecx,47)
        R3(ecx,edx,esi,eax,ebx,48) R3(ebx,ecx,edx,esi,eax,49) 
        R3(eax,ebx,ecx,edx,esi,50) R3(esi,eax,ebx,ecx,edx,51)
        R3(edx,esi,eax,ebx,ecx,52) R3(ecx,edx,esi,eax,ebx,53) 
        R3(ebx,ecx,edx,esi,eax,54) R3(eax,ebx,ecx,edx,esi,55)
        R3(esi,eax,ebx,ecx,edx,56) R3(edx,esi,eax,ebx,ecx,57) 
        R3(ecx,edx,esi,eax,ebx,58) R3(ebx,ecx,edx,esi,eax,59)
        R4(eax,ebx,ecx,edx,esi,60) R4(esi,eax,ebx,ecx,edx,61) 
        R4(edx,esi,eax,ebx,ecx,62) R4(ecx,edx,esi,eax,ebx,63)
        R4(ebx,ecx,edx,esi,eax,64) R4(eax,ebx,ecx,edx,esi,65) 
        R4(esi,eax,ebx,ecx,edx,66) R4(edx,esi,eax,ebx,ecx,67)
        R4(ecx,edx,esi,eax,ebx,68) R4(ebx,ecx,edx,esi,eax,69) 
        R4(eax,ebx,ecx,edx,esi,70) R4(esi,eax,ebx,ecx,edx,71)
        R4(edx,esi,eax,ebx,ecx,72) R4(ecx,edx,esi,eax,ebx,73) 
        R4(ebx,ecx,edx,esi,eax,74) R4(eax,ebx,ecx,edx,esi,75)
        R4(esi,eax,ebx,ecx,edx,76) R4(edx,esi,eax,ebx,ecx,77) 
        R4(ecx,edx,esi,eax,ebx,78) R4(ebx,ecx,edx,esi,eax,79)
        "popl %%ebp\n\t"
        "popl %%edi\n\t"
        "popl %%ebp\n\t"
        "addl 0(%%edi),%%eax\n\t"
        "addl 4(%%edi),%%ebx\n\t"
        "addl 8(%%edi),%%ecx\n\t"
        "addl 12(%%edi),%%edx\n\t"
        "addl 16(%%edi),%%esi\n\t"
        "movl %%eax,0(%%ebp)\n\t"
        "movl %%ebx,4(%%ebp)\n\t"
        "movl %%ecx,8(%%ebp)\n\t"
        "movl %%edx,12(%%ebp)\n\t"
        "movl %%esi,16(%%ebp)\n\t"
        "popl %%ebp"
        : 
        : "D" (state_in), "a" (state_out), "b" (block)
        : "eax","ebx","ecx","edx","esi","edi","memory");
}

/* ---------------------------------------------------------------------- */
#else /* ANSI_C_ONLY or non-specialized architecture */
/* ---------------------------------------------------------------------- */

#if (__LITTLE_ENDIAN__)
/* This version of blk0 does an inline endian reversal of input buffer */
#define blk0(i) (block[i] = LOAD_INT32_REVERSED(&(block[i])))
#else
#define blk0(i) (block[i])
#endif
#define blk(i) (block[i&15] = ROTL_CONST(block[(i+13)&15] ^ \
                                         block[(i+ 8)&15] ^ \
                                         block[(i+ 2)&15] ^ \
                                         block[ i    &15],1))

/* (R0+R1), R2, R3, R4 are the different operations used in sha1 */
#define R0(v,w,x,y,z,i) z+=((w&(x^y))^y)+    blk0(i)+0x5A827999+ \
                           ROTL_CONST(v,5); w=ROTL_CONST(w,30);
#define R1(v,w,x,y,z,i) z+=((w&(x^y))^y)+    blk (i)+0x5A827999+ \
                           ROTL_CONST(v,5);w=ROTL_CONST(w,30);
#define R2(v,w,x,y,z,i) z+=(w^x^y)+          blk (i)+0x6ED9EBA1+ \
                           ROTL_CONST(v,5);w=ROTL_CONST(w,30);
#define R3(v,w,x,y,z,i) z+=(((w|x)&y)|(w&x))+blk (i)+0x8F1BBCDC+ \
                           ROTL_CONST(v,5);w=ROTL_CONST(w,30);
#define R4(v,w,x,y,z,i) z+=(w^x^y)+          blk (i)+0xCA62C1D6+ \
                           ROTL_CONST(v,5);w=ROTL_CONST(w,30);

/* ---------------------------------------------------------------------- */

static void sha1_transform(INT32 state_in[ 5], 
                           INT32 state_out[ 5], 
                           INT8  buffer   [64])
{
    INT32 a, b, c, d, e;
    INT32 block[16];        /* Copy data to temporary buffer for */
    memcpy(block,buffer,64); /* endian reversal required by sha1  */
        
    /* Copy ctx->state[] to working vars */
    a = state_in[0];
    b = state_in[1];
    c = state_in[2];
    d = state_in[3];
    e = state_in[4];
    /* 4 rounds of 20 operations each. Loop unrolled. */
    R0(a,b,c,d,e, 0); R0(e,a,b,c,d, 1); R0(d,e,a,b,c, 2); R0(c,d,e,a,b, 3);
    R0(b,c,d,e,a, 4); R0(a,b,c,d,e, 5); R0(e,a,b,c,d, 6); R0(d,e,a,b,c, 7);
    R0(c,d,e,a,b, 8); R0(b,c,d,e,a, 9); R0(a,b,c,d,e,10); R0(e,a,b,c,d,11);
    R0(d,e,a,b,c,12); R0(c,d,e,a,b,13); R0(b,c,d,e,a,14); R0(a,b,c,d,e,15);
    R1(e,a,b,c,d,16); R1(d,e,a,b,c,17); R1(c,d,e,a,b,18); R1(b,c,d,e,a,19);
    R2(a,b,c,d,e,20); R2(e,a,b,c,d,21); R2(d,e,a,b,c,22); R2(c,d,e,a,b,23);
    R2(b,c,d,e,a,24); R2(a,b,c,d,e,25); R2(e,a,b,c,d,26); R2(d,e,a,b,c,27);
    R2(c,d,e,a,b,28); R2(b,c,d,e,a,29); R2(a,b,c,d,e,30); R2(e,a,b,c,d,31);
    R2(d,e,a,b,c,32); R2(c,d,e,a,b,33); R2(b,c,d,e,a,34); R2(a,b,c,d,e,35);
    R2(e,a,b,c,d,36); R2(d,e,a,b,c,37); R2(c,d,e,a,b,38); R2(b,c,d,e,a,39);
    R3(a,b,c,d,e,40); R3(e,a,b,c,d,41); R3(d,e,a,b,c,42); R3(c,d,e,a,b,43);
    R3(b,c,d,e,a,44); R3(a,b,c,d,e,45); R3(e,a,b,c,d,46); R3(d,e,a,b,c,47);
    R3(c,d,e,a,b,48); R3(b,c,d,e,a,49); R3(a,b,c,d,e,50); R3(e,a,b,c,d,51);
    R3(d,e,a,b,c,52); R3(c,d,e,a,b,53); R3(b,c,d,e,a,54); R3(a,b,c,d,e,55);
    R3(e,a,b,c,d,56); R3(d,e,a,b,c,57); R3(c,d,e,a,b,58); R3(b,c,d,e,a,59);
    R4(a,b,c,d,e,60); R4(e,a,b,c,d,61); R4(d,e,a,b,c,62); R4(c,d,e,a,b,63);
    R4(b,c,d,e,a,64); R4(a,b,c,d,e,65); R4(e,a,b,c,d,66); R4(d,e,a,b,c,67);
    R4(c,d,e,a,b,68); R4(b,c,d,e,a,69); R4(a,b,c,d,e,70); R4(e,a,b,c,d,71);
    R4(d,e,a,b,c,72); R4(c,d,e,a,b,73); R4(b,c,d,e,a,74); R4(a,b,c,d,e,75);
    R4(e,a,b,c,d,76); R4(d,e,a,b,c,77); R4(c,d,e,a,b,78); R4(b,c,d,e,a,79);
    /* Add the working vars back into ctx.state[] */
    state_out[0] = state_in[0] + a;
    state_out[1] = state_in[1] + b;
    state_out[2] = state_in[2] + c;
    state_out[3] = state_in[3] + d;
    state_out[4] = state_in[4] + e;
}

/* ---------------------------------------------------------------------- */
#endif
/* ---------------------------------------------------------------------- */

static void sha1_init(SHA1_CTX* ctx, INT32 state_in[5], INT32 bit_len)
/* This version of sha1_init accepts an initialization vector and    */
/* bit-length as parameters to accommodate preprocessed key in HMAC. */
{
    /* SHA1_ initialization constants */
    ctx->state[0] = state_in[0];
    ctx->state[1] = state_in[1];
    ctx->state[2] = state_in[2];
    ctx->state[3] = state_in[3];
    ctx->state[4] = state_in[4];
    ctx->count    = bit_len;
}

/* ---------------------------------------------------------------------- */

static void sha1_update(SHA1_CTX* ctx, INT8* data, INT32 len)
/* Incorporate len bytes of data into the sha1 context structure. */
{
    INT32 i,j;

    i = 0;
    j = ctx->count;
    ctx->count += (len << 3);
    j = (j >> 3) & 63;
    if ((j + len) >= 64) {
        if (j) {
            i = 64-j;
            memcpy(&ctx->buffer[j], data, i);
            sha1_transform(ctx->state, ctx->state, ctx->buffer);
        }
        while (i + 63 < len) {
            sha1_transform(ctx->state, ctx->state, &data[i]);
            i += 64;
        }
        j = 0;
    }
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

/* ---------------------------------------------------------------------- */

static void sha1_final(INT8 digest[], SHA1_CTX* ctx)
/* Append bit-count to message and finalize pending data */
{
    INT32 i,j;
    INT8 temp[64] = {0x80,0,};
    
    j = (((INT32)ctx->count >> 3) & 63);
    if (j > 55) {
        STORE_INT64_BIG(temp+56, ctx->count);
        sha1_update(ctx, temp, 64 - j);
        ((WORD *)temp)[0] = 0;
        sha1_update(ctx, temp, 64);
    } else {
        STORE_INT64_BIG(temp+56-j, ctx->count);
        sha1_update(ctx, temp, 64 - j);
    }
    for (i = 0; i < SHA1_CHAIN_WORDS; i++)
        STORE_INT32_BIG((INT32 *)digest + i, ctx->state[i]);
}

/* ---------------------------------------------------------------------- */

static void sha1(INT8 digest[], SHA1_CTX* ctx, INT8* data, INT32 len)
/* All-In-One (non-incremental) sha1 for messages shorter than 2^29-1     */
/* bytes. Assumes a pre-initialized sha1 context structure.               */
{
    INT8 buf[64]={0};
    INT32 i;
    INT32 olen;

    olen = len;
    while (len >= 64) {
        sha1_transform(ctx->state, ctx->state, data);
        data += 64;
        len -= 64;
    }
    memcpy(buf,data,len);
    buf[len] = 0x80;
    if (len > 55) {
        sha1_transform(ctx->state, ctx->state, buf);
        memset(buf,0,64);
    }
    STORE_INT32_BIG(buf+60, (olen << 3) + ctx->count);
    sha1_transform(ctx->state, ctx->state, buf);
    
    for (i = 0; i < SHA1_CHAIN_WORDS; i++)
        STORE_INT32_BIG((INT32 *)digest + i, ctx->state[i]);
}

/* ---------------------------------------------------------------------- */

static void prg(INT8 k[], INT32 idx, INT32 nbytes, INT8 *dst_buf)
/* Generate pseudorandom bytes using SHA1 in a feedback mode as           */
/* described in the UMAC specification. Each value of idx causes a        */
/* different pseudorandom stream.                                         */
{
    INT32 init_state[5] = {0x67452301,0xEFCDAB89,0x98BADCFE, \
                            0x10325476,0xC3D2E1F0};
    SHA1_CTX temp_ctx;
    INT32 bytes_to_copy;
    INT8  in_buf[2 * SHA1_CHAIN_BYTES] = {0},
           out_buf[SHA1_CHAIN_BYTES] = {0};
    
    out_buf[sizeof(out_buf) - 1] = (INT8)idx;
    while (nbytes) {
        memcpy(in_buf,k,SHA1_CHAIN_BYTES);
        memcpy(in_buf+SHA1_CHAIN_BYTES,out_buf,SHA1_CHAIN_BYTES);
        sha1_init(&temp_ctx, init_state, 0);
        sha1(out_buf, &temp_ctx, in_buf, sizeof(in_buf));
        if (nbytes < SHA1_CHAIN_BYTES)
            bytes_to_copy = nbytes;
        else
            bytes_to_copy = SHA1_CHAIN_BYTES;
        memcpy(dst_buf, out_buf, bytes_to_copy);
        nbytes -= bytes_to_copy;
        dst_buf += bytes_to_copy;
    }
}

/* ---------------------------------------------------------------------- */

static void prf_reset(prf_ctx *pc)
/* Resets the PRF's sha1 context to the precomputed value of the          */
/* PRF's index and hmac key                                               */
{
    sha1_init(&pc->hc,pc->k1,1024);
}

/* ---------------------------------------------------------------------- */

static void prf_init(prf_ctx *pc,INT8 prg_key[],
                     INT32 prg_idx, INT32 prf_idx)
/* Precompute hmac-sha1 chaining values according to the prf index        */
/* (prf_idx) and prf_key derived from the prg_key.                        */
{
    INT32 init_state[5] = {0x67452301,0xEFCDAB89,0x98BADCFE,
                            0x10325476,0xC3D2E1F0};
    INT32 prf_key[16];
    WORD i;
    
    prg(prg_key,prg_idx,sizeof(prf_key),(INT8 *)prf_key);
    for (i = 0; i < 16; i++)
        prf_key[i] ^= 0x36363636;
    sha1_transform(init_state, pc->k1, (INT8 *)prf_key);
    for (i = 0; i < 16; i++) {
        prf_key[i] ^= 0x6A6A6A6A;
    }
    sha1_transform(init_state, pc->k2, (INT8 *)prf_key);
    memset(prf_key, 0, sizeof(prf_key));
    ((INT8 *)prf_key)[sizeof(prf_key) - 1] = (INT8)prf_idx;
    sha1_transform(pc->k1, pc->k1, (INT8 *)prf_key);
    sha1_init(&pc->hc,pc->k1,1024);
}

/* ---------------------------------------------------------------------- */

static void prf_update(prf_ctx *pc, INT8 *buf, INT32 nbytes)
{
    sha1_update(&pc->hc, buf, nbytes);
}

/* ---------------------------------------------------------------------- */

static void prf_final(prf_ctx *pc, INT8 tag[])
/* Complete the HMAC of the input data                                    */
{
    INT8 tdigest[SHA1_CHAIN_BYTES];
    
    sha1_final(tdigest,&pc->hc);
    sha1_init(&pc->hc,pc->k2,512);
    sha1(tag, &pc->hc, tdigest, sizeof(tdigest));
}

/* ---------------------------------------------------------------------- */

static void prf(prf_ctx *pc, INT8 *buf, INT32 nbytes, INT8 tag[])
/* All-in-one prf_update(), prf_final() equivalent.                       */
{
    INT8 tdigest[SHA1_CHAIN_BYTES];
    
    sha1(tdigest, &pc->hc, buf, nbytes);
    sha1_init(&pc->hc,pc->k2,512);
    sha1(tag, &pc->hc, tdigest, sizeof(tdigest));
}

/* ---------------------------------------------------------------------- */
#else 
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* ----- PRF/PRG Based on RC6 ------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
#if (( ! ANSI_C_ONLY) && __GNUC__ && __i386__)
/* ---------------------------------------------------------------------- */

#define RC6_BLOCK(a,b,c,d,n) \
    "leal 1(%%"#b",%%"#b"),%%eax\n\t" \
    "imul %%"#b",%%eax\n\t" \
    "roll $5,%%eax\n\t" \
    "leal 1(%%"#d",%%"#d"),%%ecx\n\t" \
    "imul %%"#d",%%ecx\n\t" \
    "roll $5,%%ecx\n\t" \
    "xorl %%eax,%%"#a"\n\t" \
    "roll %%cl,%%"#a"\n\t" \
    "addl "#n"(%%esi),%%"#a"\n\t" \
    "xorl %%ecx,%%"#c"\n\t" \
    "movl %%eax,%%ecx\n\t" \
    "roll %%cl,%%"#c"\n\t" \
    "addl "#n"+4(%%esi),%%"#c"\n\t"

static void RC6(INT32 S[], void *pt, void *ct)
{ 
    INT32 *s = S;
    INT32 A = ((INT32 *)pt)[0];
    INT32 B = ((INT32 *)pt)[1] + *s++;
    INT32 C = ((INT32 *)pt)[2];
    INT32 D = ((INT32 *)pt)[3] + *s++;


    asm volatile (
        "pushl %%ebp\n\t"
        "movl %%ecx,%%ebp\n\t"
      
        RC6_BLOCK(edi,ebx,ebp,edx,0)
        RC6_BLOCK(ebx,ebp,edx,edi,8)
        RC6_BLOCK(ebp,edx,edi,ebx,16)
        RC6_BLOCK(edx,edi,ebx,ebp,24)
      
        RC6_BLOCK(edi,ebx,ebp,edx,32)
        RC6_BLOCK(ebx,ebp,edx,edi,40)
        RC6_BLOCK(ebp,edx,edi,ebx,48)
        RC6_BLOCK(edx,edi,ebx,ebp,56)
      
        RC6_BLOCK(edi,ebx,ebp,edx,64)
        RC6_BLOCK(ebx,ebp,edx,edi,72)
        RC6_BLOCK(ebp,edx,edi,ebx,80)
        RC6_BLOCK(edx,edi,ebx,ebp,88)
      
        RC6_BLOCK(edi,ebx,ebp,edx,96)
        RC6_BLOCK(ebx,ebp,edx,edi,104)
        RC6_BLOCK(ebp,edx,edi,ebx,112)
        RC6_BLOCK(edx,edi,ebx,ebp,120)
      
        RC6_BLOCK(edi,ebx,ebp,edx,128)
        RC6_BLOCK(ebx,ebp,edx,edi,136)
        RC6_BLOCK(ebp,edx,edi,ebx,144)
        RC6_BLOCK(edx,edi,ebx,ebp,152)
      
        "movl %%ebp,%%ecx\n\t"
        "popl %%ebp"
        : "=D" (A), "=b" (B), "=c" (C), "=d" (D)
        : "0" (A), "1" (B), "2" (C), "3" (D), "S" (s)
        : "eax","ebx","ecx","edx","esi","edi");
    

    A += *(s+40);
    C += *(s+41);
    ((INT32 *)ct)[0] = A; 
    ((INT32 *)ct)[1] = B;  
    ((INT32 *)ct)[2] = C; 
    ((INT32 *)ct)[3] = D;  
} 

/* ---------------------------------------------------------------------- */
#else /* ANSI_C_ONLY or non-specialized architecture */
/* ---------------------------------------------------------------------- */

#define RC6_BLOCK(a,b,c,d,n)    \
        t = b*(2*b+1);          \
        t = ROTL_CONST(t,5);    \
        u = d*(2*d+1);          \
        u = ROTL_CONST(u,5);    \
        a ^= t;                 \
        a = ROTL_VAR(a,u);  \
        a += s[n];              \
        c ^= u;                 \
        c = ROTL_VAR(c,t);  \
        c += s[n+1];

static void RC6(INT32 S[], void *pt, void *ct)
{ 
    const INT32 *s = (INT32 *)S;
    INT32 A = LOAD_INT32_LITTLE((INT32 *)pt  );
    INT32 B = LOAD_INT32_LITTLE((INT32 *)pt+1) + s[0];
    INT32 C = LOAD_INT32_LITTLE((INT32 *)pt+2);
    INT32 D = LOAD_INT32_LITTLE((INT32 *)pt+3) + s[1];
    INT32 t,u;
    
    RC6_BLOCK(A,B,C,D, 2)
    RC6_BLOCK(B,C,D,A, 4)
    RC6_BLOCK(C,D,A,B, 6)
    RC6_BLOCK(D,A,B,C, 8)

    RC6_BLOCK(A,B,C,D,10)
    RC6_BLOCK(B,C,D,A,12)
    RC6_BLOCK(C,D,A,B,14)
    RC6_BLOCK(D,A,B,C,16)

    RC6_BLOCK(A,B,C,D,18)
    RC6_BLOCK(B,C,D,A,20)
    RC6_BLOCK(C,D,A,B,22)
    RC6_BLOCK(D,A,B,C,24)

    RC6_BLOCK(A,B,C,D,26)
    RC6_BLOCK(B,C,D,A,28)
    RC6_BLOCK(C,D,A,B,30)
    RC6_BLOCK(D,A,B,C,32)

    RC6_BLOCK(A,B,C,D,34)
    RC6_BLOCK(B,C,D,A,36)
    RC6_BLOCK(C,D,A,B,38)
    RC6_BLOCK(D,A,B,C,40)

    A += s[42];
    C += s[43];
    STORE_INT32_LITTLE((INT32 *)ct  , A); 
    STORE_INT32_LITTLE((INT32 *)ct+1, B); 
    STORE_INT32_LITTLE((INT32 *)ct+2, C); 
    STORE_INT32_LITTLE((INT32 *)ct+3, D); 
} 

/* ---------------------------------------------------------------------- */
#endif /* 386 && gcc */
/* ---------------------------------------------------------------------- */

static void RC6_SETUP(INT8 *K, INT32 S[])
{
    WORD i, j, k, u=32/8;
    INT32 A, B, L[RC6_KEY_WORDS]; 
    L[RC6_KEY_WORDS-1]=0;
    i = RC6_KEY_BYTES-1;
    do {
        L[i/u] = (L[i/u]<<8)+(UINT8)K[i];
    } while (i--);
    S[0]=RC6_P;
    for (i=1; i<RC6_TABLE_WORDS; i++)
        S[i] = S[i-1]+RC6_Q;
    A=B=i=j=k=0;
    while (k<3*RC6_TABLE_WORDS) {
        A = S[i] = ROTL_CONST(S[i]+(A+B),3);  
        B = L[j] = ROTL_VAR(L[j]+(A+B),(A+B));
        k++;
        i=(i+1)%RC6_TABLE_WORDS;
        j=(j+1)%RC6_KEY_WORDS;
    } 
} 

/* ---------------------------------------------------------------------- */

static void cbc_step(INT32 S[], INT32 *chain, INT32 *data)
{
    chain[0] ^= data[0];
    chain[1] ^= data[1];
    chain[2] ^= data[2];
    chain[3] ^= data[3];
    RC6(S,chain,chain);
}

/* ---------------------------------------------------------------------- */

static void prg(INT8 k[], INT32 prg_idx, INT32 nbytes, INT8 *dst_buf)
/* Generate pseudorandom bytes using RC6 in a feedback mode as            */
/* described in the UMAC specification. Each value of idx causes a        */
/* different pseudorandom stream.                                         */
{
    INT32 tmp[4] = {0,0,0,0},
           S[RC6_TABLE_WORDS],
           bytes_to_copy;
    
    RC6_SETUP(k, S);
    ((INT8 *)tmp)[15] = (INT8)prg_idx;
    while (nbytes) {
        RC6(S,tmp,tmp);
        bytes_to_copy = (nbytes < 16 ? nbytes : 16);
        memcpy(dst_buf, tmp, bytes_to_copy);
        nbytes -= bytes_to_copy;
        dst_buf += bytes_to_copy;
    }
}

/* ---------------------------------------------------------------------- */

static void prf_reset(prf_ctx *pc)
/* Reset the chaining variables to the precomputed encryption of index.   */
{
    pc->chain[0] = pc->k1_idx[0];
    pc->chain[1] = pc->k1_idx[1];
    pc->chain[2] = pc->k1_idx[2];
    pc->chain[3] = pc->k1_idx[3];
    pc->next_buf_pos = 0;
}

/* ---------------------------------------------------------------------- */

static void prf_init(prf_ctx *pc,INT8 key[],INT32 prg_idx,INT32 prf_idx)
/* Derive three subkeys and precompute the encryption of index.           */
{
    INT8 temp_cbc_keys[3*16];
    INT8 buf[16] = {0};
    
    memset(pc, 0, sizeof(prf_ctx));
    prg(key,prg_idx,sizeof(temp_cbc_keys),temp_cbc_keys);
    RC6_SETUP(&temp_cbc_keys[00], pc->k1);
    RC6_SETUP(&temp_cbc_keys[16], pc->k2);
    RC6_SETUP(&temp_cbc_keys[32], pc->k3);
    buf[15] = (INT8)prf_idx;
    RC6(pc->k1,buf,pc->k1_idx);
    RC6(pc->k3,buf,pc->k3_idx);
    prf_reset(pc);
}

/* ---------------------------------------------------------------------- */

static void prf_update(prf_ctx *pc, INT8 *buf, INT32 nbytes)
/* Incorporate as much of buf as possible into prf_ctx and buffer the     */
/* rest into pc->buf. 1-16 bytes will be buffered upon exit.              */
{
    INT32 i,j;
    
    i = 0;
    j = pc->next_buf_pos;
    if ((j + nbytes) > 16) {
        if (j) {
            i = 16 - j;
            memcpy(pc->buf+pc->next_buf_pos, buf, i);
            cbc_step(pc->k1,pc->chain,(INT32 *)pc->buf);
        }
        while (i + 16 < nbytes) {
            cbc_step(pc->k1,pc->chain,(INT32 *)&buf[i]);
            i += 16;
        }
        j = 0;
    }
    memcpy(pc->buf+j, buf+i, nbytes - i);
    pc->next_buf_pos = j + nbytes - i;
}

/* ---------------------------------------------------------------------- */

static void prf_final(prf_ctx *pc, INT8 tag[16])
/* If 16 bytes were left buffered by prf_update(), then we know that the  */
/* data length is divisible by 16, so we use k3 for final block. If < 16  */
/* were in the buffer, then we pad to 16 byte boundary and finish with k2 */
{
    INT32 count,next_pad;
    INT8 *p;

    if (pc->next_buf_pos != 16) {
        count = pc->next_buf_pos;
        p = pc->buf + count;
        next_pad = ((count + (16 - 1)) & ~(16 - 1));
        count = next_pad - count;
        memset(p,0,count);
        *p = 0x80;
        cbc_step(pc->k2,pc->chain,(INT32 *)pc->buf);
    } else {
        cbc_step(pc->k3,pc->chain,(INT32 *)pc->buf);
    }
    ((INT32 *)tag)[0] = pc->chain[0];
    ((INT32 *)tag)[1] = pc->chain[1];
    ((INT32 *)tag)[2] = pc->chain[2];
    ((INT32 *)tag)[3] = pc->chain[3];
}

/* ---------------------------------------------------------------------- */

static void prf(prf_ctx *pc, INT8 *buf, INT32 nbytes, INT8 tag[16])
/* Non-incremental call to 3-key CBC. prf_ctx must be reset before use.   */
/* nbytes == 0 indicates that the tag is the prf of idx under k3.         */
{
    if (nbytes) {
        while (nbytes > 16) {
            cbc_step(pc->k1,pc->chain,(INT32 *)buf);
            nbytes -= 16;
            buf += 16;
        }
        if (nbytes == 16) {
            cbc_step(pc->k3,pc->chain,(INT32 *)buf);
        } else {
            ((INT32 *)(pc->buf))[0] = 0;
            ((INT32 *)(pc->buf))[1] = 0;
            ((INT32 *)(pc->buf))[2] = 0;
            ((INT32 *)(pc->buf))[3] = 0;
            memcpy(pc->buf, buf, nbytes);
            pc->buf[nbytes] = 0x80;
            cbc_step(pc->k2,pc->chain,(INT32 *)buf);
        }
        ((INT32 *)tag)[0] = pc->chain[0];
        ((INT32 *)tag)[1] = pc->chain[1];
        ((INT32 *)tag)[2] = pc->chain[2];
        ((INT32 *)tag)[3] = pc->chain[3];
    } else {
        ((INT32 *)tag)[0] = pc->k3_idx[0];
        ((INT32 *)tag)[1] = pc->k3_idx[1];
        ((INT32 *)tag)[2] = pc->k3_idx[2];
        ((INT32 *)tag)[3] = pc->k3_idx[3];
    }
}

/* ---------------------------------------------------------------------- */
#endif /* RC6 based PRF/PRG */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End PRF and PRG Section ---------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin Universal Hash Section ----------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* The NH-based hash functions used in UMAC are described in the paper    */
/* and specification, both of which can be found at the UMAC website.     */
/* As with the PRF interface, the hash function interface has two         */
/* versions, one incremental and another non-incremental. In the          */
/* incremental interface, the client calls the routine hash_update() as   */
/* many times as necessary. When there is no more data to be fed to the   */
/* hash, the client calls hash_final() which calculates the hash output.  */
/* Before beginning another hash calculation the hash_reset() routine     */
/* must be called. The non-incremental routine, hash(), is equivalent to  */
/* the sequence of calls hash_update() and hash_final(); however it is    */
/* optimized and should be prefered whenever the incremental interface is */
/* not necessary. When using either interface, it is the client's         */
/* responsability to pass no more than HASH_BLOCK_SIZE bytes before       */
/* calling hash_final().                                                  */
/*                                                                        */
/* The routine hash_init() initializes the hash_ctx data structure and    */
/* must be called once, before any other PRF routine.                     */

#if (UMAC_MMX_15)
#define SECURITY         16
/* If SECURITY == 16 we output 64 bits per hash                           */
#define hash_aux_HBS_mult  hash_aux_32_HBS_mult /* SECURITY related alias */
#define hash_aux_PB_mult   hash_aux_32_PB_mult
#elif (UMAC_STD_30 || UMAC_MMX_30)
#define SECURITY         32
/* If SECURITY == 32 we output 64 bits per hash                           */
#define hash_aux_HBS_mult  hash_aux_64_HBS_mult /* SECURITY related alias */
#define hash_aux_PB_mult   hash_aux_64_PB_mult
#else
#define SECURITY         64
/* If SECURITY == 64 we output 128 bits per hash                           */
#define hash_aux_HBS_mult  hash_aux_128_HBS_mult /* SECURITY related alias */
#define hash_aux_PB_mult   hash_aux_128_PB_mult
#endif

#if (UMAC_STD_30 || UMAC_STD_60)

#define L1_COMPRESSION        32        /* Standard UMAC parameters */
#define L2_COMPRESSION        16
#define NH_WORD_SIZE           4
#define BYTES_PER_L1_SHIFT     8
#define BYTES_PER_L2_SHIFT     8
#define PAD_BOUNDARY           8
#define HASH_KEY_SIZE        384

#else /* (UMAC_MMX_15 || UMAC_MMX_30 || UMAC_MMX_60) */

#define L1_COMPRESSION      1024        /* Standard UMAC parameters */
#define L2_COMPRESSION         1
#define NH_WORD_SIZE           2
#define BYTES_PER_L1_SHIFT    32
#define BYTES_PER_L2_SHIFT     0
#define PAD_BOUNDARY          32
#define HASH_KEY_SIZE       4096

#endif

#define HASH_BLOCK_SIZE     4096
#define HASH_OUTPUT_LEN     (SECURITY / 4)
#define HASH_BUF_SIZE       64
#define BYTES_PER_L1_ITER   (2 * NH_WORD_SIZE * L1_COMPRESSION)

#define TOEPLITZ_KEYS       (SECURITY / (NH_WORD_SIZE * 8))
#define TOEPLITZ_SHIFTS     (TOEPLITZ_KEYS - 1)
#define TOEPLITZ_EXTRA      (TOEPLITZ_SHIFTS * \
                            (BYTES_PER_L1_SHIFT + BYTES_PER_L2_SHIFT))

/* ---------------------------------------------------------------------- */
#if (UMAC_STD_30 || UMAC_STD_60)
/* ---------------------------------------------------------------------- */

#define ALLOC_BOUNDARY (4) /* Maximize speed for vectors */

typedef struct {         /* Method dependent NH hashing state saved       */
    INT64 dtmp[2];       /* between incremental calls.                    */
    INT64 sum1, sum2;
    INT32 *key2;
} hash_state;

/* ---------------------------------------------------------------------- */
#else /* (UMAC_MMX_15 || UMAC_MMX_30 || UMAC_MMX_60) */
/* ---------------------------------------------------------------------- */

#define ALLOC_BOUNDARY (16) /* Maximize speed for vectors */

typedef struct {         /* Method dependent hashing state saved          */
    INT32 dtmp[4];       /* between incremental calls.                    */
} hash_state;

/* ---------------------------------------------------------------------- */
#endif
/* ---------------------------------------------------------------------- */

typedef struct {
    INT8  hash_key [HASH_KEY_SIZE + TOEPLITZ_EXTRA];
    INT8  data     [HASH_BUF_SIZE];  /* Incomming data buffer            */
    INT32 next_data_empty; /* Bookeeping variable for data buffer.       */
    INT32 bytes_hashed;    /* Bytes (of HASH_BLOCK_SIZE) incorperated.   */
    hash_state state;       /* Method dependent hashing state             */
} hash_ctx;


/* ---------------------------------------------------------------------- */
/* ----- STD Universal Hash --------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
#if (UMAC_STD_30 || UMAC_STD_60)
/* ---------------------------------------------------------------------- */

static void hash_reset(hash_ctx *hc)
/* Reset hash_ctx to ready for hashing of new data                        */
{
    hc->bytes_hashed = 0;
    hc->next_data_empty = 0;
    hc->state.sum1 = 0;
    hc->state.dtmp[0] = 0;
    #if (SECURITY == 64)
    hc->state.sum2 = 0;
    hc->state.dtmp[1] = 0;
    #endif
    hc->state.key2 = (INT32 *)(hc->hash_key + BYTES_PER_L1_ITER +
                                TOEPLITZ_SHIFTS * BYTES_PER_L1_SHIFT);
}

/* ---------------------------------------------------------------------- */

static void write_result(hash_ctx *hc, INT8 *result)
/* Method dependent manner of writing hash result to memory.              */
{
    STORE_INT64_BIG(result,hc->state.sum1);
    #if (SECURITY == 64)
    STORE_INT64_BIG(result+8,hc->state.sum2);
    #endif
}

/* ---------------------------------------------------------------------- */

static void hash_aux_64_PB_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by PAD_BOUNDARY (8), which means we can do  */
/* only one multiplication per iteration. 64 bits are written at hp.      */
{
  INT64 h;
  WORD c = dlen / 8;
  INT32 *k = (INT32 *)kp;
  INT32 *d = (INT32 *)dp;
  INT32 d0,d1,k0,k1;

  h = *((INT64 *)hp);
  do {
    d0 = LOAD_INT32_LITTLE(d+0);
    d1 = LOAD_INT32_LITTLE(d+1);
    k0 = *(k+0);
    k1 = *(k+1);

    h += (INT64)(INT32)(k0 + d0) * (INT64)(INT32)(k1 + d1);

    d += 2;
    k += 2;
  } while (--c);
  *((INT64 *)hp) = h;
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_PB_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by PAD_BOUNDARY (8), which means we can do  */
/* only one multiplication per iteration. 128 bits are written at hp by   */
/* performing two passes over the data with the second key being the      */
/* toeplitz shift of the first.                                           */
{
    INT64 h1,h2;
    WORD c = dlen / 8;
    INT32 *k = (INT32 *)kp;
    INT32 *d = (INT32 *)dp;
    INT32 d0,d1,k0,k1,k2,k3;

    h1 = *((INT64 *)hp+0);
    h2 = *((INT64 *)hp+1);
    k0 = *(k+0);
    k1 = *(k+1);
    do {
        d0 = LOAD_INT32_LITTLE(d+0);
        d1 = LOAD_INT32_LITTLE(d+1);
        k2 = *(k+2);
        k3 = *(k+3);

        h1 += (INT64)(INT32)(k0 + d0) * (INT64)(INT32)(k1 + d1);
        h2 += (INT64)(INT32)(k2 + d0) * (INT64)(INT32)(k3 + d1);

        k0 = k2;
        k1 = k3;
        d += 2;
        k += 2;
    } while (--c);
    *((INT64 *)hp+0) = h1;
    *((INT64 *)hp+1) = h2;
}

/* ---------------------------------------------------------------------- */
#if (( ! ANSI_C_ONLY) && __GNUC__ && __i386__)
/* ---------------------------------------------------------------------- */

#define NH_BLOCK(n) \
    "movl "#n"(%%ebx),%%eax\n\t" \
    "movl "#n"+4(%%ebx),%%edx\n\t" \
    "addl "#n"(%%ecx),%%eax\n\t" \
    "addl "#n"+4(%%ecx),%%edx\n\t" \
    "imull %%edx\n\t" \
    "addl %%eax,%%esi\n\t" \
    "adcl %%edx,%%edi\n\t"

static void hash_aux_64_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 64 bits are written at hp.             */
{
  INT32 *p = hp;
  
  asm volatile (
    "\n\t"
    "pushl %%ebp\n\t"
    "movl %%eax,%%ebp\n\t"
    ".align 4,0x90\n"
    "1:\n\t"
    
    NH_BLOCK(0)
    NH_BLOCK(8)
    NH_BLOCK(16)
    NH_BLOCK(24)
    NH_BLOCK(32)
    NH_BLOCK(40)
    NH_BLOCK(48)
    NH_BLOCK(56)

    "addl $64,%%ecx\n\t"
    "addl $64,%%ebx\n\t"
    "decl %%ebp\n\t"
    "jne 1b\n\t"
    "popl %%ebp"
    : "=S" (p[0]), "=D" (p[1])
    : "c" (kp), "b" (dp), "a" (dlen/64), "0" (p[0]), "1" (p[1])
    : "eax","ebx","ecx","edx","esi","edi");
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. 128 bits are written at hp by performing two     */
/* passes over the data with the second key being the toeplitz shift of   */
/* the first.                                                             */
{
    hash_aux_64_HBS_mult(kp,dp,hp,dlen);
    hash_aux_64_HBS_mult((INT8 *)kp+8,dp,(INT8 *)hp+8,dlen);
}

/* ---------------------------------------------------------------------- */
#elif (( ! ANSI_C_ONLY) && _M_IX86)
/* ---------------------------------------------------------------------- */

#define NH_BLOCK(n)        \
    __asm mov eax,n[ebx]   \
    __asm mov edx,n+4[ebx] \
    __asm add eax,n[ecx]   \
    __asm add edx,n+4[ecx] \
    __asm imul edx         \
    __asm add esi,eax      \
    __asm adc edi,edx

static void hash_aux_64_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 64 bits are written at hp.             */
{
  __asm mov ecx,kp
  __asm mov ebx,dp
  __asm mov eax,hp
  __asm mov edx,dlen
  __asm shr edx,6
  __asm push ebp
  __asm mov ebp,edx
  __asm mov esi,[eax]
  __asm mov edi,4[eax]
label1:
    NH_BLOCK(0)
    NH_BLOCK(8)
    NH_BLOCK(16)
    NH_BLOCK(24)
    NH_BLOCK(32)
    NH_BLOCK(40)
    NH_BLOCK(48)
    NH_BLOCK(56)
  __asm add ecx,64
  __asm add ebx,64
  __asm dec ebp
  __asm jne label1
  __asm pop ebp
  __asm mov eax,hp
  __asm mov [eax],esi
  __asm mov 4[eax],edi
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. 128 bits are written at hp by performing two     */
/* passes over the data with the second key being the toeplitz shift of   */
/* the first.                                                             */
{
    hash_aux_64_HBS_mult(kp,dp,hp,dlen);
    hash_aux_64_HBS_mult((INT8 *)kp+8,dp,(INT8 *)hp+8,dlen);
}

/* ---------------------------------------------------------------------- */
#else /* ANSI_C_ONLY or non-specialized architecture */
/* ---------------------------------------------------------------------- */

static void hash_aux_64_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 64 bits are written at hp.             */
{
  INT64 h;
  WORD c = dlen / 16;
  INT32 *k = (INT32 *)kp;
  INT32 *d = (INT32 *)dp;
  INT32 d0,d1,d2,d3;
  INT32 k0,k1,k2,k3;

  h = *((INT64 *)hp);
  do {
    d0 = LOAD_INT32_LITTLE(d+0);
    d1 = LOAD_INT32_LITTLE(d+1);
    d2 = LOAD_INT32_LITTLE(d+2);
    d3 = LOAD_INT32_LITTLE(d+3);
    k0 = *(k+0);
    k1 = *(k+1);
    k2 = *(k+2);
    k3 = *(k+3);
    h += (INT64)(INT32)(k0 + d0) * (INT64)(INT32)(k1 + d1);
    h += (INT64)(INT32)(k2 + d2) * (INT64)(INT32)(k3 + d3);
    d += 4;
    k += 4;
  } while (--c);
  *((INT64 *)hp) = h;
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 128 bits are written at hp by          */
/* performing two passes over the data with the second key being the      */
/* toeplitz shift of the first.                                           */
{
    INT64 h1,h2;
    WORD c = dlen / 16;
    INT32 *k = (INT32 *)kp;
    INT32 *d = (INT32 *)dp;
    INT32 d0,d1,d2,d3;
    INT32 k0,k1,k2,k3,k4,k5;

    h1 = *((INT64 *)hp);
    h2 = *((INT64 *)hp+1);
    k0 = *(k+0);
    k1 = *(k+1);
    do {
        d0 = LOAD_INT32_LITTLE(d+0);
        d1 = LOAD_INT32_LITTLE(d+1);
        d2 = LOAD_INT32_LITTLE(d+2);
        d3 = LOAD_INT32_LITTLE(d+3);
        k2 = *(k+2);
        k3 = *(k+3);
        k4 = *(k+4);
        k5 = *(k+5);
        h1 += (INT64)(INT32)(k0 + d0) * (INT64)(INT32)(k1 + d1);
        h1 += (INT64)(INT32)(k2 + d2) * (INT64)(INT32)(k3 + d3);
        h2 += (INT64)(INT32)(k2 + d0) * (INT64)(INT32)(k3 + d1);
        h2 += (INT64)(INT32)(k4 + d2) * (INT64)(INT32)(k5 + d3);
        k0 = k4;
        k1 = k5;
        d += 4;
        k += 4;
    } while (--c);
    *((INT64 *)hp) = h1;
    *((INT64 *)hp+1) = h2;
}

/* ---------------------------------------------------------------------- */
#endif
/* ---------------------------------------------------------------------- */

static void hash_full(void *kp, void *dp, void *hp, INT32 dlen)
/* All-in-one, non-incremental equivalent of hash_update(), hash_final()  */
/* the data pointed at by dp must be of length divisible by PAD_BOUNDARY. */
{
    WORD i;
    INT64 sum1,sum2;
    INT64 dtmp[2];
    INT32 *msg,
           *key2;
    const WORD full_l1_iters = dlen / BYTES_PER_L1_ITER;
    const WORD partial_l1_bytes = dlen % BYTES_PER_L1_ITER;
    
    sum1 = sum2 = 0;
    msg = (INT32 *)dp;
    key2 = (INT32 *)((INT8 *)kp + 
           (BYTES_PER_L1_ITER + TOEPLITZ_SHIFTS * BYTES_PER_L1_SHIFT));
      
    for (i = full_l1_iters; i > 0; --i) {
        /* chunk of level 1 */
        dtmp[0] = dtmp[1] = 0;
        hash_aux_HBS_mult(kp, msg, dtmp, BYTES_PER_L1_ITER);

        /* chunk of level 2 */
        sum1 += (INT64)(INT32)(*(key2+0) + (INT32)(dtmp[0] >> 32)) *
                (INT64)(INT32)(*(key2+1) + (INT32)(dtmp[0]));
        #if (SECURITY == 64)
        sum2 += (INT64)(INT32)(*(key2+2) + (INT32)(dtmp[1] >> 32)) *
                (INT64)(INT32)(*(key2+3) + (INT32)(dtmp[1]));
        #endif
        
        msg += (BYTES_PER_L1_ITER/4);
        key2 += 2;
    }

    /* If remaining bytes */
    if (partial_l1_bytes) {
        dtmp[0] = dtmp[1] = 0;;
        hash_aux_PB_mult(kp, msg, dtmp, partial_l1_bytes);
    
        sum1 += (INT64)(INT32)(*(key2+0) + (INT32)(dtmp[0] >> 32)) *
                (INT64)(INT32)(*(key2+1) + (INT32)(dtmp[0]));
        #if (SECURITY == 64)
        sum2 += (INT64)(INT32)(*(key2+2) + (INT32)(dtmp[1] >> 32)) *
                (INT64)(INT32)(*(key2+3) + (INT32)(dtmp[1]));
        #endif
    }
    STORE_INT64_BIG(hp,sum1);
    #if (SECURITY == 64)
    STORE_INT64_BIG((INT64 *)hp+1,sum2);
    #endif
}

/* ---------------------------------------------------------------------- */

static void hash_transform_HBS_mult(hash_ctx *hc, INT8 *buf, INT32 nbytes)
/* Incorporate nbytes of data pointed at by buf into a hash_ctx. This is  */
/* done by repeatedly calling hash_aux_HBS_mult on appropriately parsed   */
/* pieces of memory and then performing an NH has on their outputs.       */ 
{
    WORD i;
    INT64 sum1;
    INT32 *msg,
           *key1,
           *key2;
    WORD full_l1_iters,
         l1_iter_bytes;
  
    #if (SECURITY == 64)
    INT64 sum2 = hc->state.sum2;
    #endif
    sum1 = hc->state.sum1;
    key2 = hc->state.key2;
    msg = (INT32 *)buf;    

    l1_iter_bytes = hc->bytes_hashed % BYTES_PER_L1_ITER;
    if (l1_iter_bytes != 0) {
        WORD remaining = BYTES_PER_L1_ITER - (l1_iter_bytes);
        key1 = (INT32 *)(hc->hash_key + l1_iter_bytes);
        if (remaining > nbytes) {
            hash_aux_HBS_mult(key1, msg, hc->state.dtmp, nbytes);
            nbytes = 0;
        } else {
            hash_aux_HBS_mult(key1, msg, hc->state.dtmp, remaining);
            sum1 += (INT64)(INT32)(*(key2+0) + (INT32)(hc->state.dtmp[0] >> 32)) *
                    (INT64)(INT32)(*(key2+1) + (INT32)(hc->state.dtmp[0]));
            hc->state.dtmp[0] = 0;
            #if (SECURITY == 64)
            sum2 += (INT64)(INT32)(*(key2+2) + (INT32)(hc->state.dtmp[1] >> 32)) *
                    (INT64)(INT32)(*(key2+3) + (INT32)(hc->state.dtmp[1]));
            hc->state.dtmp[1] = 0;
            #endif
            nbytes -= remaining;
            msg += remaining/4;
            key2 += 2;
        }
    }

    full_l1_iters = nbytes / BYTES_PER_L1_ITER;
    for (i = full_l1_iters; i > 0; --i) {
    /* chunk of level 1 */
        hash_aux_HBS_mult(hc->hash_key, msg, 
                                        hc->state.dtmp, BYTES_PER_L1_ITER);

        /* chunk of level 2 */
        sum1 += (INT64)(INT32)(*(key2+0) + (INT32)(hc->state.dtmp[0] >> 32)) *
                (INT64)(INT32)(*(key2+1) + (INT32)(hc->state.dtmp[0]));
        hc->state.dtmp[0] = 0;
        #if (SECURITY == 64)
        sum2 += (INT64)(INT32)(*(key2+2) + (INT32)(hc->state.dtmp[1] >> 32)) *
                (INT64)(INT32)(*(key2+3) + (INT32)(hc->state.dtmp[1]));
        hc->state.dtmp[1] = 0;
        #endif

        msg += (BYTES_PER_L1_ITER/4);
        key2 += 2;
    }

    /* If remaining bytes */
    nbytes %= BYTES_PER_L1_ITER;
    if (nbytes) {
        hash_aux_HBS_mult(hc->hash_key, msg,
                                        hc->state.dtmp, nbytes);
    }
    hc->state.sum1 = sum1;
    #if (SECURITY == 64)
    hc->state.sum2 = sum2;
    #endif
    hc->state.key2 = key2;
}

/* ---------------------------------------------------------------------- */

static void hash_transform_PB_mult(hash_ctx *hc, INT8 *buf, INT32 nbytes)
/* Incorporate nbytes of data pointed at by buf into a hash_ctx. This is  */
/* only called on the final piece of the message which is guaranteed to   */
/* be shorter than HASH_BUF_SIZE bytes.                                   */
{
    INT64 sum1;
    INT32 *msg,
           *key1,
           *key2;
  
    #if (SECURITY == 64)
    INT64 sum2 = hc->state.sum2;
    #endif
    sum1 = hc->state.sum1;
    key2 = hc->state.key2;
    msg = (INT32 *)buf;    

    if (nbytes) {
        key1 = (INT32 *)(hc->hash_key + (hc->bytes_hashed % BYTES_PER_L1_ITER));
        hash_aux_PB_mult(key1, msg, hc->state.dtmp, nbytes);
    }
    sum1 += (INT64)(INT32)(*(key2+0) + (INT32)(hc->state.dtmp[0] >> 32)) *
            (INT64)(INT32)(*(key2+1) + (INT32)(hc->state.dtmp[0]));
    hc->state.dtmp[0] = 0;
    hc->state.sum1 = sum1;
    #if (SECURITY == 64)
    sum2 += (INT64)(INT32)(*(key2+2) + (INT32)(hc->state.dtmp[1] >> 32)) *
            (INT64)(INT32)(*(key2+3) + (INT32)(hc->state.dtmp[1]));
    hc->state.dtmp[1] = 0;
    hc->state.sum2 = sum2;
    #endif
}

/* ---------------------------------------------------------------------- */
/* ----- MMX Universal Hash -------------------------------------------- */
/* ---------------------------------------------------------------------- */

#else

static void hash_aux_32_PB_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by PAD_BOUNDARY (32). 32 bits are written   */
/* at hp.                                                                 */
{
    INT32 h;
    INT32 c = dlen / 32;
    INT16 *k = (INT16 *)kp;
    INT16 *d = (INT16 *)dp;

    h = *(INT32 *)hp;
    do {
        h += (INT32)(INT16)(*(k+0)  + LOAD_INT16_LITTLE(d+0)) * 
             (INT32)(INT16)(*(k+8)  + LOAD_INT16_LITTLE(d+8));
        h += (INT32)(INT16)(*(k+1)  + LOAD_INT16_LITTLE(d+1)) * 
             (INT32)(INT16)(*(k+9)  + LOAD_INT16_LITTLE(d+9));
        h += (INT32)(INT16)(*(k+2)  + LOAD_INT16_LITTLE(d+2)) * 
             (INT32)(INT16)(*(k+10) + LOAD_INT16_LITTLE(d+10));
        h += (INT32)(INT16)(*(k+3)  + LOAD_INT16_LITTLE(d+3)) * 
             (INT32)(INT16)(*(k+11) + LOAD_INT16_LITTLE(d+11));
        h += (INT32)(INT16)(*(k+4)  + LOAD_INT16_LITTLE(d+4)) * 
             (INT32)(INT16)(*(k+12) + LOAD_INT16_LITTLE(d+12));
        h += (INT32)(INT16)(*(k+5)  + LOAD_INT16_LITTLE(d+5)) * 
             (INT32)(INT16)(*(k+13) + LOAD_INT16_LITTLE(d+13));
        h += (INT32)(INT16)(*(k+6)  + LOAD_INT16_LITTLE(d+6)) * 
             (INT32)(INT16)(*(k+14) + LOAD_INT16_LITTLE(d+14));
        h += (INT32)(INT16)(*(k+7)  + LOAD_INT16_LITTLE(d+7)) * 
             (INT32)(INT16)(*(k+15) + LOAD_INT16_LITTLE(d+15));
        d += 16;
        k += 16;
    } while (--c);
    *(INT32 *)hp = h;
}
/* ---------------------------------------------------------------------- */

static void hash_aux_64_PB_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. 64 bits are written at hp by performing two     */
/* passes over the data with the second key being the toeplitz shift of   */
/* the first.                                                             */
{
    hash_aux_32_PB_mult(kp,dp,hp,dlen);
    hash_aux_32_PB_mult((INT8 *)kp+16,dp,(INT8 *)hp+4,dlen);
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_PB_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. 128 bits are written at hp by performing four    */
/* passes over the data with the later keys being the toeplitz shift of   */
/* the first.                                                             */
{
    hash_aux_32_PB_mult(kp,dp,hp,dlen);
    hash_aux_32_PB_mult((INT8 *)kp+16,dp,(INT8 *)hp+4,dlen);
    hash_aux_32_PB_mult((INT8 *)kp+32,dp,(INT8 *)hp+8,dlen);
    hash_aux_32_PB_mult((INT8 *)kp+48,dp,(INT8 *)hp+12,dlen);
}

/* ---------------------------------------------------------------------- */
#if (( ! ANSI_C_ONLY) && __GNUC__ && __i386__)
/* ---------------------------------------------------------------------- */

#define MMX_BLOCK_128(n) \
    "movq "#n"+0(%%eax),%%mm0\n\t" \
    "movq "#n"+16(%%eax),%%mm1\n\t" \
    "movq "#n"+0(%%ebx),%%mm2\n\t" \
    "movq "#n"+16(%%ebx),%%mm3\n\t" \
    "paddw %%mm0,%%mm2\n\t" \
    "paddw %%mm1,%%mm3\n\t" \
    "pmaddwd %%mm3,%%mm2\n\t" \
    "paddd %%mm2,%%mm4\n\t" \
    "psubw %%mm1,%%mm3\n\t"         \
    "movq "#n"+32(%%ebx),%%mm2\n\t" \
    "paddw %%mm0,%%mm3\n\t" \
    "paddw %%mm1,%%mm2\n\t" \
    "pmaddwd %%mm2,%%mm3\n\t" \
    "paddd %%mm3,%%mm5\n\t" \
    "psubw %%mm1,%%mm2\n\t"         \
    "movq "#n"+48(%%ebx),%%mm3\n\t" \
    "paddw %%mm0,%%mm2\n\t" \
    "paddw %%mm1,%%mm3\n\t" \
    "pmaddwd %%mm3,%%mm2\n\t" \
    "paddd %%mm2,%%mm6\n\t" \
    "psubw %%mm1,%%mm3\n\t"         \
    "movq "#n"+64(%%ebx),%%mm2\n\t" \
    "paddw %%mm0,%%mm3\n\t" \
    "paddw %%mm1,%%mm2\n\t" \
    "pmaddwd %%mm2,%%mm3\n\t" \
    "paddd %%mm3,%%mm7\n\t" \
    "movq "#n"+8(%%eax),%%mm0\n\t" \
    "movq "#n"+24(%%eax),%%mm1\n\t" \
    "movq "#n"+8(%%ebx),%%mm2\n\t" \
    "movq "#n"+24(%%ebx),%%mm3\n\t" \
    "paddw %%mm0,%%mm2\n\t" \
    "paddw %%mm1,%%mm3\n\t" \
    "pmaddwd %%mm3,%%mm2\n\t" \
    "paddd %%mm2,%%mm4\n\t" \
    "psubw %%mm1,%%mm3\n\t"         \
    "movq "#n"+40(%%ebx),%%mm2\n\t" \
    "paddw %%mm0,%%mm3\n\t" \
    "paddw %%mm1,%%mm2\n\t" \
    "pmaddwd %%mm2,%%mm3\n\t" \
    "paddd %%mm3,%%mm5\n\t" \
    "psubw %%mm1,%%mm2\n\t"         \
    "movq "#n"+56(%%ebx),%%mm3\n\t" \
    "paddw %%mm0,%%mm2\n\t" \
    "paddw %%mm1,%%mm3\n\t" \
    "pmaddwd %%mm3,%%mm2\n\t" \
    "paddd %%mm2,%%mm6\n\t" \
    "psubw %%mm1,%%mm3\n\t"         \
    "movq "#n"+72(%%ebx),%%mm2\n\t" \
    "paddw %%mm0,%%mm3\n\t" \
    "paddw %%mm1,%%mm2\n\t" \
    "pmaddwd %%mm2,%%mm3\n\t" \
    "paddd %%mm3,%%mm7\n\t"

#define MMX_BLOCK_64(n)                \
    "movq "#n"+0(%%eax),%%mm0\n\t"  \
    "movq "#n"+16(%%eax),%%mm1\n\t" \
    "movq "#n"+0(%%ebx),%%mm2\n\t"  \
    "movq "#n"+16(%%ebx),%%mm3\n\t" \
    "paddw %%mm0,%%mm2\n\t"         \
    "paddw %%mm1,%%mm3\n\t"         \
    "pmaddwd %%mm3,%%mm2\n\t"       \
    "paddd %%mm2,%%mm4\n\t"         \
    "psubw %%mm1,%%mm3\n\t"         \
    "movq "#n"+32(%%ebx),%%mm2\n\t" \
    "paddw %%mm0,%%mm3\n\t"         \
    "paddw %%mm1,%%mm2\n\t"         \
    "pmaddwd %%mm3,%%mm2\n\t"       \
    "paddd %%mm2,%%mm5\n\t"         \
    "movq "#n"+8(%%eax),%%mm0\n\t"  \
    "movq "#n"+24(%%eax),%%mm1\n\t" \
    "movq "#n"+8(%%ebx),%%mm2\n\t"  \
    "movq "#n"+24(%%ebx),%%mm3\n\t" \
    "paddw %%mm0,%%mm2\n\t"         \
    "paddw %%mm1,%%mm3\n\t"         \
    "pmaddwd %%mm3,%%mm2\n\t"       \
    "paddd %%mm2,%%mm4\n\t"         \
    "psubw %%mm1,%%mm3\n\t"         \
    "movq "#n"+40(%%ebx),%%mm2\n\t" \
    "paddw %%mm0,%%mm3\n\t"         \
    "paddw %%mm1,%%mm2\n\t"         \
    "pmaddwd %%mm3,%%mm2\n\t"       \
    "paddd %%mm2,%%mm5\n\t"

#define MMX_BLOCK_32(n)                \
    "movq "#n"+0(%%eax),%%mm0\n\t"  \
    "movq "#n"+16(%%eax),%%mm1\n\t" \
    "movq "#n"+0(%%ebx),%%mm2\n\t"  \
    "movq "#n"+16(%%ebx),%%mm3\n\t" \
    "paddw %%mm0,%%mm2\n\t"         \
    "paddw %%mm1,%%mm3\n\t"         \
    "movq "#n"+8(%%eax),%%mm4\n\t"  \
    "movq "#n"+24(%%eax),%%mm6\n\t" \
    "pmaddwd %%mm3,%%mm2\n\t"       \
    "movq "#n"+8(%%ebx),%%mm5\n\t"  \
    "movq "#n"+24(%%ebx),%%mm3\n\t" \
    "paddd %%mm2,%%mm7\n\t"         \
    "paddw %%mm4,%%mm5\n\t"         \
    "paddw %%mm6,%%mm3\n\t"         \
    "pmaddwd %%mm3,%%mm5\n\t"       \
    "paddd %%mm5,%%mm7\n\t"         

static void hash_aux_32_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 64 bits are written at hp by           */
/* performing two passes over the data with the second key being the      */
/* toeplitz shift of the first.                                           */
{
  INT32 t[2];
  INT32 *p = hp;

  asm volatile (
    "\n\t"
    "pxor %%mm7,%%mm7\n\t"
    ".align 4,0x90\n"
    "1:\t"

    MMX_BLOCK_32(0)
    MMX_BLOCK_32(32)
    
    "addl $64,%%eax\n\t"
    "addl $64,%%ebx\n\t"
    "decl %%edx\n\t"
    "jne 1b\n\t"
    "movq %%mm7,(%%ecx)\n\t"
    "emms"
    : 
    : "a" (dp), "b" (kp), "c" (t), "d" (dlen/64)
    : "eax","ebx","edx","memory");
    p[0] += (t[0] + t[1]);
}

/* ---------------------------------------------------------------------- */

static void hash_aux_64_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 64 bits are written at hp by           */
/* performing two passes over the data with the second key being the      */
/* toeplitz shift of the first.                                           */
{
  INT32 t[4];
  INT32 *p = hp;

  asm volatile (
    "\n\t"
    "pxor %%mm4,%%mm4\n\t"
    "pxor %%mm5,%%mm5\n\t"
    ".align 4,0x90\n"
    "1:\t"

    MMX_BLOCK_64(0)
    MMX_BLOCK_64(32)
    
    "addl $64,%%eax\n\t"
    "addl $64,%%ebx\n\t"
    "decl %%edx\n\t"
    "jne 1b\n\t"
    "movq %%mm4,(%%ecx)\n\t"
    "movq %%mm5,8(%%ecx)\n\t"
    "emms"
    : 
    : "a" (dp), "b" (kp), "c" (t), "d" (dlen/64)
    : "eax","ebx","edx","memory");
    p[0] += (t[0] + t[1]);
    p[1] += (t[2] + t[3]);
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 128 bits are written at hp by          */
/* performing four passes over the data with the later keys being the     */
/* toeplitz shift of the first.                                           */
{
  INT32 t[8];
  INT32 *p = hp;
  
  asm volatile (
    "\n\t"
    "pxor %%mm4,%%mm4\n\t"
    "pxor %%mm5,%%mm5\n\t"
    "pxor %%mm6,%%mm6\n\t"
    "pxor %%mm7,%%mm7\n\t"
    ".align 4,0x90\n"
    "1:\t"

    MMX_BLOCK_128(0)
    MMX_BLOCK_128(32)
    
    "addl $64,%%eax\n\t"
    "addl $64,%%ebx\n\t"
    "decl %%edx\n\t"
    "jne 1b\n\t"
    "movq %%mm4,(%%ecx)\n\t"
    "movq %%mm5,8(%%ecx)\n\t"
    "movq %%mm6,16(%%ecx)\n\t"
    "movq %%mm7,24(%%ecx)\n\t"
    "emms"
    : 
    : "a" (dp), "b" (kp), "c" (t), "d" (dlen/64)
    : "eax","ebx","edx","memory");
    p[0] = p[0] + t[0] + t[1];
    p[1] = p[1] + t[2] + t[3];
    p[2] = p[2] + t[4] + t[5];
    p[3] = p[3] + t[6] + t[7];
}

/* ---------------------------------------------------------------------- */
#elif (( ! ANSI_C_ONLY) && _M_IX86)
/* ---------------------------------------------------------------------- */

#define MMX_BLOCK_128(n) \
    __asm movq mm0,n+0[eax] \
    __asm movq mm1,n+16[eax] \
    __asm movq mm2,n+0[ebx] \
    __asm movq mm3,n+16[ebx] \
    __asm paddw mm2,mm0 \
    __asm paddw mm3,mm1 \
    __asm pmaddwd mm2,mm3 \
    __asm paddd mm4,mm2 \
    __asm psubw mm3,mm1         \
    __asm movq mm2,n+32[ebx] \
    __asm paddw mm3,mm0 \
    __asm paddw mm2,mm1 \
    __asm pmaddwd mm3,mm2 \
    __asm paddd mm5,mm3 \
    __asm psubw mm2,mm1         \
    __asm movq mm3,n+48[ebx] \
    __asm paddw mm2,mm0 \
    __asm paddw mm3,mm1 \
    __asm pmaddwd mm2,mm3 \
    __asm paddd mm6,mm2 \
    __asm psubw mm3,mm1         \
    __asm movq mm2,n+64[ebx] \
    __asm paddw mm3,mm0 \
    __asm paddw mm2,mm1 \
    __asm pmaddwd mm3,mm2 \
    __asm paddd mm7,mm3 \
    __asm movq mm0,n+8[eax] \
    __asm movq mm1,n+24[eax] \
    __asm movq mm2,n+8[ebx] \
    __asm movq mm3,n+24[ebx] \
    __asm paddw mm2,mm0 \
    __asm paddw mm3,mm1 \
    __asm pmaddwd mm2,mm3 \
    __asm paddd mm4,mm2 \
    __asm psubw mm3,mm1         \
    __asm movq mm2,n+40[ebx] \
    __asm paddw mm3,mm0 \
    __asm paddw mm2,mm1 \
    __asm pmaddwd mm3,mm2 \
    __asm paddd mm5,mm3 \
    __asm psubw mm2,mm1         \
    __asm movq mm3,n+56[ebx] \
    __asm paddw mm2,mm0 \
    __asm paddw mm3,mm1 \
    __asm pmaddwd mm2,mm3 \
    __asm paddd mm6,mm2 \
    __asm psubw mm3,mm1         \
    __asm movq mm2,n+72[ebx] \
    __asm paddw mm3,mm0 \
    __asm paddw mm2,mm1 \
    __asm pmaddwd mm3,mm2 \
    __asm paddd mm7,mm3

#define MMX_BLOCK_64(n)                \
    __asm movq mm0,n+0[eax]  \
    __asm movq mm1,n+16[eax] \
    __asm movq mm2,n+0[ebx]  \
    __asm movq mm3,n+16[ebx] \
    __asm paddw mm2,mm0         \
    __asm paddw mm3,mm1         \
    __asm pmaddwd mm2,mm3       \
    __asm paddd mm4,mm2         \
    __asm psubw mm3,mm1         \
    __asm movq mm2,n+32[ebx] \
    __asm paddw mm3,mm0         \
    __asm paddw mm2,mm1         \
    __asm pmaddwd mm2,mm3       \
    __asm paddd mm5,mm2         \
    __asm movq mm0,n+8[eax]  \
    __asm movq mm1,n+24[eax] \
    __asm movq mm2,n+8[ebx]  \
    __asm movq mm3,n+24[ebx] \
    __asm paddw mm2,mm0         \
    __asm paddw mm3,mm1         \
    __asm pmaddwd mm2,mm3       \
    __asm paddd mm4,mm2         \
    __asm psubw mm3,mm1         \
    __asm movq mm2,n+40[ebx] \
    __asm paddw mm3,mm0         \
    __asm paddw mm2,mm1         \
    __asm pmaddwd mm2,mm3       \
    __asm paddd mm5,mm2

#define MMX_BLOCK_32(n)      \
    __asm movq mm0,n+0[ebx]  \
    __asm movq mm1,n+16[ebx] \
    __asm movq mm2,n+0[eax]  \
    __asm movq mm3,n+16[eax] \
    __asm paddw mm2,mm0      \
    __asm paddw mm3,mm1      \
    __asm movq mm4,n+8[ebx]  \
    __asm movq mm6,n+24[ebx] \
    __asm pmaddwd mm2,mm3    \
    __asm movq mm5,n+8[eax]  \
    __asm movq mm3,n+24[eax] \
    __asm paddd mm7,mm2      \
    __asm paddw mm5,mm4      \
    __asm paddw mm3,mm6      \
    __asm pmaddwd mm5,mm3    \
    __asm paddd mm7,mm5         

static void hash_aux_32_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 64 bits are written at hp by           */
/* performing two passes over the data with the second key being the      */
/* toeplitz shift of the first.                                           */
{
  INT32 t[2];
  INT32 *p = hp;
  WORD loop_count = dlen / 64;
  
  __asm mov eax, kp
  __asm mov ebx, dp
  __asm pxor mm7, mm7
  do {
    MMX_BLOCK_32(0)
    MMX_BLOCK_32(32)
    __asm add eax, 64
    __asm add ebx, 64
  } while (--loop_count);
  __asm movq t, mm7
  __asm emms

  p[0] += (t[0] + t[1]);
}


/* ---------------------------------------------------------------------- */

static void hash_aux_64_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 64 bits are written at hp by           */
/* performing two passes over the data with the second key being the      */
/* toeplitz shift of the first.                                           */
{
  INT32 t[4];
  INT32 *p = hp;
  WORD loop_count = dlen / 64;
  
  __asm mov eax, dp
  __asm mov ebx, kp
  __asm pxor mm4, mm4
  __asm pxor mm5, mm5
  do {
    MMX_BLOCK_64(0)
    MMX_BLOCK_64(32)
    __asm add eax, 64
    __asm add ebx, 64
  } while (--loop_count);
  __asm movq t, mm4
  __asm movq t+8, mm5
  __asm emms

  p[0] += (t[0] + t[1]);
  p[1] += (t[2] + t[3]);
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. Previous (partial) hash result is loaded and     */
/* then stored via hp pointer. The length of the data pointed at by dp is */
/* guaranteed to be divisible by HASH_BUF_SIZE (64), which means we can   */
/* optimize by unrolling the loop. 128 bits are written at hp by          */
/* performing four passes over the data with the later keys being the     */
/* toeplitz shift of the first.                                           */
{
  INT32 t[8];
  INT32 *p = hp;
  WORD loop_count = dlen / 64;
  
  __asm mov eax, dp
  __asm mov ebx, kp
  __asm pxor mm4, mm4
  __asm pxor mm5, mm5
  __asm pxor mm6, mm6
  __asm pxor mm7, mm7
  do {
    MMX_BLOCK_128(0)
    MMX_BLOCK_128(32)
    __asm add eax, 64
    __asm add ebx, 64
  } while (--loop_count);
  __asm movq t   , mm4
  __asm movq t+ 8, mm5
  __asm movq t+16, mm6
  __asm movq t+24, mm7
  __asm emms

  p[0] += (t[0] + t[1]);
  p[1] += (t[2] + t[3]);
  p[2] += (t[4] + t[5]);
  p[3] += (t[6] + t[7]);
}

/* ---------------------------------------------------------------------- */
#elif (( ! ANSI_C_ONLY) && __ALTIVEC__ && __VEC__)
/* ---------------------------------------------------------------------- */

/* The following routines are written using the C programming model for   */
/* AltiVec processors as defined by Motorola. AltiVec information is      */
/* available at (http://www.motorola.com/SPS/PowerPC/AltiVec/).           */
/* The routines assume that kp and dp are on divisible by 16-byte         */
/* boundaries and that the host machine is natively big-endian.           */

static void hash_aux_32_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
{
    signed short *key = (signed short *)kp;
    signed short *data = (signed short *)dp;
    INT32 *p = (INT32 *)hp;
    vector signed long h1;
    vector signed short d1, d2, d3, d4;
    vector signed short k1, k2, k3, k4;
    vector unsigned char endian =
             (vector unsigned char)(1,0,3,2,5,4,7,6,9,8,11,10,13,12,15,14);
    signed long r1[4]; 
    int iters;
    
    iters = dlen/64;
    h1 = (vector signed long)(0);
    
    do {
        d1 = vec_ld(0,data);
        d2 = vec_ld(16,data);
        d3 = vec_ld(32,data);
        d4 = vec_ld(48,data);
        d1 = vec_perm(d1,d1,endian);
        d2 = vec_perm(d2,d2,endian);
        d3 = vec_perm(d3,d3,endian);
        d4 = vec_perm(d4,d4,endian);
        k1 = vec_ld(0,key);
        k2 = vec_ld(16,key);
        k3 = vec_ld(32,key);
        k4 = vec_ld(48,key);
        
        h1 = vec_msum(vec_add(d1,k1), vec_add(d2,k2), h1);
        h1 = vec_msum(vec_add(d3,k3), vec_add(d4,k4), h1);
        
        key += 32;
        data += 32;
    } while (--iters);
    
    vec_st(h1, 0, r1);
    p[0] = p[0] + r1[0] + r1[1] + r1[2] + r1[3];
}

/* ---------------------------------------------------------------------- */

static void hash_aux_64_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
{
    signed short *key = (signed short *)kp;
    signed short *data = (signed short *)dp;
    INT32 *p = (INT32 *)hp;
    vector signed long h1, h2;
    vector signed short d1, d2, d3, d4;
    vector signed short k1, k2, k3, k4, k5;
    vector unsigned char endian = 
           (vector unsigned char)(1,0,3,2,5,4,7,6,9,8,11,10,13,12,15,14);
    signed long r1[4], r2[4]; 
    int iters;
    
    iters = dlen/64;
    h1 = (vector signed long)(0);
    h2 = (vector signed long)(0);
    
    k1 = vec_ld(0,key);
    do {
        d1 = vec_ld(0,data);
        d2 = vec_ld(16,data);
        d3 = vec_ld(32,data);
        d4 = vec_ld(48,data);
        d1 = vec_perm(d1,d1,endian);
        d2 = vec_perm(d2,d2,endian);
        d3 = vec_perm(d3,d3,endian);
        d4 = vec_perm(d4,d4,endian);
        k2 = vec_ld(16,key);
        k3 = vec_ld(32,key);
        k4 = vec_ld(48,key);
        k5 = vec_ld(64,key);
        
        h1 = vec_msum(vec_add(d1,k1), vec_add(d2,k2), h1);
        h2 = vec_msum(vec_add(d1,k2), vec_add(d2,k3), h2);
        
        h1 = vec_msum(vec_add(d3,k3), vec_add(d4,k4), h1);
        h2 = vec_msum(vec_add(d3,k4), vec_add(d4,k5), h2);
        
        k1 = k5;
        
        key += 32;
        data += 32;
    } while (--iters);
    
    vec_st(h1, 0, r1);
    vec_st(h2, 0, r2);
    p[0] = p[0] + r1[0] + r1[1] + r1[2] + r1[3];
    p[1] = p[1] + r2[0] + r2[1] + r2[2] + r2[3];
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
{
    signed short *key = (signed short *)kp;
    signed short *data = (signed short *)dp;
    INT32 *p = (INT32 *)hp;
    vector signed long h1, h2, h3, h4;
    vector signed short d1, d2, d3, d4;
    vector signed short k1, k2, k3, k4, k5, k6, k7;
    vector unsigned char endian =
           (vector unsigned char)(1,0,3,2,5,4,7,6,9,8,11,10,13,12,15,14);
    signed long r1[4], r2[4], r3[4], r4[4]; 
    int iters;
    
    iters = dlen/64;
    h1 = (vector signed long)(0);
    h2 = (vector signed long)(0);
    h3 = (vector signed long)(0);
    h4 = (vector signed long)(0);
    
    k1 = vec_ld(0,key);
    k2 = vec_ld(16,key);
    k3 = vec_ld(32,key);
    do {
        d1 = vec_ld(0,data);
        d2 = vec_ld(16,data);
        d3 = vec_ld(32,data);
        d4 = vec_ld(48,data);
        d1 = vec_perm(d1,d1,endian);
        d2 = vec_perm(d2,d2,endian);
        d3 = vec_perm(d3,d3,endian);
        d4 = vec_perm(d4,d4,endian);
        k4 = vec_ld(48,key);
        k5 = vec_ld(64,key);
        k6 = vec_ld(80,key);
        k7 = vec_ld(96,key);
        
        h1 = vec_msum(vec_add(d1,k1), vec_add(d2,k2), h1);
        h2 = vec_msum(vec_add(d1,k2), vec_add(d2,k3), h2);
        h3 = vec_msum(vec_add(d1,k3), vec_add(d2,k4), h3);
        h4 = vec_msum(vec_add(d1,k4), vec_add(d2,k5), h4);
        
        h1 = vec_msum(vec_add(d3,k3), vec_add(d4,k4), h1);
        h2 = vec_msum(vec_add(d3,k4), vec_add(d4,k5), h2);
        h3 = vec_msum(vec_add(d3,k5), vec_add(d4,k6), h3);
        h4 = vec_msum(vec_add(d3,k6), vec_add(d4,k7), h4);
        
        k1 = k5;
        k2 = k6;
        k3 = k7;
        
        key += 32;
        data += 32;
    } while (--iters);
    
    vec_st(h1, 0, r1);
    vec_st(h2, 0, r2);
    vec_st(h3, 0, r3);
    vec_st(h4, 0, r4);
    p[0] = p[0] + r1[0] + r1[1] + r1[2] + r1[3];
    p[1] = p[1] + r2[0] + r2[1] + r2[2] + r2[3];
    p[2] = p[2] + r3[0] + r3[1] + r3[2] + r3[3];
    p[3] = p[3] + r4[0] + r4[1] + r4[2] + r4[3];
}

/* ---------------------------------------------------------------------- */
#else /* ANSI_C_ONLY or non-specialized architecture */
/* ---------------------------------------------------------------------- */

static void hash_aux_32_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. 64 bits are written at hp by performing two     */
/* passes over the data with the second key being the toeplitz shift of   */
/* the first.                                                             */
{
    hash_aux_32_PB_mult(kp,dp,hp,dlen);
}

/* ---------------------------------------------------------------------- */

static void hash_aux_64_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. 64 bits are written at hp by performing two     */
/* passes over the data with the second key being the toeplitz shift of   */
/* the first.                                                             */
{
    hash_aux_32_PB_mult(kp,dp,hp,dlen);
    hash_aux_32_PB_mult((INT8 *)kp+16,dp,(INT8 *)hp+4,dlen);
}

/* ---------------------------------------------------------------------- */

static void hash_aux_128_HBS_mult(void *kp, void *dp, void *hp, INT32 dlen)
/* NH hashing primitive. 128 bits are written at hp by performing four    */
/* passes over the data with the later keys being the toeplitz shift of   */
/* the first.                                                             */
{
    hash_aux_32_PB_mult(kp,dp,hp,dlen);
    hash_aux_32_PB_mult((INT8 *)kp+16,dp,(INT8 *)hp+4,dlen);
    hash_aux_32_PB_mult((INT8 *)kp+32,dp,(INT8 *)hp+8,dlen);
    hash_aux_32_PB_mult((INT8 *)kp+48,dp,(INT8 *)hp+12,dlen);
}

/* ---------------------------------------------------------------------- */
#endif
/* ---------------------------------------------------------------------- */

static void hash_reset(hash_ctx *hc)
/* Reset hash_ctx to ready for hashing of new data                        */
{
    hc->bytes_hashed = 0;
    hc->next_data_empty = 0;
    hc->state.dtmp[0] = 0;
    #if (SECURITY >= 32)
    hc->state.dtmp[1] = 0;
    #endif
    #if (SECURITY == 64)
    hc->state.dtmp[2] = 0;
    hc->state.dtmp[3] = 0;
    #endif
}

/* ---------------------------------------------------------------------- */

static void write_result(hash_ctx *hc, INT8 *result)
/* Method dependent manner of writing hash result to memory.              */
{
    STORE_INT32_BIG(result+ 0,hc->state.dtmp[0]);
    #if (SECURITY >= 32)
    STORE_INT32_BIG(result+ 4,hc->state.dtmp[1]);
    #endif
    #if (SECURITY == 64)
    STORE_INT32_BIG(result+ 8,hc->state.dtmp[2]);
    STORE_INT32_BIG(result+12,hc->state.dtmp[3]);
    #endif
}

/* ---------------------------------------------------------------------- */

static void hash_full(void *kp, void *dp, void *hp, INT32 dlen)
/* All-in-one, non-incremental equivalent of hash_update(), hash_final()  */
/* the data pointed at by dp must be of length divisible by PAD_BOUNDARY. */
{
    INT32 dtmp[4];
    INT8 *msg = (INT8 *)dp;
    INT8 *key = (INT8 *)kp;
    INT32 hash_buf_mult,
           bytes_remaining;
    

    dtmp[0] = dtmp[1] = dtmp[2] = dtmp[3] = 0;
    hash_buf_mult = dlen - (dlen % HASH_BUF_SIZE);
    bytes_remaining = dlen - hash_buf_mult;
    
    hash_aux_HBS_mult(kp, msg, dtmp, hash_buf_mult);
    if (bytes_remaining) {
        key += hash_buf_mult;
        msg += hash_buf_mult;
        hash_aux_PB_mult(kp, msg, dtmp, bytes_remaining);
    }
    STORE_INT32_BIG((INT32 *)hp+0,dtmp[0]);
    #if (SECURITY >= 32)
    STORE_INT32_BIG((INT32 *)hp+1,dtmp[1]);
    #endif
    #if (SECURITY == 64)
    STORE_INT32_BIG((INT32 *)hp+2,dtmp[2]);
    STORE_INT32_BIG((INT32 *)hp+3,dtmp[3]);
    #endif
}

/* ---------------------------------------------------------------------- */

static void hash_transform_HBS_mult(hash_ctx *hc, INT8 *buf, INT32 nbytes)
/* Incorporate nbytes of data pointed at by buf into a hash_ctx. This is  */
/* done by calling hash_aux_HBS_mult on appropriately parsed              */
/* pieces of memory and then performing an NH has on their outputs.       */ 
{
    INT8 *key;

    key = hc->hash_key + hc->bytes_hashed;
    hash_aux_HBS_mult(key, buf, hc->state.dtmp, nbytes);
}

/* ---------------------------------------------------------------------- */

static void hash_transform_PB_mult(hash_ctx *hc, INT8 *buf, INT32 nbytes)
/* Incorporate nbytes of data pointed at by buf into a hash_ctx. This is  */
/* only called on the final piece of the message which is guaranteed to   */
/* be shorter than HASH_BUF_SIZE bytes.                                   */
{
    INT8 *key;
  
    if (nbytes) {
        key = hc->hash_key + hc->bytes_hashed;
        hash_aux_PB_mult(key, buf, hc->state.dtmp, nbytes);
    }
}

/* ---------------------------------------------------------------------- */
#endif
/* ---------------------------------------------------------------------- */

static INT32 num_bytes_hashed(hash_ctx *hc)
/* The UMAC routines need to know how many bytes have been hashed. This   */
/* is calculated by summing the number of bytes incorporated into the     */
/* hash_ctx and the bytes buffered in hc->data.                           */
{
    return (hc->bytes_hashed + hc->next_data_empty);
}

/* ---------------------------------------------------------------------- */

static void endian_convert(void *buf, WORD bpw, INT32 num_bytes)
/* We endian convert the hash_key on big-endian computers to              */
/* compensate for the lack of big-endian memory reads during hashing.     */
{
    WORD iters = num_bytes / bpw;
    if (bpw == 2) {
        INT16 *p = (INT16 *)buf;
        do {
            *p = ((UINT16)*p >> 8) | (*p << 8);
            p++;
        } while (--iters);
    } else if (bpw == 4) {
        INT32 *p = (INT32 *)buf;
        do {
            *p = LOAD_INT32_REVERSED(p);
            p++;
        } while (--iters);
    }
}


/* ---------------------------------------------------------------------- */

static void hash_init(hash_ctx *hc, INT8 key[])
/* Generate hash_key, endian convert and reset to be ready for hashing.   */
{
    prg(key,1,sizeof(hc->hash_key),hc->hash_key);
    #if (! __LITTLE_ENDIAN__)
    endian_convert(hc->hash_key, NH_WORD_SIZE, sizeof(hc->hash_key));
    #endif
    hash_reset(hc);
}

/* ---------------------------------------------------------------------- */

static void hash_update(hash_ctx *hc, INT8 *buf, INT32 nbytes)
/* Incorporate nbytes of data into a hash_ctx, buffer whatever is not an  */
/* even multiple of HASH_BUF_SIZE.                                        */
{
    INT32 i,j;
    
    j = hc->next_data_empty;
    if ((j + nbytes) >= HASH_BUF_SIZE) {
        if (j) {
            i = HASH_BUF_SIZE - j;
            memcpy(hc->data+j, buf, i);
            hash_transform_HBS_mult(hc,hc->data,HASH_BUF_SIZE);
            nbytes -= i;
            buf += i;
            hc->bytes_hashed += HASH_BUF_SIZE;
        }
        if (nbytes >= HASH_BUF_SIZE) {
            i = nbytes - (nbytes % HASH_BUF_SIZE);
            hash_transform_HBS_mult(hc, buf, i);
            nbytes -= i;
            buf += i;
            hc->bytes_hashed += i;
        }
        j = 0;
    }
    memcpy(hc->data + j, buf, nbytes);
    hc->next_data_empty = j + nbytes;
}

/* ---------------------------------------------------------------------- */

static void hash_final(hash_ctx *hc, INT8 *result)
/* If any bytes have been hashed, then pad the data to a multiple of      */
/* PAD_BOUNDARY, incorporate the buffer hc->data into the hash_ctx and    */
/* write the results.                                                     */
{
    INT32 next_pad, num_bytes;
    INT8 *p;

    if (hc->next_data_empty || (hc->bytes_hashed % BYTES_PER_L1_ITER)) {
        num_bytes = hc->next_data_empty;    /* Bytes already in buffer */

        if (num_bytes % PAD_BOUNDARY) {
            p = hc->data + num_bytes;
            next_pad = ((num_bytes + PAD_BOUNDARY) & ~(PAD_BOUNDARY - 1));
            memset(p,0,next_pad - num_bytes);
            num_bytes = next_pad;
        }
        hash_transform_PB_mult(hc, hc->data, num_bytes);
    }

    write_result(hc,result);
    hash_reset(hc);
}

/* ---------------------------------------------------------------------- */

static void hash(hash_ctx *hc, INT8 *buf, INT32 nbytes, INT8 *result)
/* All-in-one hash_update() and hash_final() equivalent. If nbytes is     */
/* divisible by PAD_BOUNDARY, then no padding will be needed of the       */
/* input data and so it can be hashed in place.                           */
{
    if (nbytes % PAD_BOUNDARY) {
        hash_update(hc, buf, nbytes);
        hash_final(hc, result);
    } else {
        hash_full(hc->hash_key, buf, result, nbytes);
    }
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End Universal Hash Section ------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- Begin UMAC Section --------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

/* As with the PRF and hash function, the UMAC interface has both an      */
/* incremental and non-incremental interface. The non-incremental is more */
/* optimaized than the incremental version and should be preferred when   */
/* the incremental interface is not required. */

#if (UMAC_STD_30 || UMAC_STD_60)
#define MIN_HASH_LEN     56  /* Applying the PRF directly on the message  */
#else                        /* is faster when their length is shorter    */
#define MIN_HASH_LEN     33  /* than MIN_HASH_LEN.                        */
#endif

#define HASH_OUT_BUF_LEN 64 /* The hash output is buffered for the PRF   */

typedef struct UMAC_CTX {
    hash_ctx hash;            /* Hash function for message compression    */
    prf_ctx prf0;             /* PRF for hashed output                    */
    prf_ctx prf1;             /* PRF for short unhashed messages          */
    INT8  hash_out_buf[HASH_OUT_BUF_LEN]; /* Output Buffer for hash fxn  */
    INT32 last_block_length; /* Length of last hash-block for annotation */
    INT32 next_hash_buf_empty; /* Bookeeping for hash_out_buf            */
    INT32 prf_update_has_occurred; /* Has prf_update() been called?      */
} UMAC_CTX;

/* ---------------------------------------------------------------------- */

int umac_reset(umac_ctx_t ctx)
/* Reset the PRFs and hash function to begin a new authentication.        */
{
    prf_reset(&ctx->prf0);
    prf_reset(&ctx->prf1);
    hash_reset(&ctx->hash);
    ctx->next_hash_buf_empty = 0;
    ctx->prf_update_has_occurred = 0;
    return (1);
}

/* ---------------------------------------------------------------------- */

static void umac_len_nonce_encode_tag(umac_ctx_t ctx, 
                                      INT8 nonce[8], 
                                      INT8 tag[])
/* Once finished hashing a message, we must append to the hash output the */
/* length of the last hash-block and the nonce, and then pass this final  */
/* bit of data to the prf. The prf output is the MAC tag                  */
{
    INT8 *tmp;
    WORD i;
    
    i = 0;
    while ((i < 7) && (nonce[i] == 0))
        i++;

    if (ctx->next_hash_buf_empty > (sizeof(ctx->hash_out_buf) - 11 + i)) {
        prf_update(&ctx->prf0, ctx->hash_out_buf, ctx->next_hash_buf_empty);
        ctx->next_hash_buf_empty = 0;
        ctx->prf_update_has_occurred = 1;
    }
    tmp = ctx->hash_out_buf+ctx->next_hash_buf_empty;
    STORE_INT32_BIG(tmp, ctx->last_block_length << 19);
    memcpy(tmp+2, nonce+i, 8-i);
    tmp[10-i] = (INT8)(8-i);

    if (ctx->prf_update_has_occurred) {
        prf_update(&ctx->prf0, ctx->hash_out_buf, 
                   ctx->next_hash_buf_empty+11-i);
        prf_final(&ctx->prf0,tag);
    } else {
        prf(&ctx->prf0, ctx->hash_out_buf, 
            ctx->next_hash_buf_empty+11-i,tag);
    }
}

/* ---------------------------------------------------------------------- */

int umac_delete(umac_ctx_t ctx)
/* Deallocate the ctx structure */
{
    char bytes_to_sub;
    
    if (ctx) {
        bytes_to_sub = *((char *)ctx - 1);
        ctx = (umac_ctx_t)((char *)ctx - bytes_to_sub);
        free(ctx);
    }
    return (1);
}

/* ---------------------------------------------------------------------- */

umac_ctx_t umac_new(char key[])
/* Dynamically allocate a umac_ctx struct, initialize variables, 
 * generate subkeys from key.
 */
{
    umac_ctx_t ctx;
    char bytes_to_add;
    
    ctx = (umac_ctx_t)malloc(sizeof(UMAC_CTX)+ALLOC_BOUNDARY);
    if (ctx) {
        bytes_to_add = ALLOC_BOUNDARY - ((int)ctx & (ALLOC_BOUNDARY - 1));
        ctx = (umac_ctx_t)((char *)ctx + bytes_to_add);
        *((char *)ctx - 1) = bytes_to_add;
        memset(ctx, 0, sizeof(UMAC_CTX));
        prf_init(&ctx->prf0,(INT8 *)key,0,0);
        prf_init(&ctx->prf1,(INT8 *)key,0,1);
        hash_init(&ctx->hash, (INT8 *)key);
    }
    return (ctx);
}

/* ---------------------------------------------------------------------- */

int umac_final(umac_ctx_t ctx, char tag[], char nonce[8])
/* Incorporate any pending data, pad, and generate tag */
{
    WORD bytes_hashed = num_bytes_hashed(&ctx->hash);

    if ((ctx->next_hash_buf_empty == 0) &&   /* If hash_out_buf is empty  */
        ( ! ctx->prf_update_has_occurred) && /* and no prf_update() yet   */
        (bytes_hashed < MIN_HASH_LEN))       /* and bytes_hashed is small */
    {                                        /* then prf unhashed message */
        prf(&ctx->prf1, ctx->hash.data, bytes_hashed,(INT8 *)tag);
    } else {
        if (bytes_hashed != 0) {
            INT8 *hash_result = ctx->hash_out_buf+ctx->next_hash_buf_empty;
            ctx->last_block_length = bytes_hashed;
            hash_final(&ctx->hash, hash_result);
            
            ctx->next_hash_buf_empty += HASH_OUTPUT_LEN;

            if (ctx->next_hash_buf_empty == HASH_OUT_BUF_LEN) {
                prf_update(&ctx->prf0, ctx->hash_out_buf, HASH_OUT_BUF_LEN);
                ctx->next_hash_buf_empty = 0;
                ctx->prf_update_has_occurred = 1;
            }
        }

        umac_len_nonce_encode_tag(ctx,(INT8 *)nonce,(INT8 *)tag);
    }
    umac_reset(ctx);
    return (1);
}

/* ---------------------------------------------------------------------- */

int umac_update(umac_ctx_t ctx, char *input, long len)
/* Given len bytes of data, we parse it into HASH_BLOCK_SIZE chunks and   */
/* hash each one, calling the PRF on the hashed output whenever the hash- */
/* output buffer is full.                                                 */
{
    WORD bytes_hashed, bytes_remaining;
    INT8 *hash_result;
    
    bytes_hashed = num_bytes_hashed(&ctx->hash);
    
    if (bytes_hashed + len >= HASH_BLOCK_SIZE) {
    
        /* Calculate where next hash output will be placed */
        hash_result = ctx->hash_out_buf+ctx->next_hash_buf_empty;
        
        /* If some bytes have already been passed to the hash function    */
        /* then we want to pass at most (HASH_BLOCK_SIZE - bytes_hashed)  */
        /* bytes to complete the current hash_block.                      */
        if (bytes_hashed) {
            bytes_remaining = (HASH_BLOCK_SIZE - bytes_hashed);
            hash_update(&ctx->hash, (INT8 *)input, bytes_remaining);
            hash_final(&ctx->hash, hash_result);
            
            ctx->next_hash_buf_empty += HASH_OUTPUT_LEN;
            hash_result += HASH_OUTPUT_LEN;
        
            if (ctx->next_hash_buf_empty == HASH_OUT_BUF_LEN) {
                prf_update(&ctx->prf0, ctx->hash_out_buf, HASH_OUT_BUF_LEN);
                ctx->next_hash_buf_empty = 0;
                hash_result = ctx->hash_out_buf;
                ctx->prf_update_has_occurred = 1;
            }
            len -= bytes_remaining;
            input += bytes_remaining;
        }
        
        /* Hash directly from input stream if enough bytes */
        while (len >= HASH_BLOCK_SIZE) {
            hash(&ctx->hash, (INT8 *)input, HASH_BLOCK_SIZE, hash_result);
            
            ctx->next_hash_buf_empty += HASH_OUTPUT_LEN;
            hash_result += HASH_OUTPUT_LEN;

            if (ctx->next_hash_buf_empty == HASH_OUT_BUF_LEN) {
                prf_update(&ctx->prf0, ctx->hash_out_buf, HASH_OUT_BUF_LEN);
                ctx->next_hash_buf_empty = 0;
                hash_result = ctx->hash_out_buf;
                ctx->prf_update_has_occurred = 1;
            }
            len -= HASH_BLOCK_SIZE;
            input += HASH_BLOCK_SIZE;
        }
        ctx->last_block_length = 0;
    }
    
    /* incrementally hash remaining < HASH_BLOCK_SIZE bytes of input data */
    if (len)
        hash_update(&ctx->hash, (INT8 *)input, len);

    return (1);
}

/* ---------------------------------------------------------------------- */

int umac(umac_ctx_t ctx, char *input, 
         long len, char tag[],
         char nonce[8])
/* All-in-one version simply calls umac_update() and umac_final().        */
{
    if (len < MIN_HASH_LEN) {
        prf(&ctx->prf1, (INT8 *)input, len, (INT8 *)tag);
        umac_reset(ctx);
    } else {
        umac_update(ctx,input,len);
        umac_final(ctx,tag,nonce);
    }
    return (1);
}

/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ----- End UMAC Section ----------------------------------------------- */
/* ---------------------------------------------------------------------- */
/* ---------------------------------------------------------------------- */

#endif

void D2FL::static_initialize(){
}

int D2FL::initialize(ErrorHandler *) {
	timer.initialize(this);
	timer.schedule_now();

#ifdef USE_UMAC
	click_chatter("MAC ALG: UMAC\n");
	uc = umac_new((char *)seckey);
#endif
	return 0;
}


void D2FL::static_cleanup(){}

D2FL::D2FL():timer(this), localaddr("192.168.58.131"){
//	printk("construct the D2FL element");
	click_chatter("construct the D2FL element");
}

D2FL::~D2FL(){}

int D2FL::configure(Vector<String> &conf, ErrorHandler *errh){
	bool verbose = false;
	bool details = false;
	bool asym = false;

	if(cp_va_kparse_remove_keywords(conf, this, errh,
  		"VERBOSE", 0, cpBool, &verbose,
		"DTAILS", 0, cpBool, &details,
		"ASYM", 0, cpBool, &asym,
		cpEnd) < 0)
		return -1;	
	
#ifdef KERNEL_HMAC
	tfm = crypto_alloc_hash("hmac(sha1)", 0, CRYPTO_ALG_ASYNC);
	if(IS_ERR(tfm)){
		printk("failed to load transform for hmac\n");
		return -1;
	}
	desc.tfm = tfm;
	desc.flags = -1;
#endif
	return 0;
}

Packet* D2FL::simple_action(Packet *p){
	const click_ip *ipHead = reinterpret_cast<const click_ip*>(p->data());
	if(ipHead->ip_p != 0x06)
		switch(ipHead->ip_p){
			case 0x02:
				click_chatter("--Receive a sinal packet!\n");
			default:
				return p;
		}
	int sizeIPhead = ipHead->ip_hl << 2;
	const click_tcp *tcpHead = reinterpret_cast<const click_tcp*>(p->data() + sizeIPhead);
	int packetLen = (int)ntohs(ipHead->ip_len);
	unsigned short oldIPchecksum = ntohs(ipHead->ip_sum);
#if DEBUG > 1
	click_chatter("packet length is %i", packetLen);
#endif
	struct in_addr src = ipHead->ip_src;
	struct in_addr dst = ipHead->ip_dst;
	unsigned char *packetEnd = (unsigned char *)p + packetLen;
	unsigned char *originalPacketEnd = packetEnd - EXT_LEN;

	WritablePacket * q;
#if DEBUG > 1
	unsigned short oldhmac= *((unsigned short*)(p->data() + packetLen - 24 + 4));
	click_chatter("The original mac in packet is %x\n", oldhmac);
#endif
	click_ip *ipHead2;
	click_tcp *tcpHead2;
	if(q = p->uniqueify()){

		ipHead2 = (click_ip*)(q->data());
		tcpHead2= (click_tcp*)(q->data() + sizeIPhead);
#if DEBUG > 1
		click_chatter("src addr is %x\n", ipHead2->ip_src.s_addr);
#endif
		ipHead2->ip_sum = 0;
		ipHead2->ip_ttl= 0;
		tcpHead2->th_sum = 0;
		ipHead2->ip_len = htons(packetLen - 24);
	} else {
		click_chatter("packet uniqueify error\n");
		return 0;
	}
	const unsigned char *packetHmac = p->data() + packetLen - EXT_LEN + 4;
#if DEBUG > 1
	click_chatter("going to verify\n");
#endif
	if(verify_packet(q->data(), packetLen - EXT_LEN, packetHmac, seckey)){
#if DEBUG > 0 
		click_chatter("packet hmac eeror, droped\n");
#endif
	}	
		
	//append the new mac of this router
	unsigned int authLen = 0;
	unsigned char *auth = NULL;
	auth = MACwithKey(seckey, 24, q->data(), packetLen - EXT_LEN, &authLen);
	*((unsigned int *)(originalPacketEnd + SEC_TRAILOR)) = localaddr.in_addr().s_addr;
	*((unsigned short*)(originalPacketEnd + SEC_TRAILOR + 4)) = *((unsigned short*)auth);

	return p;
}

void printPacket(const unsigned char * packet, int size)
{
	if(size > 100)
		return;

	for(int i = 0; i < size/4; i++){
		click_chatter("%x ",*((unsigned int*)packet));
		packet += 4;
	}
	click_chatter("\n");
}

int D2FL::verify_packet(const unsigned char *packData, int packLen, const unsigned char *packHmac, const unsigned char* key)
{
	unsigned int authLen = 0;
	unsigned char * auth = NULL;
	 
#if DEBUG > 1
	click_chatter("packet len: %d", packLen);
#endif
	
	auth = MACwithKey(key, 24, packData, packLen, &authLen);
	if( memcmp(packHmac, auth, 2)) return 1;
	return 0;
}

unsigned char *D2FL::MACwithKey(const unsigned char* secKey, int secKeyLen, const unsigned char* plaintext, int plainLen, unsigned int *macLen)
{
#ifdef KERNEL_HMAC
	int ret;
	if((ret = crypto_hash_setkey(tfm, secKey, secKeyLen))){
		printk("setKey fail\n");
		return NULL;
	}
	
	sg_set_buf(&sg, plaintext, plainLen);
	if((ret = crypto_hash_digest(&desc, &sg, plainLen, mac))) {
		printk("digest fail\n");
		return NULL;
	}
	*macLen = 20;
#elif defined(USE_HMAC)
	hmac_sha1_simple((void*)seckey, secKeyLen, (void*)plaintext, plainLen, mac);
#elif defined(USE_UMAC)
	char nonce[8] = {0,1,2,3,4,5,6,7};
#if DEBUG > 1
	char testchar[22] = {1};
	umac(uc, (char *)testchar, 22, (char *)mac, nonce);
	click_chatter("Test mac is %x\n",*((unsigned short*)mac));
#endif
	umac(uc, (char *)plaintext, plainLen, (char *)mac, (char *)plaintext);
#endif
	*macLen = 2;
#if DEBUG > 1
	click_chatter("mac is %x\n",*((unsigned short*)mac));
#endif
	return mac;
}

void D2FL::add_handlers(){
	int i = 0;
}

void D2FL::run_timer(Timer *timer)
{
  WritablePacket *p = Packet::make(sizeof(click_ip) + 4);
  memset(p->data(), '\0', p->length());

  /* for now just pseudo-header fields for UDP checksum */
  click_ip *ipp = reinterpret_cast<click_ip *>(p->data());
  ipp->ip_len = htons(p->length() - sizeof(*ipp));
  ipp->ip_p = 4;
  ipp->ip_src = localaddr.in_addr();
  ipp->ip_dst = IPAddress("192.168.58.132").in_addr();

  /* RIP payload */
  unsigned int *r = (unsigned int *) (ipp + 1);
  r[0] = htonl(goodPktNum++);

  /* the remaining IP header fields */
  ipp->ip_len = htons(p->length());
  ipp->ip_hl = sizeof(click_ip) >> 2;
  ipp->ip_v = 4;
  ipp->ip_ttl = 200;
  ipp->ip_sum = click_in_cksum((unsigned char *) ipp, sizeof(*ipp));

  p->set_ip_header(ipp, sizeof(click_ip));

  output(0).push(p);

  this->timer.schedule_after_msec(5 * 1000);


}
CLICK_ENDDECLS
EXPORT_ELEMENT(D2FL)
