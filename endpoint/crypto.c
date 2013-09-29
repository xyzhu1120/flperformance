#include <string.h> /* for memset() and memcpy() */

#include  "crypto.h"

#ifdef USE_UMAC
#include  "umac.h"
umac_ctx_t uctx;
char fakedata[32]="";
int init = 0;
#endif

#ifdef USE_VMAC
#include  "vmac.h"
vmac_ctx_t vctx;
#endif

int key_setup_crt=0;

#ifdef USE_HMAC
/* HMAC Code is adapted from PolarSSL library */

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

SHA_State states[2];

static void SHA_Init(SHA_State * s);
static void SHA_Bytes(SHA_State * s, void *p, int len);
static void SHA_Final(SHA_State * s, unsigned char *output);
//static void SHA_Simple(void *p, int len, unsigned char *output);

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
/*
static void SHA_Simple(void *p, int len, unsigned char *output)
{
	SHA_State s;

	SHA_Init(&s);
	SHA_Bytes(&s, p, len);
	SHA_Final(&s, output);
}
*/
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
	SHA_State newstates[2];
	unsigned char intermediate[20];

	if (key_setup_crt < KEY_SETUP_RATE)
		sha1_key_internal(newstates, (unsigned char *)key, keylen);

	//dumpBytes3("states", (unsigned char *)&states, 2*sizeof(SHA_State));
	SHA_Bytes(&states[0], data, datalen);
	SHA_Final(&states[0], intermediate);
	//dumpBytes3("\nintermediate", intermediate, 20);

	SHA_Bytes(&states[1], intermediate, 20);
	SHA_Final(&states[1], output);

	if (++key_setup_crt == 100)
		key_setup_crt = 0;
}

/**************************  End HMAC Code *************************/
#endif

extern unsigned char keyPool[300];


/* Negociate HMAC key with on-path machines
 * FIXME: just a simulation now */
extern void initKeyPool()
{
	int i;

	memset(keyPool, 1, 300);

	/* init HMAC context */
#ifdef USE_HMAC
	sha1_key_internal(states, keyPool, HMAC_KEY_LEN);
#endif

#ifdef USE_UMAC
	uctx=umac_new(keyPool);
	for(i=0;i<32;i++)
	  fakedata[i] = i+10;
#endif

#ifdef USE_VMAC
	vmac_set_key(keyPool, &vctx);
#endif
}

/* Returns a HMAC (currently HMAC with SHA-1) of the provided plaintext 
 * Updates hmacLen with the length of the MAC */
extern void MACwithKey(const unsigned char* secKey, int secKeyLen, const unsigned char* plaintext, int plainLen, unsigned char * hmac) 
{
#ifdef USE_HMAC
	hmac_sha1_simple((void *)secKey, secKeyLen, (void *)plaintext, plainLen, hmac);
#endif
	//HMAC(EVP_sha1(),secKey, secKeyLen, plaintext, plainLen, mac, macLen);
#ifdef USE_UMAC
#if 0
	umac_ctx_t ctx;
	if (key_setup_crt < KEY_SETUP_RATE)
		ctx=umac_new(secKey);

	plainLen &= ~0x1F;
#endif
	if(!init){
		uctx = umac_new(secKey);
		init = 1;
	}
	if(plainLen != 0){
	  umac(uctx, plaintext, plainLen, hmac, plaintext);
	}
	else {
	  umac(uctx, fakedata, 32, hmac, fakedata);
	}

#if 0
	if (key_setup_crt < KEY_SETUP_RATE)
		umac_delete(ctx);
	if (++key_setup_crt == 100)
		key_setup_crt = 0;
#endif
#endif

#ifdef USE_VMAC
	vmac_ctx_t ctx;
	if (key_setup_crt < KEY_SETUP_RATE)
		vmac_set_key(secKey, &ctx);
	vmac(plaintext,plainLen,plaintext,hmac,&vctx);
	if (++key_setup_crt == 100)
		key_setup_crt = 0;
#endif

}


