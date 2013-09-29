#ifndef CLICK_D2FL_HH
#define CLICK_D2FL_HH
#include <click/element.hh>
#include <click/atomic.hh>

#include <click/timer.hh>

#define EXT_LEN 24
#define DEBUG 1
#define SEC_TRAILOR 12
//#define USE_HMAC
//#define KERNEL_HMAC
#define USE_UMAC

#ifdef USE_UMAC
#include "umac.h"
#endif

CLICK_DECLS

class D2FL : public Element {
public:
	D2FL();
	~D2FL();
	
	static void static_initialize();
	static void static_cleanup();
	
	int initialize(ErrorHandler *);
	const char *class_name() const { return "D2FL"; }
	const char *port_count() const { return "1/1-3"; }
	const char *processing() const { return "a/ah"; }
	const char *flags() const { return "A"; }

	int configure(Vector<String> &, ErrorHandler *);
	void add_handlers();
	
	Packet *simple_action(Packet *);
	
	int verify_packet(const unsigned char *packData, int packLen, const unsigned char* packHmac, const unsigned char* key);
	
	unsigned char *MACwithKey(const unsigned char *secKey, int secKeyLen, const unsigned char* plaintext, int plainLen, unsigned int *macLen);

	void run_timer(Timer *timer);
private:
	IPAddress localaddr;
	
	static const unsigned char seckey[24];

	unsigned char mac[20];

	Timer timer;
	
	int goodPktNum;
	umac_ctx_t uc;
#ifdef KERNEL_HMAC
	struct crypto_hash *tfm;
	struct hash_desc desc;
	struct scatterlist sg;
#endif
};

CLICK_ENDDECLS
#endif
