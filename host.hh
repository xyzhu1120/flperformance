#ifndef _HOST_H
#define _HOST_H

struct host {
	unsigned int ip_addr;
	unsigned char mac_addr[EHTER_ADDR_LEN];
}

#endif
