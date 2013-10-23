/**************************************************************************
 * simpletun.c                                                            *
 *                                                                        *
 * A simplistic, simple-minded, naive tunnelling program using tun/tap    *
 * interfaces and TCP. DO NOT USE THIS PROGRAM FOR SERIOUS PURPOSES.      *
 *                                                                        *
 * You have been warned.                                                  *
 *                                                                        *
 * (C) 2010 Davide Brini.                                                 *
 *                                                                        *
 * DISCLAIMER AND WARNING: this is all work in progress. The code is      *
 * ugly, the algorithms are naive, error checking and input validation    *
 * are very basic, and of course there can be bugs. If that's not enough, *
 * the program has not been thoroughly tested, so it might even fail at   *
 * the few simple things it should be supposed to do right.               *
 * Needless to say, I take no responsibility whatsoever for what the      *
 * program might do. The program has been written mostly for learning     *
 * purposes, and can be used in the hope that is useful, but everything   *
 * is to be taken "as is" and without any kind of warranty, implicit or   *
 * explicit. See the file LICENSE for further details.                    *
 *************************************************************************/ 

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>
#include "packet.h"
#include<signal.h>

#include "debug.h"
#ifdef DEBUG
#include<execinfo.h>
#endif
/* buffer for reading from tun/tap interface, must be >= 1500 */
#define BUFSIZE 2000   
#define CLIENT 0
#define SERVER 1
#define PORT 55555

#define UP_LIMIT 10

int debug;
char *progname;

#ifdef DEBUG
void debug_backtrace(int dunno)
{
	#define SIZE 256
	void* array[SIZE];
	int size,i = 0;
	char **strings;
	
	if(dunno == SIGSEGV){
		fprintf(stderr, "\r\nSegmentation faul\r\n");
		size = backtrace(array,SIZE);
		fprintf(stderr, "\r\nBacktrace (%d deep):\r\n",size);
		strings = backtrace_symbols(array,size);
		for(;i < size; i++){
			fprintf(stderr, "===%d:%s\n",i, strings[i]);
		}
		free(strings);
		exit(-1);
	}
}
#endif
void handler_init(int num)
{
	if(num == SIGINT){
		printf("CTRL C to exit\n");
		exit(0);
	}
}
/**************************************************************************
 * tun_alloc: allocates or reconnects to a tun/tap device. The caller     *
 *            must reserve enough space in *dev.                          *
 **************************************************************************/


char local_mac_addr[] = {0x00,0xff,0xec,0xbb,0x1d,0xe3};
char local_ip_addr[] = "192.168.81.129";
char gate_mac_addr[] = {0x00,0x0c,0x29,0xa1,0x6c,0xbc};
char twohopnei_ip_addr[] = "192.168.81.132";

int tun_alloc(char *dev, int flags) {

  struct ifreq ifr;
  int fd, err;
  char *clonedev = "/dev/net/tun";

  if( (fd = open(clonedev , O_RDWR)) < 0 ) {
    perror("Opening /dev/net/tun");
    return fd;
  }

  memset(&ifr, 0, sizeof(ifr));

  ifr.ifr_flags = flags;

  if (*dev) {
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
  }

  if( (err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0 ) {
    perror("ioctl(TUNSETIFF)");
    close(fd);
    return err;
  }

  strcpy(dev, ifr.ifr_name);

  return fd;
}

/**************************************************************************
 * cread: read routine that checks for errors and exits if an error is    *
 *        returned.                                                       *
 **************************************************************************/
int cread(int fd, char *buf, int n){
  
  int nread;

  if((nread=read(fd, buf, n)) < 0){
    perror("Reading data");
    exit(1);
  }
  return nread;
}

/**************************************************************************
 * cwrite: write routine that checks for errors and exits if an error is  *
 *         returned.                                                      *
 **************************************************************************/
int cwrite(int fd, char *buf, int n){
  
  int nwrite;

  if((nwrite=write(fd, buf, n)) < 0){
    perror("Writing data");
    exit(1);
  }
  return nwrite;
}

/**************************************************************************
 * read_n: ensures we read exactly n bytes, and puts them into "buf".     *
 *         (unless EOF, of course)                                        *
 **************************************************************************/
int read_n(int fd, char *buf, int n) {

  int nread, left = n;

  while(left > 0) {
    if ((nread = cread(fd, buf, left)) == 0){
      return 0 ;      
    }else {
      left -= nread;
      buf += nread;
    }
  }
  return n;  
}

/**************************************************************************
 * do_debug: prints debugging stuff (doh!)                                *
 **************************************************************************/
void do_debug(char *msg, ...){
  
  va_list argp;
  
  //if(debug) {
	//va_start(argp, msg);
	//vfprintf(stderr, msg, argp);
	//va_end(argp);
  //}
}

/**************************************************************************
 * my_err: prints custom error messages on stderr.                        *
 **************************************************************************/
void my_err(char *msg, ...) {

  va_list argp;
  
  va_start(argp, msg);
  vfprintf(stderr, msg, argp);
  va_end(argp);
}

/**************************************************************************
 * usage: prints usage and exits.                                         *
 **************************************************************************/
void usage(void) {
  fprintf(stderr, "Usage:\n");
  fprintf(stderr, "%s -i <ifacename> [-s|-c <serverIP>] [-p <port>] [-u|-a] [-d]\n", progname);
  fprintf(stderr, "%s -h\n", progname);
  fprintf(stderr, "\n");
  fprintf(stderr, "-i <ifacename>: Name of interface to use (mandatory)\n");
  fprintf(stderr, "-s|-c <serverIP>: run in server mode (-s), or specify server address (-c <serverIP>) (mandatory)\n");
  fprintf(stderr, "-p <port>: port to listen on (if run in server mode) or to connect to (in client mode), default 55555\n");
  fprintf(stderr, "-u|-a: use TUN (-u, default) or TAP (-a)\n");
  fprintf(stderr, "-d: outputs debug information while running\n");
  fprintf(stderr, "-h: prints this help text\n");
  exit(1);
}
  extern unsigned int send_counter;

int main(int argc, char *argv[]) {
#ifdef DEBUG
  signal(SIGSEGV,debug_backtrace);
#endif
  signal(SIGINT,handler_init);
  printf("begin!\n");
  int tap_fd, tap_fd1, option;
  int dummy = 0;
  int flags = IFF_TUN;
  char if_name0[IFNAMSIZ] = "tap0";
  char if_name1[IFNAMSIZ] = "tap1";
  int maxfd;
  uint16_t nread, nwrite, plength;
  char buffer[BUFSIZE];
  struct sockaddr_in local, remote;
  char remote_ip[16] = "";            /* dotted quad IP string */
  unsigned short int port = PORT;
  int sock_fd, net_fd, optval = 1;
  socklen_t remotelen;
  int cliserv = -1;    /* must be specified on cmd line */
  unsigned long int tap2net = 0, net2tap = 0;

  struct in_addr addr;
  struct host twohopneis[10];
  inet_aton(twohopnei_ip_addr,&addr);
  twohopneis[0].ip_addr = addr.s_addr;
  memcpy(twohopneis[0].mac_addr,gate_mac_addr, ETHER_ADDR_LEN); 

  struct host localhost;
  inet_aton(local_ip_addr,&addr);
  localhost.ip_addr = addr.s_addr;
  memcpy(localhost.mac_addr, local_mac_addr, ETHER_ADDR_LEN);

  progname = argv[0];
  
  /* Check command line options */
  while((option = getopt(argc, argv, "i:sc:p:uahd")) > 0) {
    switch(option) {
      case 'd':
	printf("Enter dummy mode\n");
        dummy = 1;
        break;
      case 'h':
        usage();
        break;
      case 'i':
        strncpy(if_name0,optarg, IFNAMSIZ-1);
        break;
      case 's':
        cliserv = SERVER;
        break;
      case 'c':
        cliserv = CLIENT;
        strncpy(remote_ip,optarg,15);
        break;
      case 'p':
        port = atoi(optarg);
        break;
      case 'u':
        flags = IFF_TUN;
        break;
      case 'a':
        flags = IFF_TAP;
        break;
      default:
        my_err("Unknown option %c\n", option);
        usage();
    }
  }

  argv += optind;
  argc -= optind;

  if(argc > 0) {
    my_err("Too many options!\n");
    usage();
  }

  if(*if_name0 == '\0') {
    my_err("Must specify interface name!\n");
    usage();
  } else if(cliserv < 0) {
    my_err("Must specify client or server mode!\n");
    usage();
  } else if((cliserv == CLIENT)&&(*remote_ip == '\0')) {
    my_err("Must specify server address!\n");
    usage();
  }
	printf("allocate tap device!\n");
  /* initialize tun/tap interface */
  if ( (tap_fd = tun_alloc(if_name0, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun/tap interface %s!\n", if_name0);
    exit(1);
  }
  
   if ( (tap_fd1 = tun_alloc(if_name1, flags | IFF_NO_PI)) < 0 ) {
    my_err("Error connecting to tun1/tap1 interface %s!\n", if_name1);
    exit(1);
  }
  printf("allocate tap device success!\n");

  //do_debug("Successfully connected to interface %s\n", if_name0);
  
  /* use select() to handle two descriptors at once */
  maxfd = (tap_fd > tap_fd1)?tap_fd:tap_fd1;
  while(1) {
    int ret;
    fd_set rd_set;

    FD_ZERO(&rd_set);
    FD_SET(tap_fd, &rd_set); FD_SET(tap_fd1, &rd_set);
    ret = select(maxfd + 1, &rd_set, NULL, NULL, NULL);
    if (ret < 0 && errno == EINTR){
	  do_debug("ret error");
      continue;
    }

    if (ret < 0) {
      perror("select()");
      exit(1);
    }
    if(FD_ISSET(tap_fd, &rd_set)) {
      /* data from tun/tap: just read it and write it to the network */
      
      DEBUGMSG(2,"\n--Send a packet--\n");
      nread = cread(tap_fd, buffer, BUFSIZE);

      //append the trailer
      if(!dummy){
        if(isIP((unsigned char*)buffer) && isTCP((unsigned char*)buffer)){
          ++send_counter;
          if(send_counter >= UP_LIMIT){
            const int len = 14 + sizeof(struct ip) + 4;
	    unsigned char signal[14 + sizeof(struct ip) + 4] = {0};
	    ConstructSignal(signal, &(twohopneis[0]), &localhost);	
            DEBUGMSG(1,"Epoch end and send a signal\n");
            nwrite = write(tap_fd1, signal, len);
            send_counter = 0;
	  }
          int newLen = extendPacket(TCP, (unsigned char*)buffer);
          nread = newLen;
        }
      }

      DEBUGMSG(2,"route a packet(len: %i) to tap1\n", nread);
      nwrite = write(tap_fd1, buffer, nread);
      DEBUGMSG(2,"Written %d bytes to the network\n", nwrite);
    }
	
    if(FD_ISSET(tap_fd1, &rd_set)) {
      /* data from tun/tap: just read it and write it to the network */

      nread = cread(tap_fd1, buffer, BUFSIZE);

      DEBUGMSG(2,"\n--Receive a packet--\n");
      /* write length + packet */
      plength = htons(nread);
        if(!dummy){
	    if(isEpochEnd((unsigned char*)buffer)){
		DEBUGMSG(1,"Receive a Epoch end signal\n");
		const int len = 14 + sizeof(struct ip) + 40;
	    unsigned char echobuffer [14 + sizeof(struct ip) + 4] = {0};
		ConstructSignal(echobuffer, (unsigned char*)buffer);	
		nwrite = write(tap_fd1, echobuffer, len);
	    continue;
	  }
	  if(isIP((unsigned char*)buffer) && isTCP((unsigned char*)buffer)){
       	    int newLen = 0;
            verifyPacket(TCP, (unsigned char*)buffer, &newLen);
            nread = newLen;
	  }
	  DEBUGMSG(2,"packet len: %i\n", nread);
       }
      nwrite = write(tap_fd, buffer, nread);
      
      do_debug("TAP2NET %lu: Written %d bytes to the network\n", tap2net, nwrite);
    }

    //if(FD_ISSET(net_fd, &rd_set)) {
	if(0) {
      /* data from the network: read it, and write it to the tun/tap interface. 
       * We need to read the length first, and then the packet */

      /* Read length */      
      nread = read_n(net_fd, (char *)&plength, sizeof(plength));
      if(nread == 0) {
        /* ctrl-c at the other end */
        break;
      }

      net2tap++;

      /* read packet */
      nread = read_n(net_fd, buffer, ntohs(plength));
      do_debug("NET2TAP %lu: Read %d bytes from the network\n", net2tap, nread);

      /* now buffer[] contains a full packet or frame, write it into the tun/tap interface */ 
      nwrite = cwrite(tap_fd, buffer, nread);
      do_debug("NET2TAP %lu: Written %d bytes to the tap interface\n", net2tap, nwrite);
    }
  }
  
  return(0);
}
