/*********  Definition of Program Behavior  *********/

/* HMAC options */
//#define  USE_HMAC
#define  USE_UMAC
//#define  USE_VMAC

/* path length  */
#define  PATH_LEN 1

/* Key setup options (%) */
/* How many percetages of packets needs to do key setup */
#define  KEY_SETUP_RATE 0

/* Micro benchmark to test latency */
#define  Micro
#ifdef Micro
#define  MAX_PATH_LEN 8
#define  PACKET_NUM 50000

#define  PACKET_LEN_INTERVAL 100
#define  MIN_PACKET_LEN 100
#define  MAX_PACKET_LEN 1500
#endif

/* Enable time measurement */
#define  TIME

/* Enable debug output */
//#define  DEBUG 2

/* Enable this to send out extended packets or verify extended packet , if commented, send out or pass the original packets */
#define  SEND_EXTEND

/* Enable this to compute the extension but not actually add it to the packets. The goal is to first test performance only, without getting into trouble with TCP checksum etc*/
//#define FAKE
