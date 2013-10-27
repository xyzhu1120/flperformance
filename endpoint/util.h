#ifndef _UTIL_H
#define _UTIL_H

#define max(a,b) ((a)>(b) ? (a):(b))
#define min(a,b) ((a)<(b) ? (a):(b))

/* ------------------------------------------         
   output a single byte in %al hex as two 8-bit characters 
   (courtesy of Jon McCune's Flicker code) 
   ------------------------------------------ */ 
void dumpByte(unsigned char b);

/* Print a series of bytes in a reasonable format */ 
void dumpBytes(unsigned char* buffer, int len) ;

#endif
