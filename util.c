#include "util.h"
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

/* ------------------------------------------         
   output a single byte in %al hex as two 8-bit characters 
   (courtesy of Jon McCune's Flicker code) 
   ------------------------------------------ */ 
void dumpByte(unsigned char b) { 
    char c = '0'; 
 
    if((b >> 4) <= 9) 
        c = (b >> 4) + '0'; 
    else 
        c = (b >> 4) - 0xa + 'a'; 
 
    printf("%c",c); 
     
    if((b & 0xf) <= 9) 
        c = (b & 0xf) + '0'; 
    else 
        c = (b & 0xf) - 0xa + 'a'; 
     
    printf("%c",c);     
} 
 
/* Print a series of bytes in a reasonable format */ 
void dumpBytes(unsigned char* buffer, int len) { 
  int i; 
 
  if (!buffer) { 
    printf("Empty\n"); 
    return; 
  } 
 
  for (i = 0; i < len; i++) { 
    dumpByte(buffer[i]); 
    if (i > 0 && !((i+1) % 16)) { 
      printf("\n"); 
    } 
  } 
  printf("\n\n"); 
} 

