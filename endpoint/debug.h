#ifndef DEBUG_H
#define DEBUG_H

#define DEBUG 2

#ifdef DEBUG
#define DEBUGMSG(level, str, ...) \
do{if(level <= DEBUG) printf(str,## __VA_ARGS__);} while(0)
#else
#define DEBUGMSG(level, str, ...)
#endif

#endif
