all:
	gcc -O3 -mmmx -msse -msse2 simpletun.c packet.c crypto.c umac.c rijndael-alg-fst.c util.c -o tun

clean:
	rm *.o tun
