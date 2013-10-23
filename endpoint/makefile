INC=
LIB=

CC=gcc
CC_FLAG=-Wall -pg -g -O3 -mmmx -msse -msse3 -maes

PRG=tagger
OBJ=tagger.o packet.o crypto.o umac-sse2.o cbcmac.o rijndael-alg-fst.o util.o

$(PRG):$(OBJ)
	$(CC) $(INC) $(LIB) -o $@ $(OBJ)

%.o: %.c
	$(CC) $(CC_FLAG) $(INC) -c $< -o $@

.PHONY:clean
clean:
	@echo "cleaning .o and compiled files"
	rm -f $(OBJ) $(PRG)
