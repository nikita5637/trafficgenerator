AV_CC="  CC"
CC=gcc
CFLAGS=-g -O0 -std=gnu99
CLINKFLAGS=-lpthread

all:
	$(CC) $(CFLAGS) $(CLINKFLAGS) main.c
