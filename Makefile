# Example makefile for CPE464 program 1
#
# 
.PHONY: test
.PHONY: EthernetHead.o
CC = g++
CFLAGS = -g -Wall 
#CFLAGS = -g

all:  trace

test: EthernetHead.o IPHead.o checksum.o
	$(CC) $(CFLAGS) -o test trace.cpp EthernetHead.o IPHead.o checksum.o -lpcap 

EthernetHead.o: EthernetHead.cpp
	$(CC) -c EthernetHead.cpp

IPHead.o: IPHead.cpp
	$(CC) -c IPHead.cpp

checksum.o: checksum.c
	$(CC) -c checksum.c
clean:
	rm -f trace
