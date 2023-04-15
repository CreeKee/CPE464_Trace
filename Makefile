# Example makefile for CPE464 program 1
#
# 
.PHONY: test
.PHONY: EthernetHead.o
CC = g++
CFLAGS = -g -Wall 
SOURCES = EthernetHead.o IPHead.o checksum.o ARPHead.o TCPHeader.o
#CFLAGS = -g

all:  trace

test: $(SOURCES)
	$(CC) $(CFLAGS) -o test trace.cpp $(SOURCES) -lpcap 
	./test

EthernetHead.o: EthernetHead.cpp
	$(CC) -c EthernetHead.cpp

IPHead.o: IPHead.cpp
	$(CC) -c IPHead.cpp

ARPhead.o: ARPhead.cpp
	$(CC) -c ARPHead.cpp

TCPHeader.o: TCPHeader.cpp
	$(CC) -c TCPHeader.cpp

checksum.o: checksum.c
	$(CC) -c checksum.c
clean:
	rm -f trace
	rm -f test
