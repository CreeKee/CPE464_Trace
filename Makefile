# Example makefile for CPE464 program 1
#
# 
.PHONY: test
.PHONY: EthernetHead.o
CC = g++
CFLAGS = -g -Wall 
SOURCES = EthernetHead.o IPHead.o checksum.o ARPHead.o
#CFLAGS = -g

all:  trace

test: $(SOURCES)
	$(CC) $(CFLAGS) -o test trace.cpp $(SOURCES) -lpcap 

EthernetHead.o: EthernetHead.cpp
	$(CC) -c EthernetHead.cpp

IPHead.o: IPHead.cpp
	$(CC) -c IPHead.cpp

ARPhead.o: ARPhead.cpp
	$(CC) -c ARPHead.cpp

checksum.o: checksum.c
	$(CC) -c checksum.c
clean:
	rm -f trace
	rm -f test
