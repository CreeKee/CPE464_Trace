# Example makefile for CPE464 program 1
#
# 

CC = g++
CFLAGS = -g -Wall -pedantic
SOURCES = EthernetHead.o IPHead.o checksum.o ARPHead.o TCPHeader.o

LOCAL = ./

FILE = UDPfile.pcap

INFILE = $(LOCAL)inputs/$(FILE)
CHECKFILE = $(LOCAL)outputs/$(FILE).out

.PHONY: $(SOURCES) clean

all:  trace

trace: $(SOURCES)
	$(CC) $(CFLAGS) -o trace trace.cpp $(SOURCES) -lpcap 

test: trace
	rm -f testout.txt
	./trace $(INFILE) >> testout.txt
	diff -w $(CHECKFILE) testout.txt

EthernetHead.o: EthernetHead.cpp
	$(CC) $(CFLAGS) -c EthernetHead.cpp

IPHead.o: IPHead.cpp
	$(CC) $(CFLAGS) -c IPHead.cpp

ARPHead.o: ARPHead.cpp
	$(CC) $(CFLAGS) -c ARPHead.cpp

TCPHeader.o: TCPHeader.cpp
	$(CC) $(CFLAGS) -c TCPHeader.cpp

checksum.o: checksum.c
	$(CC) $(CFLAGS) -c checksum.c
clean:
	rm -f trace
	rm -f *.o
