# Example makefile for CPE464 program 1
#
# 

CC = g++
CFLAGS = -g -Wall 
SOURCES = EthernetHead.o IPHead.o checksum.o ARPHead.o TCPHeader.o

PATH = /Users/admin/SethStuff/CPE464_Trace/

FILE = UDPfile.pcap

INFILE = $(PATH)inputs/$(FILE)
CHECKFILE = $(PATH)outputs/$(FILE).out
#CFLAGS = -g

.PHONY: $(SOURCES) clean

all:  trace

test: $(SOURCES)
	$(CC) $(CFLAGS) -o test trace.cpp $(SOURCES) -lpcap 
	rm testout.txt
	./test $(INFILE) >> testout.txt
	diff -w $(CHECKFILE) testout.txt

EthernetHead.o: EthernetHead.cpp
	$(CC) -c EthernetHead.cpp

IPHead.o: IPHead.cpp
	$(CC) -c IPHead.cpp

ARPHead.o: ARPHead.cpp
	$(CC) -c ARPHead.cpp

TCPHeader.o: TCPHeader.cpp
	$(CC) -c TCPHeader.cpp

checksum.o: checksum.c
	$(CC) -c checksum.c
clean:
	rm -f trace
	rm -f test
