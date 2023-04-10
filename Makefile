# Example makefile for CPE464 program 1
#
# 

CC = gcc
CFLAGS = -g -Wall 
#CFLAGS = -g

all:  trace

test:
	$(CC) $(CFLAGS) -o trace trace.cpp -lpcap 

trace: trace.cpp
	$(CC) $(CFLAGS) -o trace trace.c checksum.c  -lpcap 

clean:
	rm -f trace
