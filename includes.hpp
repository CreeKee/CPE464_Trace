#include <string.h>
#include <arpa/inet.h>
#include <iostream>
#include <netinet/if_ether.h>
#include <stdio.h>
#include "checksum.h"

#define BYTEWIDTH 8
#define FIELDSIZE 8
#define LOWERMASK 0x0F

#define IPTYPE 0x0800
#define ARPTYPE 0x0806
#define ICMPNUM 1
#define ECHO 0
#define ECHOREPLY 8
#define CODEOFFSET 1

//Ethernet #defines
#define MACSIZE 6
#define TYPESIZE 2
#define FORMATMACSIZE MACSIZE*3

//IP #defines
#define CHECKMESSAGE 10
#define VERSIONLENGTH 1
#define TOSLENGTH 1
#define LENGTHLENGTH 2
#define IDENTLENGTH 2
#define FLAGLENGTH 2
#define TTLLENGTH 1
#define PROTOCOLLENGTH 1
#define CKSUMLENGTH 2
#define IPLENGTH 4
#define IPSIZE 16

//ARP defines
#define OPCODELENGTH 2
#define ARPHWLENGTH 2
#define ARPSKIP 4
#define ARPOPOFFSET 6
#define ARPMACLENGTH 8
#define ARPFIELD 24

//TCP defines
#define PSEUDOLENGTH 12
#define PORTLENGTH 2
#define SEQNUMLENGTH 4
#define ACKNUMLENGTH 4
#define WINDOWLENTH 2
#define ACKMASK 0x10
#define SYNMASK 0x02
#define RSTMASK 0x04
#define FINMASK 0x01
#define HTTP_PORT 80
