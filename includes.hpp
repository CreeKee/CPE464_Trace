#include <string.h>
#include <arpa/inet.h>
#include <iostream>
#include <netinet/if_ether.h>
#include "checksum.h"

#define BYTEWIDTH 8
#define LOWERMASK 0x0F

//Ethernet #defines
#define MACSIZE 6
#define TYPESIZE 2

//IP #defines
#define VERSIONLENGTH 1
#define TOSLENGTH 1
#define LENGTHLENGTH 2
#define IDENTLENGTH 2
#define FLAGLENGTH 2
#define TTLLENGTH 1
#define PROTOCOLLENGTH 1
#define CKSUMLENGTH 2
#define IPLENGTH 4
