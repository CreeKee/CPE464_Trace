#include "IPHead.hpp"


IPHead::IPHead(const u_char* data, uint32_t* offset){

    struct in_addr carrier;

    verslen = *data;
    checked = (0 == in_cksum((unsigned short*)data, (verslen&LOWERMASK)*BYTEWIDTH/2));
    data += VERSIONLENGTH;

    tos = *(data);
    data += TOSLENGTH;

    length = ntohs(*(uint16_t*)data);
    data += LENGTHLENGTH;

    ident = ntohs(*(uint16_t*)data);
    data += IDENTLENGTH;

    flag = ntohs(*(uint16_t*)data);
    data += FLAGLENGTH;

    ttl = *(data);
    data += TTLLENGTH;

    protocol = *(data);
    data += PROTOCOLLENGTH;

    chksum = *((uint16_t*)data);
    data += CKSUMLENGTH;

    carrier.s_addr = *(uint32_t*)data;
    memcpy(sourceIP, inet_ntoa(carrier), IPSIZE);
    data += IPLENGTH;

    carrier.s_addr = *(uint32_t*)data;
    memcpy(destIP, inet_ntoa(carrier), IPSIZE);
    data += IPLENGTH;

    data += IPLENGTH;
    if((verslen&LOWERMASK) == 5){
        options  = *data;
    }

    *offset += (verslen&LOWERMASK)*BYTEWIDTH/2;
    
}

void IPHead::display(){
    printf("\tType: IP\n");
    printf("\t\tHeader Len: %d (bytes)\n",(verslen&LOWERMASK)*BYTEWIDTH/2 );
    printf("\t\tTOS 0x%x\n",tos);
    printf("\t\tTTL: %d\n",ttl);
    printf("\t\tIP PDU Len: %d (bytes)\n",length);

    switch(getProtocol()){

        case(ICMPNUM):
            printf("\t\tProtocol: ICMP\n");
            break;

        default:
            printf("\t\tProtocol: Unkown\n");
            break;
    }

    printf("\t\tChecksum: %s (0x%x)\n",(checked == true ? "Correct" : "Incorrect"), chksum);
    printf("\t\tSender IP: %s\n", sourceIP);
    printf("\t\tDest IP: %s\n\n",destIP);
}