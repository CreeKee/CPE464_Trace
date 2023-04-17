#include "IPHead.hpp"

/*
IPHead constructor
*/
IPHead::IPHead(const u_char* data, uint32_t* offset){

    struct in_addr carrier;

    //get version and length
    verslen = *data;

    //verify checksum
    checked = (0 == in_cksum((unsigned short*)data, (verslen&LOWERMASK)*BYTEWIDTH/2));
    data += VERSIONLENGTH;

    //get TOS
    tos = *(data);
    data += TOSLENGTH;

    //get total length
    length = ntohs(*(uint16_t*)data);
    data += LENGTHLENGTH;

    //get indetification number
    ident = ntohs(*(uint16_t*)data);
    data += IDENTLENGTH;

    //get flags
    flag = ntohs(*(uint16_t*)data);
    data += FLAGLENGTH;

    //get TTL
    ttl = *(data);
    data += TTLLENGTH;

    //get protocol
    protocol = *(data);
    data += PROTOCOLLENGTH;

    //get checksum
    chksum = *((uint16_t*)data);
    data += CKSUMLENGTH;

    //store source IP in IP header and pseudo header
    memcpy(pseudo, data, IPLENGTH);
    carrier.s_addr = *(uint32_t*)data;
    memcpy(sourceIP, inet_ntoa(carrier), IPSIZE);
    data += IPLENGTH;

    //store destination IP in IP header and pseudo header
    memcpy(pseudo+IPLENGTH, data, IPLENGTH);
    carrier.s_addr = *(uint32_t*)data;
    memcpy(destIP, inet_ntoa(carrier), IPSIZE);
    data += IPLENGTH;

    if((verslen&LOWERMASK) == 5){
        options  = *data;
    }

    //clear protocol field in pseudo header
    memset(pseudo+2*IPLENGTH, 0, 1);

    //copy protocol to pseudo header
    pseudo[2*IPLENGTH+1] = protocol;

    //store IP payload length in pseudo header
    *(uint16_t*)(pseudo+2*IPLENGTH+2) = htons((uint16_t)(length - (verslen&LOWERMASK)*BYTEWIDTH/2));

    //update offset
    *offset += (verslen&LOWERMASK)*BYTEWIDTH/2;
    
    return;
}

/*
display function to print IP header information
*/
void IPHead::display(){
    printf("\tIP Header\n");
    printf("\t\tHeader Len: %d (bytes)\n",(verslen&LOWERMASK)*BYTEWIDTH/2 );
    printf("\t\tTOS: 0x%x\n",tos);
    printf("\t\tTTL: %d\n",ttl);
    printf("\t\tIP PDU Len: %d (bytes)\n",length);

    //select protocol
    switch(getProtocol()){

        case(IPPROTO_ICMP):
            printf("\t\tProtocol: ICMP\n");
            break;

        case(IPPROTO_TCP):
            printf("\t\tProtocol: TCP\n");
            break;

        case(IPPROTO_UDP):
            printf("\t\tProtocol: UDP\n");
            break;

        default:
            printf("\t\tProtocol: Unknown\n");
            break;
    }

    printf("\t\tChecksum: %s (0x%x)\n",(checked == true ? "Correct" : "Incorrect"), chksum);
    printf("\t\tSender IP: %s\n", sourceIP);
    printf("\t\tDest IP: %s\n",destIP);

    return;
}
