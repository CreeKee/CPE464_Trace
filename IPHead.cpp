#include "IPHead.hpp"


IPHead::IPHead(const u_char* data, uint32_t* offset){

    verslen = *data;
    data += VERSIONLENGTH;
    printf("%d\n",verslen);

    tos = *(data);
    data += TOSLENGTH;

    length = ntohs(*data);
    data += LENGTHLENGTH;

    ident = ntohs(*data);
    data += IDENTLENGTH;

    flag = ntohs(*data);
    data += FLAGLENGTH;

    ttl = *(data);
    data += TTLLENGTH;

    protocol = *(data);
    data += PROTOCOLLENGTH;

    chksum = ntohs(*(data));
    checked = (chksum == in_cksum((unsigned short*)data, length));
    data += CKSUMLENGTH;

    sourceIP.s_addr = *data;
    data += IPLENGTH;

    destIP.s_addr = *data;
    data += IPLENGTH;

    if(verslen&LOWERMASK == 5){
        options  = *data;
    }

    *offset += (verslen&LOWERMASK)*BYTEWIDTH;
    
}