#include "TCPHeader.hpp"

TCPHead::TCPHead(const u_char* data, bool checked){

    srcPort = ntohs(*(uint16_t*)data);
    data += PORTLENGTH;

    dstPort = ntohs(*(uint16_t*)data);
    data += PORTLENGTH;

    sequenceNum = ntohl(*(uint32_t*)data);
    data += SEQNUMLENGTH;

    ackNum = ntohl(*(uint32_t*)data);
    data += ACKNUMLENGTH;

    flags = ntohs(*(uint16_t*)data);
    data += FLAGLENGTH;

    windowSize = ntohs(*(uint16_t*)data);
    data += WINDOWLENTH; //TODO

    checksum = ntohs(*(uint16_t*)data);

    conf = checked;
}

void TCPHead::display(){
    printf("\n\tTCP Header\n");
    
    

    switch(srcPort){
        
        case HTTP_PORT:
            printf("\t\tSource Port:  HTTP\n");
            break;

        default:
            printf("\t\tSource Port: : %u\n", srcPort);
            break;
    }

    switch(dstPort){
        
        case HTTP_PORT:
            printf("\t\tDest Port:  HTTP\n");
            break;

        default:
        printf("\t\tDest Port: : %u\n", dstPort);
            break;
    }

    printf("\t\tSequence Number: %u\n", sequenceNum);

    if((flags & ACKMASK) == 0 || ackNum == 0){
        printf("\t\tACK Number: <not valid>\n");
    }
    else{
        printf("\t\tACK Number: %u\n", ackNum);
    }

    printf("\t\tACK Flag: %s\n",flags & ACKMASK ? "Yes":"No");
    printf("\t\tSYN Flag: %s\n",flags & SYNMASK ? "Yes":"No");
    printf("\t\tRST Flag: %s\n",flags & RSTMASK ? "Yes":"No");
    printf("\t\tFIN Flag: %s\n",flags & FINMASK ? "Yes":"No");

    printf("\t\tWindow Size: %u\n", windowSize);
    printf("\t\tChecksum: %s (0x%x)\n", (conf == true ?"Correct":"Incorrect"), checksum);
}


