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
/*
	TCP Header
		Source Port: : 1675
		Dest Port: : 22
		Sequence Number: 120760710
		ACK Number: 3289360763
		ACK Flag: Yes
		SYN Flag: No
		RST Flag: No
		FIN Flag: No
		Window Size: 16560
		Checksum: Correct (0xab2)
*/
void TCPHead::display(){
    printf("\tTCP Header\n");
    printf("\t\tSource Port: : %u\n", srcPort);
    printf("\t\tDest Port: : %u\n", dstPort);
    printf("\t\tSequence Number: %u\n", sequenceNum);
    printf("\t\tACK Number: %u\n", ackNum);
    printf("\t\tTODO flags\n");

    printf("\t\tACK Flag: %s\n",flags & ACKMASK ? "Yes":"No");
    printf("\t\tSYN Flag: %s\n",flags & SYNMASK ? "Yes":"No");
    printf("\t\tRST Flag: %s\n",flags & RSTMASK ? "Yes":"No");
    printf("\t\tFIN Flag: %s\n",flags & FINMASK ? "Yes":"No");

    printf("\t\tWindow Size: %u\n", windowSize);
    printf("\t\tChecksum: %s (0x%x)", (conf == true ?"Correct":"Incorrect"), checksum);
}


