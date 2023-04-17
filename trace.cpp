#include "EthernetHead.hpp"
#include "includes.hpp"
#include "IPHead.hpp"
#include "ARPHead.hpp"
#include "TCPHeader.hpp"

void processEthernetHead(const u_char* data, uint32_t* offset);
void processIPHead(const u_char* data, uint32_t* offset);
void processARPHead(const u_char* data, uint32_t* offset);
void processICMP(const u_char* data);
void processTCPHead(const u_char* data, uint32_t* offset, IPHead Ihead);
void processUDP(const u_char* data);
bool pseudoSum(const u_char* data, IPHead Ihead);

int main(int argc, char* argv[]){

    int res;
    int packetNum = 1;
    char errbuf[PCAP_ERRBUF_SIZE];    

    struct pcap_pkthdr* pktHeader;
    const u_char* data;
    uint32_t offset = 0;

    //open packet folder
    pcap_t* packet = pcap_open_offline(argv[1], errbuf);
    if(!packet){
        perror("ERROR: unable to open file\n");
        exit(-1);
    }

    //process packets
    while((res = pcap_next_ex(packet, &pktHeader, &data)) >=0 ){

        printf("\nPacket number: %d  Frame Len: %d\n\n", packetNum, pktHeader->len);

        //increment packet number
        packetNum++;

        //reset data offset
        offset = 0;

        //process packet, starting with the ethernet header
        processEthernetHead(data, &offset);
        
    }

    return 0;
}

/*
processEthernetHead takes a pointer to the start of a packet which
starts with an ethernet header and processes that header, prints it
and processes any subsequent headers
*/
void processEthernetHead(const u_char* data, uint32_t* offset){

    //read in ethernet header
    EthernetHead Ehead = EthernetHead(data, offset);

    //display ethernet header
    Ehead.display();

    //select next header type
    switch(Ehead.getType()){

        case IPTYPE:
            printf("\t\tType: IP\n\n");
            processIPHead(data, offset);
            break;
        
        case ARPTYPE:
            printf("\t\tType: ARP\n\n");
            processARPHead(data, offset);
            break;

        default:
            break;
    }

}

/*
processIPHead takes a pointer and offset whcih points to the start 
of a IP header in a packet, prints it, and processes any subsequent
headers.
*/
void processIPHead(const u_char* data, uint32_t* offset){

    //read IP header
    IPHead Ihead(data+*offset, offset);

    //display IP header
    Ihead.display();

    //select next header
    switch(Ihead.getProtocol()){

        case(IPPROTO_ICMP):
            processICMP(data+*offset);
            break;

        case(IPPROTO_TCP):
            processTCPHead(data, offset, Ihead);
            break;

        case(IPPROTO_UDP):
            processUDP(data+*offset);
            break;

        default:
            break;
    }

    return;
}

/*
processARPHead takes a pointer and offset which points to the start 
of a ARP header in a packet and prints its contents
*/
void processARPHead(const u_char* data, uint32_t* offset){

    //read in ARP header
    ARPHead Ahead(data+*offset);

    //print ARP header
    Ahead.display();

    return;
}

/*
processTCPHead takes a pointer and offset which points to the start 
of a TCP header in a packet and prints its contents
*/
void processTCPHead(const u_char* data, uint32_t* offset,IPHead Ihead){

    //read in TCP header
    TCPHead Thead(data+*offset, pseudoSum(data+*offset, Ihead));

    //print TCP header
    Thead.display();

    return;
}

/*
processICMP takes a pointer to the start 
of a ICMP header in a packet and prints its contents.

NOTE: because so little is needed from ICMP headers, a seperate class
was deemed unescessary.
*/
void processICMP(const u_char* data){

    printf("\t\nICMP Header\n");

    //select type
    switch(*data){
        case ICMPREQUEST:
            printf("\t\tType: Request\n");
            break;

        case ICMPREPLY:
            printf("\t\tType: Reply\n");
            break;

        default:
            printf("\t\tType: %d\n", *(data+CODEOFFSET)-1);
            break;
    }

    return;
}

/*
processUDP takes a pointer to the start 
of a UDP header in a packet and prints its contents.

NOTE: because so little is needed from UDP headers, a seperate class
was deemed unescessary.
*/
void processUDP(const u_char* data){

    //display info
    printf("\n\tUDP Header\n");
    printf("\t\tSource Port: : %d\n", ntohs(*(uint16_t*)(data)));
    printf("\t\tDest Port: : %d\n", ntohs(*(uint16_t*)(data+PORTLENGTH)));

}

/*
pseudoSum takes a pointer to the start of a TCP header, and an IP header
that has already been created. Then returns true or false based on whether
the TCP checksum is valid, including pseudo header
*/
bool pseudoSum(const u_char* data, IPHead Ihead){

    bool retval;
    
    //calculate number of bits for summation
    uint32_t IPpayload = (Ihead.getLength()-(Ihead.getHeadLen()*BYTEWIDTH/2));

    //create header
    uint8_t* pseudoHeader = new uint8_t[PSEUDOLENGTH+IPpayload];
    
    //copy pseudo header from IP header
    memcpy(pseudoHeader, Ihead.getPseudo(), PSEUDOLENGTH);

    //store TCP header and payload
    memcpy(pseudoHeader+PSEUDOLENGTH, data, IPpayload);
 
    //calculate and verify checksum
    retval = in_cksum((unsigned short*)pseudoHeader, IPpayload+PSEUDOLENGTH) == 0;
    free(pseudoHeader);

    return retval;

}


