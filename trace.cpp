#include "EthernetHead.hpp"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "IPHead.hpp"
#include "ARPHead.hpp"
#include "TCPHeader.hpp"

void processEthernetHead(const u_char* data, uint32_t* offset);
void processIPHead(const u_char* data, uint32_t* offset);
void processARPHead(const u_char* data, uint32_t* offset);
void processICMP(const u_char* data, uint32_t* offset);
void processTCPHead(const u_char* data, uint32_t* offset, IPHead Ihead);
bool psuedoSum(const u_char* data, IPHead Ihead);

int main(){

    int res;
    int packetNum = 1;
    char fileName[] = "/Users/admin/SethStuff/CPE464_Trace/inputs/smallTCP.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];    

    struct pcap_pkthdr* pktHeader;
    const u_char* data;
    uint32_t offset = 0;

    pcap_t* packet = pcap_open_offline(fileName, errbuf);
    if(!packet){
        printf("ERROR: unable to open file\n"); //TODO
    }


    while((res = pcap_next_ex(packet, &pktHeader, &data)) >=0){ //error check

        printf("Packet number: %d Frame Len: %d\n\n", packetNum, pktHeader->len);

        packetNum++;
        offset = 0;

        processEthernetHead(data, &offset);
        
        putchar('\n');
    }
    return 0;
}

void processEthernetHead(const u_char* data, uint32_t* offset){

        EthernetHead Ehead = EthernetHead(data, offset);

        printf("\tEthernet Header:\n");
        printf("\t\tDest MAC: %s\n", Ehead.getDest());
        printf("\t\tSource MAC: %s\n\n", Ehead.getSrc());

        switch(Ehead.getType()){

            case IPTYPE:
                printf("\tType: IP\n");
                processIPHead(data, offset);
                break;
            
            case ARPTYPE:
                printf("\tType: ARP\n");
                processARPHead(data, offset);
                break;

            default:
                break;
        }

}

void processIPHead(const u_char* data, uint32_t* offset){

    IPHead Ihead(data+*offset, offset);
    Ihead.display();

        switch(Ihead.getProtocol()){

            case(IPPROTO_ICMP):
                processICMP(data, offset);
                break;

            case(IPPROTO_TCP):
                processTCPHead(data, offset, Ihead);
                break;

            default:
                break;
        }

        return;
}

void processARPHead(const u_char* data, uint32_t* offset){

    ARPHead Ahead(data+*offset);
    Ahead.display();

    return;
}

void processICMP(const u_char* data, uint32_t* offset){

    printf("\tICMP Header\n");
    switch(*(data+*offset+CODEOFFSET)){
        case ECHO:
            printf("\t\tType: Request\n");
            break;

        case ECHOREPLY:
            printf("\t\tType: Reply\n");
            break;

        default:
            printf("\t\tUnkown ICMP type\n");
            break;
    }

    return;
}

void processTCPHead(const u_char* data, uint32_t* offset,IPHead Ihead){

    TCPHead Thead(data+*offset, psuedoSum(data+*offset, Ihead));
    Thead.display();
}

bool psuedoSum(const u_char* data, IPHead Ihead){

    uint32_t IPpayload = (Ihead.getLength()-(Ihead.getHeadLen()*BYTEWIDTH/2));
    uint8_t* pseudoHeader = new uint8_t[PSEUDOLENGTH+IPpayload];
    
    memcpy(pseudoHeader, Ihead.getPseudo(), PSEUDOLENGTH);
    memcpy(pseudoHeader+PSEUDOLENGTH, data, IPpayload);

    free(pseudoHeader);

    return in_cksum((unsigned short*)pseudoHeader, IPpayload+PSEUDOLENGTH) == 0;

}











