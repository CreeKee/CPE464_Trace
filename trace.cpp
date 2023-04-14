#ifndef __USE_MISC
#define __USE_MISC
#endif // __USE_MISC

#include "EthernetHead.hpp"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "IPHead.hpp"
#include "ARPHead.hpp"

void processEthernetHead(const u_char* data, uint32_t* offset);
void processIPHead(const u_char* data, uint32_t* offset);
void processARPHead(const u_char* data, uint32_t* offset);
void processICMP(const u_char* data, uint32_t* offset);

int main(){

    int res;
    int packetNum = 0;
    char fileName[] = "/Users/admin/SethStuff/CPE464_Trace/inputs/PingTest.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];    

    struct pcap_pkthdr* pktHeader;
    const u_char* data;
    uint32_t offset = 0;

    pcap_t* packet = pcap_open_offline(fileName, errbuf);
    if(!packet){
        printf("yodel\n"); //TODO
    }


    while((res = pcap_next_ex(packet, &pktHeader, &data)) >=0){ //error check
        packetNum++;
        offset = 0;

        processEthernetHead(data, &offset);
        
        putchar('\n');
        printf("Packet number: %d Frame Len: %d\n", packetNum, pktHeader->len);
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
                processIPHead(data, offset);
                break;
            
            case ARPTYPE:
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

            case(ICMPNUM):
                processICMP(data, offset);
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