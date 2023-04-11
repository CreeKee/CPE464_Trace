#ifndef __USE_MISC
#define __USE_MISC
#endif // __USE_MISC

#include "EthernetHead.hpp"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "IPHead.hpp"
#include "ARPHead.hpp"

void processIPHead(const u_char* data, uint32_t* offset);
void processARPHead(const u_char* data, uint32_t* offset);
void processICMP(const u_char* data, uint32_t* offset);

int main(){

    EthernetHead* Ehead;

    int res;

    struct ether_addr srcAdd;
    struct ether_addr dstAdd;
    uint16_t type;

    char* fileName = "/Users/admin/SethStuff/CPE464_Trace/inputs/PingTest.pcap";
    char errbuf[PCAP_ERRBUF_SIZE];    

    struct pcap_pkthdr* pktHeader;
    const u_char* data;
    uint32_t offset = 0;

    pcap_t* packet = pcap_open_offline(fileName, errbuf);
    if(!packet){
        printf("yodel\n"); //TODO
    }


    while((res = pcap_next_ex(packet, &pktHeader, &data)) >=0){ //error check
        
        offset = 0;

        Ehead = new EthernetHead(data, &offset);

        printf("%s\n%s\n%x\n", 
            Ehead->getDest(), 
            Ehead->getSrc(), 
            Ehead->getType());

        switch(Ehead->getType()){

            case IPTYPE:
                processIPHead(data, &offset);
                break;
            
            case ARPTYPE:
                processARPHead(data, &offset);
                break;

            default:
                break;
        }
        
        putchar('\n');
        putchar('\n');
        free(Ehead);
    }
    
    return 0;
}

void processIPHead(const u_char* data, uint32_t* offset){
    IPHead Ihead(data+*offset, offset);
    printf("IP\n%d (bytes)\n0x%x\n%d\n%d\n%d\n%d 0x%x\n%s\n%s",
        Ihead.getHeadLen()*BYTEWIDTH/2, 
        Ihead.getTos(),
        Ihead.getTtl(),
        Ihead.getLength(),
        Ihead.getProtocol(),
        Ihead.getConf(),
        Ihead.getCksum(),
        Ihead.getSourceIP(),
        Ihead.getDestIP());

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
    return;
}

void processICMP(const u_char* data, uint32_t* offset){

    printf("\nICMP Header\n");
    switch(*(data+*offset+CODEOFFSET)){
        case ECHO:
            printf("Type: Request\n");
            break;

        case ECHOREPLY:
            printf("Type: Reply\n");
            break;

        default:
            printf("unkown ICMP type\n");
            break;
    }

    return;
}