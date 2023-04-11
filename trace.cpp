#ifndef __USE_MISC
#define __USE_MISC
#endif // __USE_MISC



#include "EthernetHead.hpp"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "IPHead.hpp"

void packetHandler(
    u_char *args,
    const struct pcap_pkthdr *header,
    const u_char *packet
){

    return;

}

int main(){

    EthernetHead* Ehead;
    IPHead* Ihead;

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
        printf("yodel\n");
    }


    while((res = pcap_next_ex(packet, &pktHeader, &data)) >=0){ //error check
        
        offset = 0;

        Ehead = new EthernetHead(data, &offset);

        printf("%s\n%s\n%x\n", 
            Ehead->getSrc(), 
            Ehead->getDest(), 
            Ehead->getType());

        switch(Ehead->getType()){
            case 2048:

                //Ihead = new IPHead(data+offset, &offset);
                //printf("%d\n",Ihead->getHeadLen());
                break;
            
            default:
                break;
        }
        
        
        putchar('\n');
        putchar('\n');
        //free(Ehead);
        //free(Ihead);
    }
    
    return 0;
}