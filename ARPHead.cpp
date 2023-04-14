#include "ARPHead.hpp"


ARPHead::ARPHead(const u_char* data){

    struct in_addr IPcarrier;
    struct ether_addr MACcarrier;

    memset(srcMac, '\0', FORMATMACSIZE);
    memset(dstMac, '\0', FORMATMACSIZE);

    data += ARPOPOFFSET;

    opcode = ntohs(*(uint16_t*)data);
    
    data += OPCODELENGTH;

    memcpy(MACcarrier.ether_addr_octet, (data), MACSIZE);
    memcpy(srcMac, ether_ntoa((&MACcarrier)), strlen(ether_ntoa((&MACcarrier))));
    data += MACSIZE;

    IPcarrier.s_addr = *(uint32_t*)data;
    memcpy(sourceIP, inet_ntoa(IPcarrier), IPSIZE);
    data += IPLENGTH;

    memcpy(MACcarrier.ether_addr_octet, data, MACSIZE);
    memcpy(dstMac, ether_ntoa((&MACcarrier)), strlen(ether_ntoa((&MACcarrier))));
    data += MACSIZE;

    IPcarrier.s_addr = *(uint32_t*)data;
    memcpy(destIP, inet_ntoa(IPcarrier), IPSIZE);

    
}

void ARPHead::display(){
        printf("\tType: ARP\n");

    switch(opcode){

        case ARPOP_REQUEST:
            printf("\t\tOpcode: Request\n");
            break;

        case ARPOP_REPLY:
            printf("\t\tOpcode: Reply\n");
            break;

        default:
            printf("\t\tOpcode: Unkown\n");
            break;
    }
    printf("\t\tSender MAC: %s\n", srcMac);
    printf("\t\tSender IP: %s\n", sourceIP);
    printf("\t\tTarget MAC: %s\n", dstMac);
    printf("\t\tTarget IP: %s\n", destIP);
    
}