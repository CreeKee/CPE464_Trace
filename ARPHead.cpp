#include "ARPHead.hpp"

/*
ARPHead constructor
*/
ARPHead::ARPHead(const u_char* data){

    struct in_addr IPcarrier;
    struct ether_addr MACcarrier;

    //clear mac adresses
    memset(srcMac, '\0', FORMATMACSIZE);
    memset(dstMac, '\0', FORMATMACSIZE);

    //jump to important data
    data += ARPOPOFFSET;

    //save opcode
    opcode = ntohs(*(uint16_t*)data);
    data += OPCODELENGTH;

    //save source MAC address
    memcpy(MACcarrier.ether_addr_octet, (data), MACSIZE);
    memcpy(srcMac, ether_ntoa((&MACcarrier)), strlen(ether_ntoa((&MACcarrier))));
    data += MACSIZE;

    //save source IP address
    IPcarrier.s_addr = *(uint32_t*)data;
    memcpy(sourceIP, inet_ntoa(IPcarrier), IPSIZE);
    data += IPLENGTH;

    //save destination MAC adress
    memcpy(MACcarrier.ether_addr_octet, data, MACSIZE);
    memcpy(dstMac, ether_ntoa((&MACcarrier)), strlen(ether_ntoa((&MACcarrier))));
    data += MACSIZE;

    //save destination IP address
    IPcarrier.s_addr = *(uint32_t*)data;
    memcpy(destIP, inet_ntoa(IPcarrier), IPSIZE);

    return;
    
}

/*
display function to print ARP header information
*/
void ARPHead::display(){
    printf("\tARP header\n");

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
    printf("\t\tTarget IP: %s\n\n", destIP);
    
}