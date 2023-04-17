#include "EthernetHead.hpp"
/*
EthernetHead constructor
*/
EthernetHead::EthernetHead(const u_char* data, uint32_t* offset){

    struct ether_addr carrier;

    //clear mac addresses
    memset(srcMac, '\0', FORMATMACSIZE);
    memset(dstMac, '\0', FORMATMACSIZE);

    //save destination MAC address
    memcpy(carrier.ether_addr_octet, data, MACSIZE);
    memcpy(dstMac, ether_ntoa((&carrier)), strlen(ether_ntoa((&carrier))));
    data += MACSIZE;

    //save source MAC address
    memcpy(carrier.ether_addr_octet, (data), MACSIZE);
    memcpy(srcMac, ether_ntoa((&carrier)), strlen(ether_ntoa((&carrier))));
    data += MACSIZE;

    //save type
    type = ntohs(*((uint16_t*)data));
    *offset += 2*MACSIZE+TYPESIZE;

    return;
}

/*
display function to print Ethernet header information
*/
void EthernetHead::display(){

    //display header info
    printf("\tEthernet Header\n");
    printf("\t\tDest MAC: %s\n", dstMac);
    printf("\t\tSource MAC: %s\n", srcMac);
}



