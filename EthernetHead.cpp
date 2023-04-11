#include "EthernetHead.hpp"

EthernetHead::EthernetHead(const u_char* data, uint32_t* offset){

    struct ether_addr carrier;

    memcpy(carrier.ether_addr_octet, data, MACSIZE);
    memcpy(dstMac, ether_ntoa((&carrier)), strlen(ether_ntoa((&carrier))));

    memcpy(carrier.ether_addr_octet, (data+MACSIZE), MACSIZE);
    memcpy(srcMac, ether_ntoa((&carrier)), strlen(ether_ntoa((&carrier))));

    type = ntohs(*((uint16_t*)data+2*MACSIZE));
    *offset += 2*MACSIZE+TYPESIZE;

}




