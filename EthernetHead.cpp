#include "EthernetHead.hpp"

EthernetHead::EthernetHead(const u_char* data, uint32_t* offset){

    struct ether_addr carrier;

    memset(srcMac, '\0', FORMATMACSIZE);
    memset(dstMac, '\0', FORMATMACSIZE);

    memcpy(carrier.ether_addr_octet, data, MACSIZE);
    memcpy(dstMac, ether_ntoa((&carrier)), strlen(ether_ntoa((&carrier))));

    data += MACSIZE;

    memcpy(carrier.ether_addr_octet, (data), MACSIZE);
    memcpy(srcMac, ether_ntoa((&carrier)), strlen(ether_ntoa((&carrier))));

    data += MACSIZE;

    type = ntohs(*((uint16_t*)data));
    *offset += 2*MACSIZE+TYPESIZE;



}




