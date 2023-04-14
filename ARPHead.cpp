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