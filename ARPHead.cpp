#include "ARPHead.hpp"


ARPHead::ARPHead(const u_char* data){

    struct in_addr IPcarrier;
    struct ether_addr MACcarrier;

    data += ARPOPOFFSET;

    opcode = *(uint16_t*)data;
    data += OPCODELENGTH;

    memcpy(MACcarrier.ether_addr_octet, (data+MACSIZE), MACSIZE);
    memcpy(srcMac, ether_ntoa((&MACcarrier)), strlen(ether_ntoa((&MACcarrier))));
    data += ARPSKIP;

    IPcarrier.s_addr = *(uint32_t*)data;
    memcpy(sourceIP, inet_ntoa(IPcarrier), IPSIZE);
    data += ARPSKIP;

    memcpy(MACcarrier.ether_addr_octet, data, MACSIZE);
    memcpy(dstMac, ether_ntoa((&MACcarrier)), strlen(ether_ntoa((&MACcarrier))));
    data += ARPSKIP;

    IPcarrier.s_addr = *(uint32_t*)data;
    memcpy(destIP, inet_ntoa(IPcarrier), IPSIZE);
    
}