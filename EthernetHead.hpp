#include "includes.hpp"


#ifndef ETHER_H
#define ETHER_H

class EthernetHead{
    private: 
        char srcMac[MACSIZE*3];
        char dstMac[MACSIZE*3];
        uint16_t type;

    public:
        EthernetHead(const u_char* data, uint32_t* offset){

            struct ether_addr carrier;

            memcpy(carrier.ether_addr_octet, data, MACSIZE);
            memcpy(dstMac, ether_ntoa((&carrier)), strlen(ether_ntoa((&carrier))));

            memcpy(carrier.ether_addr_octet, (data+MACSIZE), MACSIZE);
            memcpy(srcMac, ether_ntoa((&carrier)), strlen(ether_ntoa((&carrier))));

            type = ntohs(*(data+2*MACSIZE));

            *offset += 2*MACSIZE+TYPESIZE;

        }

        char* getSrc(){return srcMac;}
        char* getDest(){return dstMac;}
        uint16_t getType(){return type;}

        char* formatSrc();
};

#endif