#include "includes.hpp"


#ifndef ETHER_H
#define ETHER_H

class EthernetHead{
    private: 
        char srcMac[FORMATMACSIZE];
        char dstMac[FORMATMACSIZE];
        uint16_t type;

    public:
        EthernetHead(const u_char* data, uint32_t* offset);

        char* getSrc(){return srcMac;}
        char* getDest(){return dstMac;}
        uint16_t getType(){return type;}

        char* formatSrc();
};

#endif