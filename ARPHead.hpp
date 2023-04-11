#include "includes.hpp"

#ifndef ARP_H
#define ARP_H

class ARPHead{

    private:
        //stuff
        uint16_t protocol;

        char sourceIP[IPSIZE];
        char destIP[IPSIZE];

        char srcMac[FORMATMACSIZE];
        char dstMac[FORMATMACSIZE];

    public:
        ARPHead(const u_char* data);

        uint16_t getProtocol(){return protocol;}
        char* getSrc(){return srcMac;}
        char* getDest(){return dstMac;}
        char* getSourceIP(){return sourceIP;}
        char* getDestIP(){return destIP;}

};

#endif