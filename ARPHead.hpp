#include "includes.hpp"

#ifndef ARP_H
#define ARP_H

class ARPHead{

    private:
        //stuff
        uint16_t opcode;

        char sourceIP[IPSIZE];
        char destIP[IPSIZE];

        char srcMac[FORMATMACSIZE];
        char dstMac[FORMATMACSIZE];

    public:
        ARPHead(const u_char* data);

        uint16_t getOpcode(){return opcode;}
        char* getSrcMAC(){return srcMac;}
        char* getDestMAC(){return dstMac;}
        char* getSrcIP(){return sourceIP;}
        char* getDestIP(){return destIP;}

        void display();
};

#endif