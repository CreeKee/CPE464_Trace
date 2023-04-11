#include "includes.hpp"

#ifndef IP_H
#define IP_H

class IPHead{

    private:
        //stuff
        u_char verslen;
        u_char tos;
        uint16_t length;
        uint16_t ident;
        uint16_t flag;
        u_char ttl;
        u_char protocol;
        uint16_t chksum;
        bool checked;

        uint32_t options;

        struct in_addr sourceIP;
        struct in_addr destIP;
    public:
        IPHead(const u_char* data, uint32_t* offset);

        u_char getHeadLen(){return verslen&LOWERMASK;}
        

};

#endif