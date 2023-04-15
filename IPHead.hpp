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

        char sourceIP[IPSIZE];
        char destIP[IPSIZE];

        uint8_t pseudo[PSEUDOLENGTH];
    public:
        IPHead(const u_char* data, uint32_t* offset);

        u_char getHeadLen(){return verslen&LOWERMASK;}
        u_char getTos(){return tos;}
        u_char getTtl(){return ttl;}
        uint16_t getLength(){return length;}
        u_char getProtocol(){return protocol;}
        bool getConf(){return checked;}
        uint16_t getCksum(){return chksum;}
        char* getSourceIP(){return sourceIP;}
        char* getDestIP(){return destIP;}
        uint8_t* getPseudo(){return pseudo;}

        void display();

};

#endif