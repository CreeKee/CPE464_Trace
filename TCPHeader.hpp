#include "includes.hpp"

#ifndef TCP_H
#define TCP_H

class TCPHead{

    private:
        uint16_t srcPort;
        uint16_t dstPort;
        uint32_t sequenceNum;
        uint32_t ackNum;
        uint16_t flags;
        uint16_t windowSize;
        uint16_t checksum;

        bool conf;

    public:
        TCPHead(const u_char* data, bool checked);

        void display();

};

#endif
