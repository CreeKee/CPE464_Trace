#include "EthernetHead.hpp"
#include <pcap.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include "IPHead.hpp"
#include "ARPHead.hpp"
#include "TCPHeader.hpp"

void processEthernetHead(const u_char* data, uint32_t* offset);
void processIPHead(const u_char* data, uint32_t* offset);
void processARPHead(const u_char* data, uint32_t* offset);
void processICMP(const u_char* data);
void processTCPHead(const u_char* data, uint32_t* offset, IPHead Ihead);
void processUDP(const u_char* data);
bool psuedoSum(const u_char* data, IPHead Ihead);

int main(int argc, char* argv[]){

    int res;
    int packetNum = 1;
    char errbuf[PCAP_ERRBUF_SIZE];    

    struct pcap_pkthdr* pktHeader;
    const u_char* data;
    uint32_t offset = 0;

    //open packet folder
    pcap_t* packet = pcap_open_offline(argv[1], errbuf);
    if(!packet){
        perror("ERROR: unable to open file\n");
        exit(-1);
    }

    while((res = pcap_next_ex(packet, &pktHeader, &data)) >=0){ //error check


        printf("\nPacket number: %d  Frame Len: %d\n\n", packetNum, pktHeader->len);

        packetNum++;
        offset = 0;

        processEthernetHead(data, &offset);
        
        
    }
    return 0;
}

void processEthernetHead(const u_char* data, uint32_t* offset){

        EthernetHead Ehead = EthernetHead(data, offset);

        printf("\tEthernet Header\n");
        printf("\t\tDest MAC: %s\n", Ehead.getDest());
        printf("\t\tSource MAC: %s\n", Ehead.getSrc());

        switch(Ehead.getType()){

            case IPTYPE:
                printf("\t\tType: IP\n\n");
                processIPHead(data, offset);
                break;
            
            case ARPTYPE:
                printf("\t\tType: ARP\n\n");
                processARPHead(data, offset);
                break;

            default:
                break;
        }

}

void processIPHead(const u_char* data, uint32_t* offset){

    IPHead Ihead(data+*offset, offset);
    Ihead.display();

        switch(Ihead.getProtocol()){

            case(IPPROTO_ICMP):
                processICMP(data+*offset);
                break;

            case(IPPROTO_TCP):
                processTCPHead(data, offset, Ihead);
                break;

            case(IPPROTO_UDP):
                processUDP(data+*offset);
                break;

            default:
                break;
        }

        return;
}

void processARPHead(const u_char* data, uint32_t* offset){

    ARPHead Ahead(data+*offset);
    Ahead.display();

    return;
}

void processTCPHead(const u_char* data, uint32_t* offset,IPHead Ihead){

    TCPHead Thead(data+*offset, psuedoSum(data+*offset, Ihead));
    Thead.display();
}

void processICMP(const u_char* data){

    printf("\t\nICMP Header\n");
    switch(*data){
        case 8: //TODO
            printf("\t\tType: Request\n");
            break;

        case 0:
            printf("\t\tType: Reply\n");
            break;

        default:
            printf("\t\tType: %d\n", *(data+CODEOFFSET)-1);
            break;
    }

    return;
}

void processUDP(const u_char* data){
    /*
    UDP Header
		Source Port: : 137
		Dest Port: : 137
    */

   printf("\n\tUDP Header\n");
   printf("\t\tSource Port: : %d\n", ntohs(*(uint16_t*)(data)));
   printf("\t\tDest Port: : %d\n", ntohs(*(uint16_t*)(data+PORTLENGTH)));

}

bool psuedoSum(const u_char* data, IPHead Ihead){

    bool retval;
    uint32_t IPpayload = (Ihead.getLength()-(Ihead.getHeadLen()*BYTEWIDTH/2));
    uint8_t* pseudoHeader = new uint8_t[PSEUDOLENGTH+IPpayload];
    
    memcpy(pseudoHeader, Ihead.getPseudo(), PSEUDOLENGTH);
    memcpy(pseudoHeader+PSEUDOLENGTH, data, IPpayload);
 
    
    retval= in_cksum((unsigned short*)pseudoHeader, IPpayload+PSEUDOLENGTH) == 0;
    free(pseudoHeader);

    return retval;

}



/*
Packet number: 10  Frame Len: 438

	Ethernet Header
		Dest MAC: 0:2:2d:90:75:89
		Source MAC: 0:6:25:78:c4:7d
		Type: IP

	IP Header
		Header Len: 20 (bytes)
		TOS: 0x0
		TTL: 51
		IP PDU Len: 424 (bytes)
		Protocol: TCP
		Checksum: Correct (0x5e75)
		Sender IP: 129.65.242.4
		Dest IP: 192.168.1.102

	TCP Header
		Source Port: : 22
		Dest Port: : 1675
		Sequence Number: 3289359219
		ACK Number: 120760270
		ACK Flag: Yes
		SYN Flag: No
		RST Flag: No
		FIN Flag: No
		Window Size: 49680
		Checksum: Correct (0x43ed)

Packet number: 11  Frame Len: 78

	Ethernet Header
		Dest MAC: 0:6:25:78:c4:7d
		Source MAC: 0:2:2d:90:75:89
		Type: IP
*/


/*
Packet number: 9  Frame Len: 60

	Ethernet Header
		Dest MAC: 0:2:2d:90:75:89
		Source MAC: 0:6:25:78:c4:7d
		Type: IP

	IP Header
		Header Len: 20 (bytes)
		TOS: 0x0
		TTL: 51
		IP PDU Len: 40 (bytes)
		Protocol: TCP
		Checksum: Correct (0xdf76)
		Sender IP: 129.65.242.4
		Dest IP: 192.168.1.102

	TCP Header
		Source Port: : 22
		Dest Port: : 1675
		Sequence Number: 3289359219
		ACK Number: 120760270
		ACK Flag: Yes
		SYN Flag: No
		RST Flag: No
		FIN Flag: No
		Window Size: 49680
		Checksum: Correct (0x9b4a)

*/

