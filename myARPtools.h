#ifndef __myARPtools__
#define __myARPtools__

#include <pcap.h>
#include <netinet/ether.h>
#include <arpa/inet.h>

int convertIP2MAC(pcap_t *pcd, const in_addr IP, ether_addr &MAC);
void makeARPpacket(u_char *packet, const in_addr sendIP, const ether_addr sendMAC,
                                   const in_addr recvIP, const ether_addr recvMAC, uint16_t ARPop);

#endif