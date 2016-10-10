#include <netinet/in.h> // for ntohs() function
#include <pcap.h>       // for packet capturing
#include <stdlib.h>
#include <string.h>
//for struct
#include <netinet/ether.h>
#include <arpa/inet.h>
//custom headerfile
#include "myLocalAddress.h"
#include "myARPtools.h"

int convertIP2MAC(pcap_t *pcd, const in_addr IP, ether_addr &MAC)
{
    int status;
    ether_addr BcastMAC;
    ether_header *etherHdr;
    ether_arp *arpHdr;

    pcap_pkthdr *recvHeader;
    const u_char *recvPacket;
    u_char sendPacket[sizeof(ether_header) + sizeof(ether_arp)];

    // check if it's in the same network
    if((getMyAddr().IP.s_addr & getMyAddr().subMask.s_addr)
        != (IP.s_addr & getMyAddr().subMask.s_addr))
        return -1;

    // make ARP REQUEST packet
    ether_aton_r("ff:ff:ff:ff:ff:ff", &BcastMAC);
    makeARPpacket(sendPacket, getMyAddr().IP, getMyAddr().MAC, IP, BcastMAC, ARPOP_REQUEST);
    
    // send and get ARP response
    while(1)
    {
        // send Request
        if(pcap_inject(pcd, sendPacket, sizeof(sendPacket))==-1)
        {
            pcap_perror(pcd,0);
            pcap_close(pcd);
            exit(1);
        }

        // get Response
        status = pcap_next_ex(pcd, &recvHeader, &recvPacket);
        if(status!=1)
            continue;

        // check if it's ARP packet
        etherHdr = (ether_header*)recvPacket;
        if(etherHdr->ether_type!=htons(ETHERTYPE_ARP))
            continue;
        
        // check if it's 1)ARP Reply 2)from the desired source
        arpHdr = (ether_arp*)(recvPacket + sizeof(ether_header));
        if(arpHdr->arp_op != htons(ARPOP_REPLY))
            continue;
        if(memcmp(&arpHdr->arp_spa, &IP.s_addr, sizeof(in_addr_t))!=0)
            continue;

        // if so, copy MAC addr
        memcpy(MAC.ether_addr_octet, arpHdr->arp_sha, ETHER_ADDR_LEN);

        break;
    }

    return 0;
}

void makeARPpacket(u_char *packet, const in_addr sendIP, const ether_addr sendMAC,
                                   const in_addr recvIP, const ether_addr recvMAC, uint16_t ARPop)
{
    ether_header etherHdr;
    ether_arp arpHdr;

    // Ethernet part
    etherHdr.ether_type = htons(ETHERTYPE_ARP);
    memcpy(etherHdr.ether_dhost, &recvMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(etherHdr.ether_shost, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);

    // ARP part
    arpHdr.arp_hrd = htons(ARPHRD_ETHER);
    arpHdr.arp_pro = htons(ETHERTYPE_IP);
    arpHdr.arp_hln = ETHER_ADDR_LEN;
    arpHdr.arp_pln = sizeof(in_addr_t);
    arpHdr.arp_op  = htons(ARPop);
    memcpy(&arpHdr.arp_sha, &sendMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_spa, &sendIP.s_addr, sizeof(in_addr_t));
    memcpy(&arpHdr.arp_tha, &recvMAC.ether_addr_octet, ETHER_ADDR_LEN);
    memcpy(&arpHdr.arp_tpa, &recvIP.s_addr, sizeof(in_addr_t));

    // build packet
    memcpy(packet, &etherHdr, sizeof(ether_header));
    memcpy(packet+sizeof(ether_header), &arpHdr, sizeof(ether_arp));

    return;
}