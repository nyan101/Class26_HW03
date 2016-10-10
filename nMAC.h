#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <stdio.h>

struct nMAC {
    uint8_t MAC[ETHER_ADDR_LEN];
    char MACstr[18];

    nMAC(){}
    nMAC(const nMAC& rhs)       { operator =(rhs); }
    nMAC(const char* rhs)       { operator =(rhs); }
    nMAC(const ether_addr& rhs) { operator =(rhs); }

    operator const char*() { ether_ntoa_r((const ether_addr*)MAC, MACstr); return MACstr;  }

    void operator = (const nMAC& rhs)       { memcpy(MAC, rhs.MAC, ETHER_ADDR_LEN);	return; }
    void operator = (const char* rhs)       { ether_aton_r(rhs, (ether_addr*)MAC);  return; }
    void operator = (const ether_addr& rhs) { memcpy(MAC, rhs.ether_addr_octet, ETHER_ADDR_LEN); return; }

    bool isBroadcast() const { return memcmp(MAC, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN)==0; }
};