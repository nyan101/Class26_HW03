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

    nMAC& operator = (const nMAC& rhs)       { memcpy(MAC, rhs.MAC, ETHER_ADDR_LEN);    return *this; }
    nMAC& operator = (const char* rhs)       { ether_aton_r(rhs, (ether_addr*)MAC);     return *this; }
    nMAC& operator = (const ether_addr& rhs) { memcpy(MAC, rhs.ether_addr_octet, ETHER_ADDR_LEN); return *this; }

    bool operator == (const char* rhs) {
        uint8_t tmp[ETHER_ADDR_LEN];
        ether_aton_r(rhs, (ether_addr*)tmp);
        return memcmp(tmp, MAC, ETHER_ADDR_LEN)==0;
    }
    bool operator == (const ether_addr& rhs) const { return memcmp(MAC, rhs.ether_addr_octet, ETHER_ADDR_LEN)==0; }

    bool isBroadcast() const { return memcmp(MAC, "\xff\xff\xff\xff\xff\xff", ETHER_ADDR_LEN)==0; }
};