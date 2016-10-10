#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

struct nIP {
    uint32_t IP; // in Network Byte Order
    char IPstr[INET_ADDRSTRLEN];

    nIP(){}
    nIP(const nIP& rhs) 	{ IP = rhs.IP; }
    nIP(const uint32_t rhs) { IP = htonl(rhs); }
    nIP(const char* rhs) 	{ operator =(rhs); }
    nIP(const in_addr& rhs) { operator =(rhs); }

    operator uint32_t() const { return ntohl(IP); }
    explicit operator const char*() { inet_ntop(AF_INET, &IP, IPstr, INET_ADDRSTRLEN); return IPstr; }

    void operator = (const nIP& rhs)     { IP = rhs.IP;     return; }
    void operator = (const uint32_t rhs) { IP = htonl(rhs); return; }
    void operator = (const char* rhs)    { inet_pton(AF_INET, rhs, &IP); return; }
    void operator = (const in_addr& rhs) { IP = rhs.s_addr; return; }

    bool operator == (const uint32_t rhs) const { return IP==htonl(rhs); }
    bool operator == (const in_addr& rhs) const { return IP==rhs.s_addr; }
    bool operator == (const char* rhs) { return inet_addr(rhs)==IP; } // "invalid string == 255.255.255.255" is true. (use isBroadcast in this case)

    bool isBroadcast() const { return IP == 0xFFFFFFFF; } // 255.255.255.255
};
