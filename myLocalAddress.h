#ifndef __myLocalAddress__
#define __myLocalAddress__

#include <netinet/ether.h>
#include <arpa/inet.h>

struct myAddress{
    struct in_addr IP;
    struct ether_addr MAC;
};

struct myFullAddress{
	struct in_addr IP;
    struct ether_addr MAC;
    struct in_addr subMask;
};

struct myFullAddress getMyAddr();
struct myAddress getGateway();

#endif