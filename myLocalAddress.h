#ifndef __myLocalAddress__
#define __myLocalAddress__

#include <netinet/ether.h>
#include <arpa/inet.h>

struct myAddress{
    in_addr IP;
    ether_addr MAC;
};

struct myFullAddress{
	in_addr IP;
    ether_addr MAC;
    in_addr subMask;
};

myFullAddress& getMyAddr();
myAddress& getGateway();

#endif