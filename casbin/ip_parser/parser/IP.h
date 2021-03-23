/*
 * @Author: your name
 * @Date: 2021-03-23 07:30:29
 * @LastEditTime: 2021-03-23 13:37:19
 * @LastEditors: Please set LastEditors
 * @Description: In User Settings Edit
 * @FilePath: /casbin/casbin/ip_parser/parser/IP.h
 */
#ifndef IP_PARSER_PARSER_IP
#define IP_PARSER_PARSER_IP

#include <vector>
#include <sstream>

#include "./allFF.h"
#include "./IPMask.h"
#include "./equal.h"
#include "./byte.h"

using namespace std;

class IP {
    public:
        vector <Byte> ip;
        bool isLegal;
        static Byte IPv4len;
        static Byte IPv6len;
        static IPMask v4InV6Prefix;

        IP();

        IP Mask(IPMask mask);

        bool Equal(IP x);

        string toString();

        // To4 converts the IPv4 address ip to a 4-byte representation.
        // If ip is not an IPv4 address, To4 returns nil.
        IP To4();

        // Is p all zeros?
        static bool isZeros(IP p);

};

#endif