#include "casbin/pch.h"

#ifndef PARSEIPV6_CPP
#define PARSEIPV6_CPP

#include "casbin/ip_parser/parser/parseIPv6.h"

namespace casbin {

IP parseIPv6(std::string_view s) {
    IP ipv6;
    std::vector<byte> newIP(IP ::IPv6len, 0);
    ipv6.ip = newIP;
    int ellipsis = -1; // position of ellipsis in ip

    // Might have leading ellipsis
    if (s.length() >= 2 && s[0] == ':' && s[1] == ':') {
        ellipsis = 0;
        s = s.substr(2, s.length() - 2);
        // Might be only ellipsis
        if (s.length() == 0) {
            return ipv6;
        }
    }

    // Loop, parsing hex numbers followed by colon.
    int i = 0;
    for (; i < IP ::IPv6len;) {
        // Hex number.
        std::pair<int, int> p = xtoi(s);
        if ((p.first >= big || p.second == 0) || p.first > 0xFFFF) {
            ipv6.isLegal = false;
            return ipv6;
        }

        // If followed by dot, might be in trailing IPv4.
        if (p.second < s.length() && s[p.second] == '.') {
            if (ellipsis < 0 && i != IP ::IPv6len - IP ::IPv4len) {
                ipv6.isLegal = false;
                return ipv6;
            }
            if (i + IP ::IPv4len > IP ::IPv6len) {
                // Not enough room.
                ipv6.isLegal = false;
                return ipv6;
            }
            IP ip4 = parseIPv4(s);
            if (ip4.isLegal == false) {
                ipv6.isLegal = false;
                return ipv6;
            }
            ipv6.ip[i] = ip4.ip[12];
            ipv6.ip[i + 1] = ip4.ip[13];
            ipv6.ip[i + 2] = ip4.ip[14];
            ipv6.ip[i + 3] = ip4.ip[15];
            s = "";
            i += IP ::IPv4len;
            break;
        }

        // Save this 16-bit chunk.
        ipv6.ip[i] = byte(p.first >> 8);
        ipv6.ip[i + 1] = byte(p.first);
        i += 2;

        // Stop at end of std::string.
        s = s.substr(p.second, s.length() - p.second);
        if (s.length() == 0) {
            break;
        }

        // Otherwise must be followed by colon and more.
        if (s[0] != ':' || s.length() == 1) {
            ipv6.isLegal = false;
            return ipv6;
        }
        s = s.substr(1, s.length() - 1);

        // Look for ellipsis.
        if (s[0] == ':') {
            if (ellipsis >= 0) { // already have one
                ipv6.isLegal = false;
                return ipv6;
            }
            ellipsis = i;
            s = s.substr(1, s.length() - 1);
            if (s.length() == 0) { // can be at end
                break;
            }
        }
    }

    // Must have used entire std::string.
    if (s.length() != 0) {
        ipv6.isLegal = false;
        return ipv6;
    }

    // If didn't parse enough, expand ellipsis.
    if (i < IP ::IPv6len) {
        if (ellipsis < 0) {
            ipv6.isLegal = false;
            return ipv6;
        }
        int n = IP ::IPv6len - i;
        for (int j = i - 1; j >= ellipsis; j--) {
            ipv6.ip[j + n] = ipv6.ip[j];
        }
        for (int j = ellipsis + n - 1; j >= ellipsis; j--) {
            ipv6.ip[j] = 0;
        }
    } else if (ellipsis >= 0) {
        // Ellipsis must represent at least one 0 group.
        ipv6.isLegal = false;
        return ipv6;
    }
    return ipv6;
}

} // namespace casbin

#endif // PARSEIPV6_CPP
