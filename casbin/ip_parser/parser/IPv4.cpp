#pragma once

#include "pch.h"

#include "./IPv4.h"

IP IPv4(byte a, byte b, byte c, byte d) {
    IP p;
    vector <byte> newIP(IP :: v4InV6Prefix.begin(), IP :: v4InV6Prefix.end());
    p.ip = newIP;
    p.ip.push_back(a);
    p.ip.push_back(b);
    p.ip.push_back(c);
    p.ip.push_back(d);
    p.isLegal = true;
    return p;
}