#pragma once

#include "pch.h"

#include "./parseIPv4.h"

IP parseIPv4(string s) {
    vector <byte> pb(IP :: IPv4len, 0);
    IP ipv4;
    for(int i = 0; i < IP :: IPv4len ; i++) {
        if(s.length() == 0) {
            // Missing octets.
            ipv4.isLegal = false;
            return ipv4;
        }
        if(i > 0) {
            if(s[0] != '.') {
                ipv4.isLegal = false;
                return ipv4;
            }
            s = s.substr(1,s.length() - 1);
        }
        pair<int,int> p = dtoi(s);
        if ((p.first>=big || p.second==0) || p.first > 0xFF) {
            ipv4.isLegal = false;
            return ipv4;
        }
        s = s.substr(p.second, s.length() - p.second);
        pb[i] = p.first;
    }
    if(s.length() != 0) {
        ipv4.isLegal = false;
        return ipv4;
    }
    return IPv4(pb[0], pb[1], pb[2], pb[3]);
}