#pragma once

#include "pch.h"

#include "./IPNet.h"

string IPNet :: NETIP_toString() {
    string ip1, ip2, ip3, ip4;
    stringstream ss1, ss2, ss3, ss4;
    ss1 << net_ip.ip[0];
    ss1 >> ip1;
    ss2 << net_ip.ip[1];
    ss2 >> ip2;
    ss3 << net_ip.ip[2];
    ss3 >> ip3;
    ss4 << net_ip.ip[3];
    ss4 >> ip4;
    return ip1 + "." + ip2 + "." + ip3 + "." + ip4;
}

string IPNet :: IPMask_toString() {
    string mask1, mask2, mask3, mask4;
    stringstream ss1, ss2, ss3, ss4;
    ss1 << mask[0];
    ss1 >> mask1;
    ss2 << mask[1];
    ss2 >>mask2;
    ss3 << mask[2];
    ss3 >>mask3;
    ss4 << mask[3];
    ss4 >>mask4;
    return mask1 + "." + mask2 + "." + mask3 + "." + mask4;
}

// Contains reports whether the network includes ip.
bool IPNet :: contains(IP ipNew) {
    pair<IP, IPMask> p = networkNumberAndMask(*this);
    IP x;
    x = ipNew.To4();
    if(x.isLegal == true) {
        ipNew = x;
    }
    int l = int(ipNew.ip.size());
    if(l != p.first.ip.size()) {
        return false;
    }
    for(int i = 0 ; i < l ; i++) {
        if((p.first.ip[i]&p.second[i]) != (ipNew.ip[i]&p.second[i])) {
            return false;
        }
    }
    return true;
}

pair<IP, IPMask> IPNet :: networkNumberAndMask(IPNet n) {
    IP newIp;
    newIp = n.net_ip.To4();
    pair <IP, IPMask> p;
    p.first = newIp;
    if(newIp.isLegal == false) {
        newIp = n.net_ip;
        if(newIp.ip.size() != IP :: IPv6len) {
            p.first.isLegal = false;
            return p;
        }
    }
    IPMask m = n.mask;
    p.second = m;
    const byte ipv4len = IP :: IPv4len;
    const byte ipv6len = IP :: IPv6len;
    if(m.size() == ipv4len){
        if(newIp.ip.size() != IP :: IPv4len) {
            p.first.isLegal = false;
        }
    } else if(m.size() == ipv6len){
        if(newIp.ip.size() == IP :: IPv4len) {
            IPMask newM(m.begin() + 12, m.end());
            m = newM;
            p.first = newIp;
            p.second = m;
        }
    } else {
        p.first.isLegal = false;
    }
    return p;
}