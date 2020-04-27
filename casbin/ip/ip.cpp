#include"ip.h"
#include<iostream>
IP::IP(string ip) {
	if (ip.size() < 7 || ip.size() > 18) {
		return;
	}
	int lastdot = 0;
	bool CIDRflag = false;
	int dotcnt = 0;
	int sum = 0;
	for (int i = 0; i < ip.size(); i++) {
		char c = ip[i];
		if (isalnum(c)) {
			sum *= 10;
			sum += c - '0';
		}
		else if(c == '.') {
			if (sum < 0 || sum>255 || dotcnt>2) {
				return;
			}
			else {
				section[dotcnt] = sum;
				sum = 0;
				dotcnt++;
			}
		}
		else if (c == '/') {
			if (CIDRflag) return;
			CIDRflag = true;
			if (sum < 0 || sum>255 || dotcnt!=3) {
				return;
			}
			else {
				section[dotcnt] = sum;
				sum = 0;
				dotcnt++;
			}
		}
		else {
			return;
		}
	}

	if (CIDRflag) {
		if (sum < 0 || sum>32) {
			return;
		}
		else {
			masklen = sum;
			isCidr = true;
		}
	}
	else {
		if (sum < 0 || sum>255 || dotcnt!=3) {
			return;
		}
		else {
			masklen = 0;
			section[dotcnt] = sum;
			isIp = true;
		}
	}
	//cout << (unsigned long)section[3] << " + " << ((unsigned long)section[2] << 8) << " + " << ((unsigned long)section[1] << 16) << " + " << ((unsigned long)section[0] << 24) << endl;
	mask = (unsigned long)section[3] + ((unsigned long)section[2] << 8) + ((unsigned long)section[1] << 16) + ((unsigned long)section[0] << 24);

}

bool IP::isIP() {
	return this->isIp;
}
bool IP::isCIDR() {
	return this->isCidr;
}

bool IP::Equal(IP ip) {
	if (this->isIp&&ip.isIp) {
		if (this->mask == ip.mask) {
			return true;
		}
		else {
			return false;
		}
	}
	return false;
}

bool IP::Contain(IP ip) {
	if (this->isCidr && ip.isIp) {
		if (mask >> (32 - masklen) == ip.mask >> (32 - masklen) ) {
			return true;
		}
		else {
			return false;
		}
	}
	return false;
}

void IP::Show() {
	cout << "IsIP:" << isIp << endl;
	cout << "IsCIDR:" << isCidr << endl;
	cout << "Section:" << endl;
	for (int i = 0; i < 4; i++)
		cout << section[i] << " ";
	cout << endl;
	cout << "MaskLen:" << masklen << endl;
	cout << "Mask:" << mask << endl;
}