#include<string>
using namespace std;

class IP {
public:
	bool isIp = false;
	bool isCidr = false;

	int section[4];
	unsigned long mask;
	int masklen;

	IP(string ip);
	bool isIP();
	bool isCIDR();
	bool Equal(IP ip);
	bool Contain(IP ip);
	void Show();
};