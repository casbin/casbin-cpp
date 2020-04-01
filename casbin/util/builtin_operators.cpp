#include "builtin_operators.h"

bool key_match(string arg1, string arg2)
{
	arg2 = trim(arg2);
	arg1 = trim(arg1);

	auto arg2arr = split(arg2, '/');
	auto arg1arr = split(arg1, '/');

	auto itr = arg2arr.begin();
	int i = 0;
	while (itr != arg2arr.end())
	{
		if (*itr == "*")
		{
			i++;
			++itr;
			continue;
		}
		if (i >= arg1arr.size())
			return false;
		if (*itr != arg1arr.at(i))
			return false;
		i++;
		++itr;
	}

	return true;
}

bool key_match2(string arg1, string arg2)
{
	arg2 = trim(arg2);
	arg1 = trim(arg1);

	vector<string> arg2arr = split(arg2, '/');
	vector<string> arg1arr = split(arg1, '/');

	int i = 0;
	for (string ele : arg2arr)
	{
		if (ele.at(0) == ':')
		{
			i++;
			continue;
		}
		if (i >= arg1arr.size())
			return false;
		if (ele != arg1arr.at(i))
			return false;
		i++;
	}

	return true;
}

bool key_match4(string arg1, string arg2)
{
	arg2 = trim(arg2);
	arg1 = trim(arg1);

	vector<string> arg2arr = split(arg2, '/');
	vector<string> arg1arr = split(arg1, '/');
	unordered_map<string, string> urlKey;

	int i = 0;
	for (string ele : arg2arr)
	{
		if (i >= arg1arr.size())
			return false;
		if (ele.at(0) == '{' && ele.at(ele.length() - 1) == '}')
		{
			ele = ele.erase(0, 1);
			ele.erase(ele.length() - 1, 1);
			if (urlKey.find(ele) == urlKey.end())
			{
				urlKey.insert(pair<string, string>(ele, arg1arr.at(i)));
			}
			else
			{
				if (urlKey.find(ele)->second != arg1arr.at(i))
					return false;
			}
			i++;
			continue;
		}
		if (ele != arg1arr.at(i))
			return false;
		i++;
	}

	return true;
}

inline bool regex_match(string arg1, string arg2)
{
	regex e(arg2);
	if (regex_search(arg1, e)) return true;
	return false;
}

vector<int> ipToInt(string IP)
{
	vector<string> arr = split(IP, '.');
	vector<int> result;
	for (string temp : arr)
	{
		result.push_back(stoi(temp));
	}

	return result;
}

string intArrToBin(vector<int> arr)
{
	string binary = "";
	for (int temp : arr)
		binary += bitset<8>(temp).to_string();

	return binary;
}

bool ip_match(string ip1, string ip2)
{
	string cidr = split(ip2, '/')[1];
	vector<int> arr1 = ipToInt(ip1);
	vector<int> arr2 = ipToInt(split(ip2, '/')[0]);

	return intArrToBin(arr1).substr(0, stoi(cidr)) == intArrToBin(arr2).substr(0, stoi(cidr));
}


function<bool(string, string)> generate_g_function(role_manager* rm) {
	auto func = [](role_manager* rm, string name1, string name2) {
		if (rm == NULL) return name1 == name2;
		bool result = rm->has_link(name1, name2);
		return result;
	};

	return bind(func, rm, placeholders::_1, placeholders::_2);
}