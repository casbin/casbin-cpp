#include "pch.h"
#include "utils.h"

extern "C++" inline string ltrim(string str, const string chars)
{
	str.erase(0, str.find_first_not_of(chars));
	return str;
}

inline string rtrim(string str, const string chars)
{
	str.erase(str.find_last_not_of(chars) + 1);
	return str;
}

inline string trim(string str, const string chars)
{
	return ltrim(rtrim(str, chars), chars);
}

vector<string> split(const string& p_pcstStr, char delim)
{
	vector<string> tokens;
	stringstream mySstream(p_pcstStr);
	string temp;

	while (getline(mySstream, temp, delim))
	{
		if (temp.length() != 0) tokens.push_back(temp);
	}

	return tokens;
}

string join(vector<string> arr, char delim)
{
	string temp = "";
	for (string ele : arr)
	{
		if (temp.size() != 0)
		{
			temp += delim;
			temp += ele;
		}
		else
			temp += ele;
	}

	return temp;
}

bool keyMatch(string arg1, string arg2)
{
	arg2 = trim(arg2);
	arg1 = trim(arg1);

	vector<string> arg2arr = split(arg2, '/');
	vector<string> arg1arr = split(arg1, '/');

	vector<string>::iterator itr = arg2arr.begin();
	int i = 0;
	while (itr != arg2arr.end())
	{
		if (*itr == "*")
		{
			i++;
			itr++;
			continue;
		}
		if (i >= arg1arr.size())
			return false;
		if (*itr != arg1arr.at(i))
			return false;
		i++;
		itr++;
	}

	return true;
}

bool keyMatch2(string arg1, string arg2)
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

bool keyMatch4(string arg1, string arg2)
{
	arg2 = trim(arg2);
	arg1 = trim(arg1);

	vector<string> arg2arr = split(arg2, '/');
	vector<string> arg1arr = split(arg1, '/');
	map<string, string> urlKey;

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

bool regexMatch(string arg1, string arg2)
{
	regex e(arg2);
	if (regex_search(arg1, e)) return true;
	return false;
}

vector<string> split(string text, string delim)
{
	smatch mat;
	if (regex_search(text, mat, regex(delim)))
	{
		vector<string> arr;
		arr.push_back(mat.prefix());
		vector<string> temp = split(mat.suffix(), delim);
		arr.insert(arr.end(), temp.begin(), temp.end());

		return arr;
	}
	else return vector<string>{text};
}

string escapeAssertion(string s) {
	return regex_replace(s, std::regex("\\."), "_");
}