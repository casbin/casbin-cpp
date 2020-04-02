#include"util.h"
#include<iostream>
#include <regex>
string Util::ArrayToString(vector<string> s)
{
	string res = "";
	vector<string>::iterator it = s.begin();
	res += *it;
	it++;
	for (; it != s.end(); it++)
		res = res + ", " + *it;
	return res;
}

bool Util::ArrayEquals(vector<string> a, vector<string> b)
{
	if (a.size() != b.size())
		return false;
	for (int i=0;i<a.size();i++)
	{
		if (a[i] != b[i])
			return false;
	}
	return true;
}

vector<string> Util::Split(string s, string c)
{
	vector<string> res;

	if ("" == s)
		return res;

	char* strs = new char[s.length() + 1];
	strcpy_s(strs, s.length() + 1, s.c_str());

	char* d = new char[c.length() + 1];
	strcpy_s(d, c.length() + 1, c.c_str());

	char* p;
	char* ptr;
	ptr = strtok_s(strs, d, &p);
	while (ptr != NULL) {
		string s = ptr;
		res.push_back(s);
		ptr = strtok_s(NULL, d, &p);
	}

	delete strs;
	delete d;

	return res;
}

string Util::EscapeAssertion(string s)
{
	if (s[0] == 'r' || s[0] == 'p') {
		int pos = s.find_first_of('.');
		if (pos != -1)
			s[pos] = '_';
	}
	regex regex_s("(\\|| |=|\\)|\\(|&|<|>|,|\\+|-|!|\\*|\\/)(r|p)(\\.)");
	smatch match;
	string::const_iterator iterStart = s.begin();
	string::const_iterator iterEnd = s.end();
	string result;
	regex_replace(back_inserter(result), iterStart, iterEnd, regex_s, "$1$2_");
	return result;
}

string Util::RemoveComments(string s)
{
	int pos = s.find_first_of('#');
	if (pos == -1)
	{
		return s;
	}
	s = s.substr(0, pos);
	s.erase(remove(s.begin(), s.end(), ' '), s.end());
	return s;
}

void Util::PrintVector(vector<string> v)
{
	cout << "[";
	for (string word : v)
	{
		cout <<"\"";
		cout << word;
		cout << "\",";
	}
	cout << "]";
}

void Util::Print2DVector(vector<vector<string>> v)
{
	cout << "[";
	for (vector<string> word : v)
	{
		Util::PrintVector(word);
		cout << ",";
	}
	cout << "]";
}

bool Util::HasPrefix(string a,string b)
{
	int pos = a.find_first_of(b);
	if (pos == 0)
		return true;
	return false;
}

string& Util::Trim(string& s, string b)
{
	s.erase(0, s.find_first_not_of(b));
	s.erase(s.find_last_not_of(b) + 1);
	return s;
}
string& Util::TrimLeft(string& s, string b)
{
	s.erase(0, s.find_first_not_of(b));
	return s;
}
string& Util::TrimRight(string& s, string b)
{
	s.erase(s.find_last_not_of(b) + 1);
	return s;
}