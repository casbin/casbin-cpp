#include"util.h"
#include<iostream>
#include <regex>
#include<map>
string Util::ArrayToString(const vector<string>& s)
{
	string res = "";
	vector<string> tmp = s;
	vector<string>::iterator it = tmp.begin();
	res += *it;
	it++;
	for (; it != tmp.end(); it++)
		res = res + ", " + *it;
	return res;
}

bool Util::ArrayEquals(const vector<string>& a, const vector<string>& b)
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

vector<string> Util::Split(const string& s, const string& c)
{
	vector<string> res;
	if (s.find(c) == s.npos) {
		res.push_back(s);
		return res;
	}
	

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

vector<string> Util::SplitN(const string& s,const string& c,const int& N)
{
	vector<string> res;
	string tmp = s;

	int cnt = N;
	if ("" == tmp)
		return res;
	int front;
	int rear = 0;
	front = rear;
	rear = tmp.find_first_of(c);

	string s1 = tmp.substr(front, rear - front);

	res.push_back(s1);

	tmp = tmp.substr(rear + c.size());

	res.push_back(tmp);

	return res;
}

string Util::EscapeAssertion(const string& s)
{
	string tmp = s;
	if (tmp[0] == 'r' || tmp[0] == 'p') {
		int pos = tmp.find_first_of('.');
		if (pos != -1)
			tmp[pos] = '_';
	}
	regex regex_s("(\\|| |=|\\)|\\(|&|<|>|,|\\+|-|!|\\*|\\/)(r|p)(\\.)");
	smatch match;
	string::const_iterator iterStart = tmp.begin();
	string::const_iterator iterEnd = tmp.end();
	string result;
	regex_replace(back_inserter(result), iterStart, iterEnd, regex_s, "$1$2_");
	return result;
}

string Util::RemoveComments(const string& s)
{
	string tmp = s;
	int pos = tmp.find_first_of('#');
	if (pos == -1)
	{
		return tmp;
	}
	tmp = tmp.substr(0, pos);
	tmp = Trim(tmp," ");
	return tmp;
}

void Util::PrintVector(const vector<string>& v)
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

void Util::Print2DVector(const vector<vector<string>>& v)
{
	cout << "[";
	for (vector<string> word : v)
	{
		Util::PrintVector(word);
		cout << ",";
	}
	cout << "]";
}

bool Util::HasPrefix(const string& a, const string& b)
{
	int pos = a.find_first_of(b);
	if (pos == 0)
		return true;
	return false;
}

bool Util::HasSuffix(const string& a, const string& b)
{
	int pos = a.find_first_of(b);
	if (pos < 0)
		return false;
	if (b.size()+ pos == a.size())
		return true;
	return false;
}

string Util::Trim(const string& s, const string& b)
{
	string tmp = s;
	tmp.erase(0, tmp.find_first_not_of(b));
	tmp.erase(tmp.find_last_not_of(b) + 1);
	return tmp;
}
string Util::TrimLeft(const string& s, const string& b)
{
	string tmp = s;
	tmp.erase(0, tmp.find_first_not_of(b));
	return s;
}
string Util::TrimRight(const string& s,const string& b)
{
	string tmp = s;
	tmp.erase(tmp.find_last_not_of(b) + 1);
	return tmp;
}

void Util::ArrayRemoveDuplicates(vector<string>* s) {
	map<string, bool> found;
	int j = 0;
	for (int i = 0; i < (*s).size(); i++) {
		string x = (*s)[i];
		if (!found[x]){
			found[x] = true;
			(*s)[j] = (*s)[i];
			j++;
		}
	}
	(*s).erase(s->begin()+j,s->end());
}

bool Util::Array2DEquals(const vector < vector<string>>& a, const  vector <vector<string>>& b) {
	if (a.size() != b.size())
		return false;
	for (int i = 0; i < a.size(); i++) {
		if (!ArrayEquals(a[i], b[i])) {
			return false;
		}
	}
	return true;
}

bool Util::SetEquals(const vector<string>& a, const vector<string>& b) {
	vector<string> tmp_a = a;
	vector<string> tmp_b = b;
	if (a.size() != b.size()) {
		return false;
	}

	sort(tmp_a.begin(), tmp_a.end());
	sort(tmp_b.begin(), tmp_b.end());
	for (int i = 0; i < a.size(); i++) {
		if (tmp_a[i] != tmp_b[i]) {
			return false;
		}
	}
	return true;
}