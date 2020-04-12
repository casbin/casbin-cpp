#pragma once
#pragma once
#include<vector>
#include<string>
#include <initializer_list>
using namespace std;

class Util
{
public:
	static vector<string> Split(const string& s, const string& c);
	static vector<string> SplitN(const string& s, const string& c,const int& N);
	static string EscapeAssertion(const string& s);
	static string RemoveComments(const string& s);
	static bool ArrayEquals(const vector<string>& a, const vector<string>& b);
	static bool Array2DEquals(const vector < vector<string>>& a, const  vector <vector<string>>& b);
	static void ArrayRemoveDuplicates(vector<string>* s);
	static string ArrayToString(const vector<string>& s);
	static string ParamasToString(const initializer_list<string>& s);
	static bool SetEquals(const vector<string>& a, const vector<string>& b);
	static vector<string> JoinSlice(const string& a, const initializer_list<string>& b);
	static void PrintVector(const vector<string>& v);
	static void Print2DVector(const vector < vector<string>>& v);
	static bool HasPrefix(const string& s, const string& b);
	static bool HasSuffix(const string& s, const string& b);
	static string Trim(const string& s, const string& b);
	static string TrimLeft(const string& s, const  string& b);
	static string TrimRight(const string& s, const  string& b);
};