#pragma once
#pragma once
#include<vector>
#include<string>
#include <initializer_list>
using namespace std;

class Util
{
public:
	static vector<string> Split(string s, string c);
	static string EscapeAssertion(string s);
	static string RemoveComments(string s);
	static bool ArrayEquals(vector<string> a, vector<string> b);
	static bool Array2DEquals(vector < vector<string>> a, vector <vector<string>> b);
	static void ArrayRemoveDuplicates(vector<string>* s);
	static string ArrayToString(vector<string> s);
	static string ParamasToString(initializer_list<string> s);
	static bool SetEquals(vector<string> a, vector<string> b);
	static vector<string> JoinSlice(string a, initializer_list<string> b);
	static void PrintVector(vector<string> v);
	static void Print2DVector(vector < vector<string>> v);
	static bool HasPrefix(string s,string b);
	static string& Trim(string& s, string b);
	static string& TrimLeft(string& s, string b);
	static string& TrimRight(string& s, string b);
};