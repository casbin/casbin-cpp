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