#pragma once

#include <string>
using namespace std;
class Logger {
public:

	virtual void SetEnable(bool enabled);
	virtual bool IsEnable();

	template <typename... Object>
	void Printf(string s, Object... objects);

	template <typename... Object>
	void Print(Object... objects);
};