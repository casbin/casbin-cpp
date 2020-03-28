#pragma once

#include <string>
#include <map>
using namespace std;

//We use string as *Assertion in Go' version temporarily
typedef string Assertion;
typedef map <string, Assertion> AssertionMap;
typedef map <string, AssertionMap> Model;