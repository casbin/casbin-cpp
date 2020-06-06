#ifndef CASBIN_CPP_UTIL__IS_INSTANCE_OF
#define CASBIN_CPP_UTIL_IS_INSTANCE_OF

#include <iostream>

using namespace std;

template<typename Base, typename T>
bool IsInstanceOf(const T*) {
   return is_base_of<Base, T>::value;
}

#endif