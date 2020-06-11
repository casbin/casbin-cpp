#pragma once

#include "pch.h"

#include "./util.h"

using namespace std;

template<typename Base, typename T>
bool IsInstanceOf(const T*) {
   return is_base_of<Base, T>::value;
}