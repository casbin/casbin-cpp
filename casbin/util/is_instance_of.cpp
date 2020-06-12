#pragma once

#include "pch.h"

#include "./util.h"
#include "../persist/watcher_ex.h"

using namespace std;

template<typename Base, typename T>
bool IsInstanceOf(const T*) {
   return is_base_of<Base, T>::value;
}

template bool IsInstanceOf<class WatcherEx, class Watcher>(class Watcher const*);