#pragma once
#include <shared_mutex>
#include <chrono>
#include <thread>
#include "enforcer.h"

using namespace std;

class SyncedEnforcer: private Enforcer {
	mutable shared_mutex m;
	bool autoLoadRunning = false;
public:
	SyncedEnforcer(string);
	SyncedEnforcer(string, string);
	SyncedEnforcer(string, Adapter*);
	void startAutoLoadPolicy(int);
};