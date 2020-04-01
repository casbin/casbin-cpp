#include "enforcer_synced.h"

SyncedEnforcer::SyncedEnforcer(string modelFile) : Enforcer(modelFile) {

}

SyncedEnforcer::SyncedEnforcer(string modelFile, string policyFile) : Enforcer(modelFile, policyFile) {

}

SyncedEnforcer::SyncedEnforcer(string modelFile, Adapter* policyAdapter) : Enforcer(modelFile, policyAdapter) {

}

void SyncedEnforcer::startAutoLoadPolicy(int d) {
	if (autoLoadRunning) return;
	autoLoadRunning = true;

	thread([d]() {
		while (true)
		{
			this_thread::sleep_for(chrono::milliseconds(d));
		}
		}).detach();
}