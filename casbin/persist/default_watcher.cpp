#pragma once

#include "pch.h"

#include "./default_watcher.h"

template <typename Func>
void DefaultWatcher :: SetUpdateCallback(Func func) {
    return;
}

void DefaultWatcher :: Update() {
    return;
}

void DefaultWatcher :: Close() {
    return;
}