/*
 * Copyright 2020 The casbin Authors. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TICKER_H
#define TICKER_H

#include <cstdint>
#include <functional>
#include <chrono>
#include <vector>
#include <thread>
#include <future>
#include <condition_variable>
#include <iostream>
#include <mutex>

using namespace std;

class Ticker {
public:
    typedef chrono::duration<int64_t, nano> tick_interval_t;
    typedef function<void()> on_tick_t;
    typedef vector<future<void>> future_vec;

    Ticker(function<void()> onTick, chrono::duration<int64_t, nano> tickInterval);
    
    ~Ticker();

    void start();

    void stop();

private:
    void timer_loop();
    on_tick_t           _onTick;
    tick_interval_t     _tickInterval;
    atomic_bool    _running;
    mutex          _tickIntervalMutex;
    future_vec          _futures1;
    future_vec          _futures2;
};

#endif // TICKER_H
