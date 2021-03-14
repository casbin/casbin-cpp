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

#include "pch.h"

#ifndef TICKER_CPP
#define TICKER_CPP

#include "./ticker.h"

Ticker::Ticker(std::function<void()> onTick, std::chrono::duration<int64_t, std::nano> tickInterval)
    : _onTick (onTick)
    , _tickInterval (tickInterval)
    , _running (false) {}

Ticker::~Ticker () {
    stop();
}

void Ticker::start() {
    if (_running) return;
    _running = true;
    _futures1.push_back(std::async(std::launch::async, &Ticker::timer_loop, this));
}

void Ticker::stop() { 
    _running = false; 
}

void Ticker::setDuration(std::chrono::duration<int64_t, std::nano> tickInterval) {
    std::lock_guard<std::mutex> lock(_tickIntervalMutex);
    _tickInterval = tickInterval;
}

void Ticker::timer_loop()
{
    while (_running) {
        _futures2.push_back(std::async(std::launch::async, _onTick));
        {
            std::lock_guard<std::mutex> lock(_tickIntervalMutex);
            tick_interval_t tickInterval = _tickInterval;
            std::this_thread::sleep_for( tickInterval );
        }
    }
}
// int main()
// {
//     std::chrono::duration<int, std::milli> timer_duration1(1000);
//     std::chrono::duration<int, std::milli> timer_duration2(500);
//     std::chrono::duration<int> main_wait(5);
//     std::chrono::duration<int> main_wait2(6);

//     Ticker ticker(std::function<void()>(tick), timer_duration1);
//     ticker.start();

//     std::this_thread::sleep_for(main_wait);
//     ticker.setDuration(timer_duration2);
//     std::this_thread::sleep_for(main_wait2);
//     ticker.stop();
// }

#endif // TICKER_CPP