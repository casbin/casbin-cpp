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

#include <chrono>
#include <functional>
#include <future>
#include <mutex>

namespace casbin {

class Ticker {
public:
    typedef std::chrono::duration<int64_t, std::nano> tick_interval_t;
    typedef std::function<void()> on_tick_t;
    typedef std::vector<std::future<void>> future_vec;

    Ticker(std::function<void()> onTick, std::chrono::duration<int64_t, std::nano> tickInterval);

    ~Ticker();

    void start();

    void stop();

private:
    void timer_loop();
    on_tick_t _onTick;
    tick_interval_t _tickInterval;
    std::atomic_bool _running;
    std::mutex _tickIntervalMutex;
    future_vec _futures1;
    future_vec _futures2;
};

}; // namespace casbin

#endif // TICKER_H
