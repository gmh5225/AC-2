#pragma once

#include <vector>
#include <thread>
#include <iostream>
#include <functional>
#include <queue>
#include <mutex>
#include <condition_variable>

class CThreadPool {

    std::vector<std::thread> m_Threads;
    std::queue<std::function<void()>> m_Tasks;
    std::mutex m_Mutex;
    std::condition_variable m_Condition;
    bool m_Stop;

public:

    CThreadPool(std::size_t numThreads);
    ~CThreadPool();

    template<typename F, typename... Args>
    void addTask(F&& f, Args&&... args) {
        {
            std::unique_lock<std::mutex> lock(m_Mutex);
            m_Tasks.emplace([=]() { f(args...); });
        }
        m_Condition.notify_one();
    }

    void stopAllThreads();
};