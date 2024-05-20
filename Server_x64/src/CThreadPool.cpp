#include "CThreadPool.hpp"

CThreadPool::CThreadPool(std::size_t numThreads)
    : m_Threads(numThreads), m_Stop(false)
{
    for (auto& thread : m_Threads) {
        thread = std::thread([this]() {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(m_Mutex);
                    m_Condition.wait(lock, [this]() { return m_Stop || !m_Tasks.empty(); });
                    if (m_Stop && m_Tasks.empty()) return;
                    task = std::move(m_Tasks.front());
                    m_Tasks.pop();
                }

                //Execute task
                task();
            }
        });
    }
}

CThreadPool::~CThreadPool() {
    //{
    //    std::unique_lock<std::mutex> lock(m_Mutex);
    //    m_Stop = true;
    //}

    //m_Condition.notify_all();

    //for (auto& thread : m_Threads) {
    //    if (thread.joinable()) thread.join();
    //}
}