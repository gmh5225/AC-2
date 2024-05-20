#include "gtest/gtest.h"
#include <iostream>
#include <functional>
#include <thread>
#include <memory>
#include <CThreadPool.hpp>
#include <CTCPServer.hpp>

//TEST(CThreadPoolTest, CreatePoolRunTasks) {
//
//	constexpr auto NUM_THREADS = 4U;
//	constexpr auto NUM_TASKS = NUM_THREADS * 5;
//
//	bool taskFlags[NUM_TASKS];
//	for (auto i = 0U; i < NUM_TASKS; i++) {
//		taskFlags[i] = false;
//	}
//
//	//Create threadpool
//	auto pool = std::make_shared<CThreadPool>(NUM_THREADS);
//	
//	for (auto i = 0U; i < NUM_TASKS; i++) {
//		pool->addTask([i, &taskFlags] {
//			taskFlags[i] = true;
//		});
//	}
//
//	std::this_thread::sleep_for(std::chrono::milliseconds(250));
//
//	//Check if all tasks have been executed
//	for (auto i = 0U; i < NUM_TASKS; i++) {
//		ASSERT_TRUE(taskFlags[i]);
//	}
//
//	//Reset flags
//	for (auto i = 0U; i < NUM_TASKS; i++) {
//		pool->addTask([i, &taskFlags] {
//			taskFlags[i] = false;
//		});
//	}
//
//	std::this_thread::sleep_for(std::chrono::milliseconds(250));
//
//	//Check if all tasks have been executed
//	for (auto i = 0U; i < NUM_TASKS; i++) {
//		ASSERT_FALSE(taskFlags[i]);
//	}
//}

constexpr auto SERVER_PORT = 8080U;

TEST(CTCPServerTest, CreateServer) {
	//const auto processorCount = std::thread::hardware_concurrency();
	auto tcpServer = std::make_shared<CTCPServer>(SERVER_PORT, 4, 20);
	ASSERT_TRUE(tcpServer->start());
	ASSERT_TRUE(tcpServer->isRunning());

	tcpServer->stop();
	ASSERT_FALSE(tcpServer->isRunning());
}