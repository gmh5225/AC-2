#include <iostream>
#include <vector>
#include <fstream>
#include "gtest/gtest.h"
#include "../Client_x64/CMapper.hpp"
#include "CTCPServerSocket.hpp"
#include "../Client_x64/Structs.hpp"
#include "../Client_x64/AES.hpp"
#include "../Client_x64/Packet.hpp"

typedef struct {
	bool isExecuted;
	char msg[32];
}TEST_DATA, * PTEST_DATA;

static constexpr auto DLL_PATH = "Z:\\AC\\x64\\Release\\Client_x64_Mapper_Testdll.dll";
static constexpr auto SUCCESS_MSG = "Hello from Testdll";

TEST(ModuleMapperTest, ExecuteTestDll) {
	TEST_DATA testData;
	testData.isExecuted = false;
	std::memset(testData.msg, 0, sizeof(testData.msg));

	//Read testdll into memory buffer
	std::ifstream file(DLL_PATH, std::ios::binary);
	std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
	file.close();

	if (buffer.empty()) {
		FAIL() << "Failed to read testdll into memory buffer";
	}

	auto mapper = CMapper(buffer);
	ASSERT_TRUE(mapper.mapExecute(&testData));
	ASSERT_TRUE(testData.isExecuted && std::strcmp(testData.msg, SUCCESS_MSG) == 0);
}

TEST(ModuleMapperTest, StreamAndExecuteTestDll) {
    ENCRYPTION_CONTEXT ctx = {};
    ctx.aesKey = AESGCM::generateKey(32);

    //Read testdll into memory buffer
    std::ifstream file(DLL_PATH, std::ios::binary);
    std::vector<unsigned char> buffer(std::istreambuf_iterator<char>(file), {});
    file.close();

    if (buffer.empty()) {
        FAIL() << "Failed to read testdll into memory buffer";
    }

    // Start the server in a separate thread
    std::thread serverThread([&ctx, &buffer]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            CTCPServerSocket serverSocket(std::move(socket));

            //Send testdll to client
            CPacket::send(&serverSocket, PacketType::EXECUTE_MODULE, buffer, &ctx);

            std::this_thread::sleep_for(std::chrono::milliseconds(200));

            service.stop();
        }
        catch (std::exception& e) {
            std::cerr << "Server exception: " << e.what() << std::endl;
        }
    });

    TEST_DATA testData;
    testData.isExecuted = false;
    std::memset(testData.msg, 0, sizeof(testData.msg));

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Test the CTCPClient's connection functionality
    auto client = std::make_shared<CTCPClient>();
    ASSERT_TRUE(client->connectByIp(IP, PORT));
    ASSERT_TRUE(client->isConnected());

    //Receive test dll from server
    auto packet = CPacket::recv(client.get(), &ctx);
    ASSERT_TRUE(packet.has_value());
    ASSERT_TRUE(packet->getHeader().type == PacketType::EXECUTE_MODULE);
    ASSERT_EQ(packet->getPayload(), buffer);

    //Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();

    //Execute testdll
    auto mapper = CMapper(packet->getPayload());
    ASSERT_TRUE(mapper.mapExecute(&testData));
    ASSERT_TRUE(testData.isExecuted && std::strcmp(testData.msg, SUCCESS_MSG) == 0);
}