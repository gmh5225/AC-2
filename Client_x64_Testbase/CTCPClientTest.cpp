#include <boost/asio.hpp>
#include <thread>
#include <iostream>
#include <memory>
#include "gtest/gtest.h"
#include "../Client_x64/CTCPClient.hpp"

static constexpr auto PORT = 8080;
static constexpr auto IP = "79.197.252.42";

TEST(CTCPClientTest, ConnectionTest) {
    // Start the server in a separate thread
    std::thread serverThread([]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            socket.close();
            service.stop();
        }
        catch (std::exception& e) {
            std::cerr << "Server exception: " << e.what() << std::endl;
        }
    });

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    // Test the CTCPClient's connection functionality
    auto client = std::make_shared<CTCPClient>();
    ASSERT_TRUE(client->connectByIp(IP, PORT));
    ASSERT_TRUE(client->isConnected());

    //Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();
}

TEST(CTCPClientTest, DataTransferTest) {
    // Start the server in a separate thread
    std::thread serverThread([]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            // Receive data from client
            char buffer[1024];
            size_t bytesReceived = socket.read_some(boost::asio::buffer(buffer));
            std::string receivedData(buffer, bytesReceived);

            // Echo back the received data
            boost::asio::write(socket, boost::asio::buffer(receivedData));

            socket.close();
            service.stop();
        }
        catch (std::exception& e) {
            std::cerr << "Server exception: " << e.what() << std::endl;
        }
      });

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(250));

    // Test the CTCPClient's connection functionality
    auto client = std::make_shared<CTCPClient>();
    ASSERT_TRUE(client->connectByIp(IP, PORT));
    ASSERT_TRUE(client->isConnected());

    // Data to send
    std::string testData = "Hello, server!";
    std::string receivedData;

    // Send data to the server
    client->send(testData.c_str(), testData.size(), 0);

    // Receive data from the server
    char buffer[1024];
    int bytesReceived = client->recv(buffer, sizeof(buffer), 0);
    if (bytesReceived > 0) {
        receivedData.assign(buffer, bytesReceived);
    }

    // Compare sent and received data
    ASSERT_EQ(testData, receivedData);

    // Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();
}