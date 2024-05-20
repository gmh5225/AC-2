#include <boost/asio.hpp>
#include <thread>
#include <iostream>
#include <memory>
#include <vector>
#include <random>
#include <fstream>
#include "gtest/gtest.h"
#include "../Client_x64/CTCPClient.hpp"
#include "../Client_x64/Packet.hpp"
#include "../Client_x64/ISocket.hpp"
#include "../Client_x64/AES.hpp"
#include "../Client_x64/Packet.hpp"
#include "CTCPServerSocket.hpp"

static constexpr auto PACKET_TYPE = PacketType::STATUS;

static std::vector<unsigned char> generateRandomBuffer(std::size_t length) {
    std::vector<unsigned char> buffer(length);

    // Use a random device to generate random numbers
    std::random_device rd;

    // Use Mersenne Twister as the random number engine
    std::mt19937 gen(rd());

    // Use uniform distribution to generate random numbers in the range [0, 255]
    std::uniform_int_distribution<unsigned short> dis(0, 255);

    // Fill the buffer with random data
    for (std::size_t i = 0; i < length; ++i) {
        buffer[i] = static_cast<unsigned char>(dis(gen));
    }

    return buffer;
}

TEST(CPacketTest, SendReceiveUncrypted) {
    // Start the server in a separate thread
    std::thread serverThread([]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            //Receive packet from client
            CTCPServerSocket serverSocket(std::move(socket));

            auto packet = CPacket::recv(&serverSocket);
            ASSERT_TRUE(packet.has_value());

            //Echo back the received packet
            std::vector<unsigned char> payload = packet->getPayload();
            CPacket::send(&serverSocket, packet->getHeader().type, payload);

            service.stop();
        }
        catch (std::exception& e) {
            std::cerr << "Server exception: " << e.what() << std::endl;
        }
    });

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Test the CTCPClient's connection functionality
    auto client = std::make_shared<CTCPClient>();
    ASSERT_TRUE(client->connectByIp(IP, PORT));
    ASSERT_TRUE(client->isConnected());

    //Send a packet
    std::vector<unsigned char> payload = { 'H', 'e', 'l', 'l', 'o' };
    ASSERT_TRUE(CPacket::send(client.get(), PACKET_TYPE, payload));

    //Receive a packet
    auto packet = CPacket::recv(client.get());
    ASSERT_TRUE(packet.has_value());

    ASSERT_EQ(packet->getHeader().type, PACKET_TYPE);
    ASSERT_EQ(packet->getPayload(), payload);

    //Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();
}

TEST(CPacketTest, SendReceiveEnncrypted) {
    ENCRYPTION_CONTEXT ctx = {};
    ctx.aesKey = AESGCM::generateKey(32);

    // Start the server in a separate thread
    std::thread serverThread([&ctx]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            //Receive packet from client
            CTCPServerSocket serverSocket(std::move(socket));

            auto packet = CPacket::recv(&serverSocket, &ctx);
            ASSERT_TRUE(packet.has_value());

            //Echo back the received packet
            std::vector<unsigned char> payload = packet->getPayload();
            CPacket::send(&serverSocket, packet->getHeader().type, payload, &ctx);

            service.stop();
        }
        catch (std::exception& e) {
            std::cerr << "Server exception: " << e.what() << std::endl;
        }
        });

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Test the CTCPClient's connection functionality
    auto client = std::make_shared<CTCPClient>();
    ASSERT_TRUE(client->connectByIp(IP, PORT));
    ASSERT_TRUE(client->isConnected());

    //Send a packet
    std::vector<unsigned char> payload = { 'H', 'e', 'l', 'l', 'o' };
    ASSERT_TRUE(CPacket::send(client.get(), PACKET_TYPE, payload, &ctx));

    //Receive a packet
    auto packet = CPacket::recv(client.get(), &ctx);
    ASSERT_TRUE(packet.has_value());

    ASSERT_EQ(packet->getHeader().type, PACKET_TYPE);
    ASSERT_EQ(packet->getPayload(), payload);

    //Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();
}
 
TEST(CPacketTest, SendReceiveLargeUnencrypted) {
    // Start the server in a separate thread
    std::thread serverThread([]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            //Receive packet from client
            CTCPServerSocket serverSocket(std::move(socket));

            auto packet = CPacket::recv(&serverSocket);
            ASSERT_TRUE(packet.has_value());

            //Echo back the received packet
            std::vector<unsigned char> payload = packet->getPayload();
            CPacket::send(&serverSocket, packet->getHeader().type, payload);

            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        catch (std::exception& e) {
            std::cerr << "Server exception: " << e.what() << std::endl;
        }
        });

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Test the CTCPClient's connection functionality
    auto client = std::make_shared<CTCPClient>();
    ASSERT_TRUE(client->connectByIp(IP, PORT));
    ASSERT_TRUE(client->isConnected());

    //Send a packet
    auto payload = generateRandomBuffer(1024 * 1024 * 2); // 2MB
    ASSERT_TRUE(CPacket::send(client.get(), PACKET_TYPE, payload));

    //Receive a packet
    auto packet = CPacket::recv(client.get());
    ASSERT_TRUE(packet.has_value());


    ASSERT_EQ(packet->getHeader().type, PACKET_TYPE);
    ASSERT_EQ(packet->getPayload(), payload);

    //Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();
}

TEST(CPacketTest, SendReceiveLargeEncrypted) {
    ENCRYPTION_CONTEXT ctx = {};
    ctx.aesKey = AESGCM::generateKey(32);

    // Start the server in a separate thread
    std::thread serverThread([&ctx]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            //Receive packet from client
            CTCPServerSocket serverSocket(std::move(socket));

            auto packet = CPacket::recv(&serverSocket, &ctx);
            ASSERT_TRUE(packet.has_value());

            //Echo back the received packet
            std::vector<unsigned char> payload = packet->getPayload();
            CPacket::send(&serverSocket, packet->getHeader().type, payload, &ctx);

            service.stop();
        }
        catch (std::exception& e) {
            std::cerr << "Server exception: " << e.what() << std::endl;
        }
     });

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Test the CTCPClient's connection functionality
    auto client = std::make_shared<CTCPClient>();
    ASSERT_TRUE(client->connectByIp(IP, PORT));
    ASSERT_TRUE(client->isConnected());

    //Send a packet
    auto payload = generateRandomBuffer(1024 * 1024 * 2); // 2MB
    ASSERT_TRUE(CPacket::send(client.get(), PACKET_TYPE, payload, &ctx));

    //Receive a packet
    auto packet = CPacket::recv(client.get(), &ctx);
    ASSERT_TRUE(packet.has_value());

    ASSERT_EQ(packet->getHeader().type, PACKET_TYPE);
    ASSERT_EQ(packet->getPayload(), payload);

    //Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();
}

constexpr auto PE_FILE_PATH = "Z:\\Dev\\Anti-Tamper\\x64\\Release\\BuilderLib.dll";

TEST(CPacketTest, SendReceivePeFileEncrypted) {
    ENCRYPTION_CONTEXT ctx = {};
    ctx.aesKey = AESGCM::generateKey(32);

    // Read file content into a buffer
    std::vector<unsigned char> fileBuffer;
    std::ifstream file(PE_FILE_PATH, std::ios::binary);
    if (file) {
        // Determine file size
        file.seekg(0, std::ios::end);
        std::size_t fileSize = file.tellg();
        file.seekg(0, std::ios::beg);

        // Resize buffer and read file content
        fileBuffer.resize(fileSize);
        file.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize);
        file.close();
    }
    else {
        // Handle file not found or other errors
        FAIL() << "Failed to open file.";
    }

    // Start the server in a separate thread
    std::thread serverThread([&ctx]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            //Receive packet from client
            CTCPServerSocket serverSocket(std::move(socket));

            auto packet = CPacket::recv(&serverSocket, &ctx);
            ASSERT_TRUE(packet.has_value());

            //Echo back the received packet
            std::vector<unsigned char> payload = packet->getPayload();
            CPacket::send(&serverSocket, packet->getHeader().type, payload, &ctx);

            service.stop();
        }
        catch (std::exception& e) {
            std::cerr << "Server exception: " << e.what() << std::endl;
        }
    });

    // Wait for the server to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Test the CTCPClient's connection functionality
    auto client = std::make_shared<CTCPClient>();
    ASSERT_TRUE(client->connectByIp(IP, PORT));
    ASSERT_TRUE(client->isConnected());

    //Send a packet
    ASSERT_TRUE(CPacket::send(client.get(), PACKET_TYPE, fileBuffer, &ctx));

    //Receive a packet
    auto packet = CPacket::recv(client.get(), &ctx);
    ASSERT_TRUE(packet.has_value());

    ASSERT_EQ(packet->getHeader().type, PACKET_TYPE);
    ASSERT_EQ(packet->getPayload(), fileBuffer);

    //Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();
}