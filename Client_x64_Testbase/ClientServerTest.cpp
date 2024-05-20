#include <iostream>
#include <vector>
#include "gtest/gtest.h"
#include "CTCPServerSocket.hpp"
#include "../Client_x64/Packet.hpp"
#include "../Client_x64/ClientHandler.hpp"
#include "../Client_x64/RSA.hpp"

//Test the handleAuthInit function (RSA and AES key exchange)
TEST(ClientServerTest, HandleAuthInit) {

    ENCRYPTION_CONTEXT serverCtx = {};

    // Start the server in a separate thread
    std::thread serverThread([&serverCtx]() {
        try {
            boost::asio::io_service service;
            boost::asio::ip::tcp::acceptor acceptor(service, boost::asio::ip::tcp::endpoint(boost::asio::ip::tcp::v4(), PORT));
            boost::asio::ip::tcp::socket socket(service);
            acceptor.accept(socket);

            //Generate RSA key pair
            auto keyPair = RSA_OSSL::generateKeyPair(2048);
            ASSERT_TRUE(keyPair.has_value());

            serverCtx.rsaPublicKey = keyPair->pubKey;

            CTCPServerSocket serverSocket(std::move(socket));

            //Send first auth packet to client by sending the RSA public key
            std::vector<unsigned char> rsaPubKey(keyPair->pubKey.begin(), keyPair->pubKey.end());
            ASSERT_TRUE(CPacket::send(&serverSocket, PacketType::AUTH_RSA_PUBKEY, rsaPubKey));

            //Receive auth response from client (the encrypted aes key)
            auto packet = CPacket::recv(&serverSocket);
            ASSERT_TRUE(packet.has_value());

            //Decrypt and store the aes key
            serverCtx.aesKey = RSA_OSSL::decryptPrivate(packet->getPayload(), keyPair->privKey);
            serverCtx.aesKey.resize(32);
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

    ENCRYPTION_CONTEXT ctx = {};
    ClientHandler::handleAuthInit(client.get(), &ctx);

    // Wait for the server to finish
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    //Compare the aes keys
    ASSERT_EQ(ctx.aesKey, serverCtx.aesKey);

    //Disconnect the client
    client->disconnect();
    ASSERT_FALSE(client->isConnected());

    // Join the server thread
    serverThread.join();
}