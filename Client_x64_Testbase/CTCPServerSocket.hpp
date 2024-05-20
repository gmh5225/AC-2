#pragma once

#include <boost/asio.hpp>
#include "../Client_x64/CTCPClient.hpp"
#include "../Client_x64/ISocket.hpp"

static constexpr auto PORT = 8080;
static constexpr auto IP = "79.197.252.42";

class CTCPServerSocket : public ISocket {
    boost::asio::ip::tcp::socket m_Socket;

public:

    CTCPServerSocket(boost::asio::ip::tcp::socket&& socket) : m_Socket(std::move(socket)) {}

    int send(const char* buffer, int len, int flags) override {
        int totalSent = 0;
        while (totalSent < len) {
            const auto remaining = len - totalSent;
            const auto sz = boost::asio::write(m_Socket, boost::asio::buffer(buffer + totalSent, remaining));
            if (sz <= 0)
                return SOCKET_ERROR;  // Error or connection closed
            totalSent += sz;
        }
        return totalSent;
    }

    int recv(char* buffer, int len, int flags) override {
        int totalReceived = 0;
        while (totalReceived < len) {
            const auto remaining = len - totalReceived;
            const auto sz = m_Socket.read_some(boost::asio::mutable_buffer(buffer + totalReceived, remaining));
            if (sz <= 0)
                return SOCKET_ERROR;  // Error or connection closed
            totalReceived += sz;
        }
        return totalReceived;
    }

    SOCKET getSocket() override {
        return m_Socket.native_handle();
    }
};