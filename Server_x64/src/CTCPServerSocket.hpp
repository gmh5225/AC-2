#pragma once

#include <boost/asio.hpp>
#include "ISocket.hpp"

class CTCPServerSocket : public ISocket {
    boost::asio::ip::tcp::socket m_Socket;

public:

    CTCPServerSocket(boost::asio::ip::tcp::socket&& socket) : m_Socket(std::move(socket)) {}

    int send(const char* buffer, int len, int flags) override;
    int recv(char* buffer, int len, int flags) override;

    auto& getSocket() {
        return m_Socket;
    }
};