#include "CTCPServerSocket.hpp"

int CTCPServerSocket::send(const char* buffer, int len, int flags) {
    const auto sz = boost::asio::write(m_Socket, boost::asio::buffer(buffer, len));
    if (sz <= 0)
        return SOCKET_ERROR;  // Error or connection closed

    return static_cast<int>(sz);
}

int CTCPServerSocket::recv(char* buffer, int len, int flags) {
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