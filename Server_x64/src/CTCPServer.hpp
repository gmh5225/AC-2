#pragma once

#include <boost/asio.hpp>
#include <thread>
#include <vector>
#include <memory>
#include <unordered_map>
#include "CTCPServerSocket.hpp"
#include "CThreadPool.hpp"
#include "CClientHandler.hpp"

class CTCPServer {

    void acceptConnections();
    void handleConnections(ThreadID tid);
    void handleOnConnect(std::shared_ptr<CTCPServerSocket> clientSocket);
    bool m_Stop;
    std::uint16_t m_NumOnConnectThreads;
    std::uint16_t m_NumHandleConnectionThreads;

    boost::asio::io_service m_IOService;
    boost::asio::ip::tcp::acceptor m_Acceptor;
    std::unique_ptr<CThreadPool> m_ThreadPool;
    std::unique_ptr<CClientHandler> m_ClientHandler;

public:

    CTCPServer(boost::asio::ip::port_type port, std::uint16_t numOnConnectThreads, std::uint16_t numHandleConnectionThreads);
    ~CTCPServer();

    bool start();
    void stop();

    inline bool isRunning() const { return !m_Stop; }
};