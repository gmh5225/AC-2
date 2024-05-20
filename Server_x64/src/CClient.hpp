#pragma once

#include "CTCPServerSocket.hpp"

class CClient {

    std::shared_ptr<CTCPServerSocket> m_Socket;

public:
    
    CClient(std::shared_ptr<CTCPServerSocket> socket);
};