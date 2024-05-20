#include "CClient.hpp"

CClient::CClient(std::shared_ptr<CTCPServerSocket> socket) 
    : m_Socket(socket) 
{

}