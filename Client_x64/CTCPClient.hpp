#pragma once

#include <memory>
#include "ISocket.hpp"

class CTCPClient : public ISocket
{
	SOCKET m_Socket;
	bool m_IsConnected;

public:

	CTCPClient();
	~CTCPClient();

	SOCKET getSocket() override { return m_Socket; }
	bool connectByIp(const char* ip, int port);
	bool connectByDomain(const char* domain, int port);
	int send(const char* buffer, int len, int flags) override;
	int recv(char* buffer, int len, int flags) override;
	bool isConnected() const { return m_IsConnected; }
	void disconnect();

};