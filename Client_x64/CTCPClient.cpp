#include <ws2tcpip.h>
#include <string>
#include "CTCPClient.hpp"

CTCPClient::CTCPClient() : m_Socket(INVALID_SOCKET), m_IsConnected(false)
{
	WSAData wsa = {};
	WSAStartup(MAKEWORD(2, 2), &wsa);
}

CTCPClient::~CTCPClient()
{
	disconnect();
	WSACleanup();
}

bool CTCPClient::connectByIp(const char* ip, int port)
{
	if (isConnected())
		return false;

	m_Socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (m_Socket == INVALID_SOCKET)
		return false;

	sockaddr_in addr = {};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);

	if (inet_pton(AF_INET, ip, &addr.sin_addr) <= 0) {
		closesocket(m_Socket);
		m_Socket = INVALID_SOCKET;
		return false;
	}

	if (connect(m_Socket, (sockaddr*)&addr, sizeof(addr)) == SOCKET_ERROR) {
		closesocket(m_Socket);
		m_Socket = INVALID_SOCKET;
		return false;
	}

	m_IsConnected = true;
	return true;
}

bool CTCPClient::connectByDomain(const char* domain, int port)
{
	if (isConnected())
		return false;

	addrinfo hints = {};
	addrinfo* result = nullptr;

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if (getaddrinfo(domain, std::to_string(port).c_str(), &hints, &result) != 0
		|| !result)
		return false;

	for (auto p = result; p != nullptr; p = p->ai_next) {
		m_Socket = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (m_Socket == INVALID_SOCKET)
			continue;

		if (connect(m_Socket, p->ai_addr, (int)p->ai_addrlen) == SOCKET_ERROR) {
			closesocket(m_Socket);
			m_Socket = INVALID_SOCKET;
			continue;
		}

		break;
	}

	freeaddrinfo(result);
	
	if (m_Socket != INVALID_SOCKET) {
		m_IsConnected = true;
		return true;
	}
	else {
		return false;
	}
}

int CTCPClient::send(const char* buffer, int len, int flags)
{
	int totalBytesSent = 0;
	int remainingBytes = len;
	const char* p = buffer;

	while (remainingBytes > 0) {
		int bytesSent = ::send(m_Socket, p, remainingBytes, flags);
		if (bytesSent == SOCKET_ERROR)
			return SOCKET_ERROR;

		remainingBytes -= bytesSent;
		p += bytesSent;
		totalBytesSent += bytesSent;
	}

	return totalBytesSent;
}

int CTCPClient::recv(char* buffer, int len, int flags)
{
	int totalBytesReceived = 0;
	int remainingBytes = len;
	char* p = buffer;

	while (remainingBytes > 0) {
		int bytesReceived = ::recv(m_Socket, p, remainingBytes, flags);
		if (bytesReceived == SOCKET_ERROR)
			return SOCKET_ERROR;
		
		if (bytesReceived == 0)
			break; // Connection closed gracefully by the peer -> Error handling???

		remainingBytes -= bytesReceived;
		p += bytesReceived;
		totalBytesReceived += bytesReceived;
	}

	return totalBytesReceived;
}

void CTCPClient::disconnect()
{
	if (m_Socket != INVALID_SOCKET) {
		closesocket(m_Socket);
		m_Socket = INVALID_SOCKET;
		m_IsConnected = false;
	}
}