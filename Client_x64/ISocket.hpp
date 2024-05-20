#pragma once

typedef unsigned __int64 SOCKET;

class ISocket {

public:
	virtual SOCKET getSocket() = 0;
	virtual int send(const char* buffer, int len, int flags) = 0;
	virtual int recv(char* buffer, int len, int flags) = 0;
	virtual ~ISocket() {}
};