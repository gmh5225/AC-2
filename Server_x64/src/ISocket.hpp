#pragma once

#include <cstdint>

class ISocket {
public:
	virtual int send(const char* buffer, int len, int flags) = 0;
	virtual int recv(char* buffer, int len, int flags) = 0;
	virtual ~ISocket() {}
};