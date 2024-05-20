#pragma once

#include <iostream>
#include <string>

union ConnectionFlags {
	std::uint8_t packed;
	struct {
		std::uint8_t isDomain : 1;
		std::uint8_t reserved : 7;
	};
};

typedef struct {
	int port;
	std::string addr; //Either IPv4, IpV6 or domain
	ConnectionFlags flags;
}GAME_SOCKET_TCP;

typedef struct {
	GAME_SOCKET_TCP connection;
	std::string name;
	std::string version;
} GAME_DATA, *PGAME_DATA;