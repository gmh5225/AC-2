#pragma once

#include <string>
#include <vector>

//Needs to be specified by the game developer
using ClientGUID = std::string;

//Struct for storing aes key and rsa public key
typedef struct {
	std::vector<unsigned char> aesKey;
	std::string rsaKey; //Either public (client) or private key (server)
} ENCRYPTION_CONTEXT, *PENCRYPTION_CONTEXT;

constexpr auto SOCK_ERROR = -1;

typedef struct {
	std::uint32_t tcpPort;
	std::uint16_t guidSize;
}SERVER_INITIALIZE, *PSERVER_INITIALIZE;