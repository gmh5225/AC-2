#pragma once

#include "ISocket.hpp"
#include "Structs.hpp"

namespace ClientHandler
{
	void handleAuthInit(ISocket* pClientSocket, PENCRYPTION_CONTEXT pEncryptionCtx);
}