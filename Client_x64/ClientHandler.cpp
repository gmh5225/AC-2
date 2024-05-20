#include "Packet.hpp"
#include "AES.hpp"
#include "RSA.hpp"
#include "ClientHandler.hpp"

void ClientHandler::handleAuthInit(ISocket* pClientSocket, PENCRYPTION_CONTEXT pEncryptionCtx)
{
	//Receive RSA public key
	auto packet = CPacket::recv(pClientSocket);
	if (!packet.has_value() || packet->getHeader().type != PacketType::AUTH_RSA_PUBKEY)
		return; //Further error handling (?)

	//Setup encryption context
	pEncryptionCtx->rsaPublicKey = std::string(packet->getPayload().begin(), packet->getPayload().end());
	pEncryptionCtx->aesKey = AESGCM::generateKey(AESGCM::KEY_SIZE_256);

	//Create AES key and send it encrypted with RSA public key
	auto encryptedAesKey = RSA_OSSL::encryptPublic(pEncryptionCtx->aesKey, pEncryptionCtx->rsaPublicKey);
	if (encryptedAesKey.size() <= 0)
		return; //Further error handling (?)

	CPacket::send(pClientSocket, PacketType::AUTH_AES_KEY, encryptedAesKey);
}