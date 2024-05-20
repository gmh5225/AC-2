#include "Packet.hpp"
#include "../openssl/AES.hpp"

std::optional<CPacket> CPacket::recv(ISocket* client, std::vector<unsigned char>& aesKey) {
	PacketHeader header;
	if (client->recv(reinterpret_cast<char*>(&header), sizeof(PacketHeader), 0) == SOCK_ERROR)
		return std::nullopt;

	//Receive payload without fragmentation
	if (header.flags.isByteSize) {
		std::vector<unsigned char> payload(header.payloadSize.packed);
		if (client->recv((char*)payload.data(), header.payloadSize.packed, 0) == SOCK_ERROR)
			return std::nullopt;

		//Decrypt payload if encryption context is provided
		if (header.flags.isPayloadEncrypted && !AESGCM::decrypt(payload, aesKey))
			return std::nullopt;

		return CPacket(header, payload);
	}

	//Receive payload with fragmentation in 4KByte chunks
	std::size_t payloadByteSize = (header.payloadSize.kilobytes * KBYTE_SIZE) + header.payloadSize.bytes;
	std::vector<unsigned char> payload(payloadByteSize);
	std::size_t fragmentChunkCount = payloadByteSize / PAYLOAD_FRAGMENT_SIZE;

	for (std::size_t i = 0; i < fragmentChunkCount; i++) {
		if (client->recv((char*)payload.data() + i * PAYLOAD_FRAGMENT_SIZE, PAYLOAD_FRAGMENT_SIZE, 0) == SOCK_ERROR)
			return std::nullopt;

		payloadByteSize -= PAYLOAD_FRAGMENT_SIZE;
	}

	//Check if there is any remaining payload data
	if (payloadByteSize > 0) {
		if (client->recv((char*)payload.data() + fragmentChunkCount * PAYLOAD_FRAGMENT_SIZE, (int)payloadByteSize, 0) == SOCK_ERROR)
			return std::nullopt;
	}

	//Decrypt payload if encryption context is provided
	if (header.flags.isPayloadEncrypted && !AESGCM::decrypt(payload, aesKey))
		return std::nullopt;

	return CPacket(header, payload);
}

bool CPacket::send(ISocket* client, PacketType type, std::vector<unsigned char>& payload, std::vector<unsigned char>& aesKey) {
	PacketHeader header = {};
	header.flags.isByteSize = payload.size() < PAYLOAD_FRAGMENT_SIZE;
	header.flags.isPayloadEncrypted = aesKey.size() > 0;
	header.type = type;
	auto copyPayload = header.flags.isPayloadEncrypted ? std::vector<unsigned char>(payload) : payload;

	//Encrypt payload if encryption context is provided
	if (header.flags.isPayloadEncrypted && !AESGCM::encrypt(copyPayload, aesKey))
		return false;

	if (!header.flags.isByteSize) {
		header.payloadSize.kilobytes = static_cast<std::uint32_t>(copyPayload.size() / KBYTE_SIZE);
		header.payloadSize.bytes = static_cast<std::uint32_t>(copyPayload.size() % KBYTE_SIZE);
	}
	else {
		header.payloadSize.packed = static_cast<std::uint32_t>(copyPayload.size());
	}

	//Send header
	if (client->send(reinterpret_cast<const char*>(&header), sizeof(PacketHeader), 0) == SOCK_ERROR)
		return false;

	//Send payload without fragmentation
	if (header.flags.isByteSize)
		return client->send((const char*)copyPayload.data(), static_cast<int>(copyPayload.size()), 0) != SOCK_ERROR;

	//Send payload with fragmentation in 4KByte chunks
	std::size_t payloadByteSize = copyPayload.size();
	std::size_t fragmentChunkCount = payloadByteSize / PAYLOAD_FRAGMENT_SIZE;

	for (std::size_t i = 0; i < fragmentChunkCount; i++) {
		if (client->send((const char*)(copyPayload.data() + i * PAYLOAD_FRAGMENT_SIZE), PAYLOAD_FRAGMENT_SIZE, 0) == SOCK_ERROR)
			return false;

		payloadByteSize -= PAYLOAD_FRAGMENT_SIZE;
	}

	//Check if there is any remaining payload data
	if (payloadByteSize > 0) {
		if (client->send((const char*)(copyPayload.data() + fragmentChunkCount * PAYLOAD_FRAGMENT_SIZE), (int)payloadByteSize, 0) == SOCK_ERROR)
			return false;
	}

	return true;
}