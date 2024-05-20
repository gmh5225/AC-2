#pragma once

#include <iostream>
#include <vector>
#include <optional>
#include "ISocket.hpp"
#include "Structs.hpp"

//Fragment size for payload in kbyte range
constexpr auto PAYLOAD_FRAGMENT_SIZE = 4096;

constexpr auto KBYTE_SIZE = 1024U;

enum class PacketType : std::uint8_t {
	AUTH_RSA_PUBKEY,
	AUTH_AES_KEY,
	STATUS,
	EXECUTE_MODULE
};

#pragma pack(push, 1)
union PacketFlags {
	std::uint8_t packed;
	struct {
		std::uint8_t isByteSize : 1; //Either byte or kbyte is specified by size in packet header
		std::uint8_t isPayloadEncrypted : 1;
		std::uint8_t reserved : 6;
	};
};
#pragma pack(pop)

#pragma pack(push, 1)
union PayloadSize {
	struct {
		std::uint32_t bytes : 10;   // 10 bits for bytes
		std::uint32_t kilobytes : 22;  // 22 bits for kilobytes
	};
	std::uint32_t packed;  // Combined 32-bit unsigned integer
};
#pragma pack(pop)

#pragma pack(push, 1)
struct PacketHeader {
	PacketType type;
	PacketFlags flags;
	PayloadSize payloadSize;
};
#pragma pack(pop)

class CPacket {

	PacketHeader m_Header;
	std::vector<unsigned char> m_Payload;

	CPacket(PacketHeader header, const std::vector<unsigned char>& payload)
		: m_Header(header), m_Payload(payload) {}

public:

	CPacket() : m_Header({}), m_Payload({}) {};

	inline auto getHeader() const -> const PacketHeader& {
		return m_Header;
	}

	inline auto getPayload() const -> const std::vector<unsigned char>& {
		return m_Payload;
	}

	static bool send(ISocket* client, PacketType type, std::vector<unsigned char>& payload, PENCRYPTION_CONTEXT pEncryptionCtx);

	static bool send(ISocket* client, PacketType type, std::vector<unsigned char>& payload) {
		return send(client, type, payload, nullptr);
	}

	static std::optional<CPacket> recv(ISocket* client, PENCRYPTION_CONTEXT pEncryptionCtx);

	static std::optional<CPacket> recv(ISocket* client) {
		return recv(client, nullptr);
	}
};