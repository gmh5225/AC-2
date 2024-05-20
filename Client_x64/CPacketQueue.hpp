#pragma once

#include <iostream>
#include <queue>
#include <memory>
#include <mutex>
#include "Packet.hpp"

class CPacketQueue
{
	std::queue<CPacket> m_OutPackets;
	std::queue<CPacket> m_InPackets;
	std::mutex m_OutPacketsMutex;
	std::mutex m_InPacketsMutex;

public:

	CPacketQueue() {};
	~CPacketQueue() {};

	inline void queueOutPacket(const CPacket& packet) {
		std::lock_guard<std::mutex> lock(m_OutPacketsMutex);
		m_OutPackets.push(packet);
	}

	inline auto dequeueOutPacket() -> std::optional<CPacket> {
		std::lock_guard<std::mutex> lock(m_OutPacketsMutex);
		if (m_OutPackets.empty())
			return std::nullopt;

		const auto packet = m_OutPackets.front();
		m_OutPackets.pop();
		return packet;
	}

	inline void queueInPacket(const CPacket& packet) {
		std::lock_guard<std::mutex> lock(m_InPacketsMutex);
		m_InPackets.push(packet);
	}

	inline auto dequeueInPacket() -> std::optional<CPacket> {
		std::lock_guard<std::mutex> lock(m_InPacketsMutex);
		if (m_InPackets.empty())
			return std::nullopt;

		const auto packet = m_InPackets.front();
		m_InPackets.pop();
		return packet;
	}
};