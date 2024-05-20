#include <iostream>
#include <functional>
#include <memory>
#include "Packet.hpp"
#include "CController.hpp"
#include "WinAPI.hpp"
#include "CPacketQueue.hpp"
#include "ClientHandler.hpp"

std::shared_ptr<CController> CController::m_Instance;
std::once_flag CController::m_OnlyOneFlag;

CController::CController(const GAME_DATA& gameData)
	: m_GameData(gameData), m_HandlerThread(INVALID_HANDLE_VALUE), m_ShouldRunHandler(false)
{
	CSyscall::getInstance();
}

CController::~CController()
{
	if (m_SocketClient && m_SocketClient.get())
		m_SocketClient->disconnect();

	if (m_HandlerThread != INVALID_HANDLE_VALUE) {
		WinAPI::TerminateThread(m_HandlerThread);
		WinAPI::CloseHandle(m_HandlerThread);
	}
}

bool CController::connectToServer()
{
	if (m_SocketClient && m_SocketClient.get() && m_SocketClient->isConnected())
		return true;

	m_SocketClient = std::make_shared<CTCPClient>();
	if (!m_SocketClient || !m_SocketClient.get())
		return false;

	if (m_GameData.connection.flags.isDomain) {
		return m_SocketClient->connectByDomain(
			m_GameData.connection.addr.c_str(), 
			m_GameData.connection.port);
	} else {
		return m_SocketClient->connectByIp(
			m_GameData.connection.addr.c_str(), 
			m_GameData.connection.port);
	}
}

bool CController::startHandlerThread()
{
	if (!m_SocketClient || !m_SocketClient.get() 
		|| !m_SocketClient->isConnected() || m_HandlerThread != INVALID_HANDLE_VALUE)
		return false;

	const auto result = WinAPI::CreateThread(
		&CController::handler, 
		nullptr, 
		THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER);

	if (!NT_SUCCESS(result.first) || result.second == INVALID_HANDLE_VALUE)
		return false;

	m_HandlerThread = result.second;
	m_ShouldRunHandler = true;
	return true;
}

void CController::handler()
{
	const auto controller = CController::getInstance();
	const auto packetHandler = std::make_shared<CPacketQueue>();

	//Handle authentication
	ClientHandler::handleAuthInit(controller->m_SocketClient.get(), &controller->m_EncryptionCtx);

	while (controller->m_ShouldRunHandler) {
		//Handle incoming requests from remote server
		auto recvPacket = CPacket::recv(controller->m_SocketClient.get());

		if (!recvPacket.has_value()) {
			//Handle packet error (?)
			continue;
		}

		//Handle packet type
		switch (recvPacket.value().getHeader().type) {
			case PacketType::STATUS:
				break;
			case PacketType::EXECUTE_MODULE:
				break;
			default:
				break;
		}

	}
}