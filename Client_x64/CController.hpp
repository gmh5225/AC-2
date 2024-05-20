#pragma once

#include "CSyscall.hpp"
#include "String.hpp"
#include "Game.hpp"
#include "Structs.hpp"
#include "CTCPClient.hpp"

class CController
{
	static std::shared_ptr<CController> m_Instance;
	static std::once_flag m_OnlyOneFlag;

	GAME_DATA m_GameData;
	ENCRYPTION_CONTEXT m_EncryptionCtx;
	std::shared_ptr<CTCPClient> m_SocketClient;
	HANDLE m_HandlerThread;
	bool m_ShouldRunHandler;

	void operator=(const CController&) = delete;
	CController(const CController&) = delete;
	CController(const GAME_DATA& gameData);

	static void handler();

public:

	~CController();

	__forceinline static auto getInstance()
	{
		return m_Instance.get();
	}

	__forceinline static auto getInstance(const GAME_DATA& gameData)
	{
		std::call_once(m_OnlyOneFlag, [&gameData]() { m_Instance.reset(new CController(gameData)); });
		return m_Instance.get();
	}

	bool connectToServer();
	bool startHandlerThread();

};