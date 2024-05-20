#include <Windows.h>
#include "CController.hpp"
#include "Game.hpp"
#include "Defines.hpp"

__declspec(dllexport) StatusCode initialize(const GAME_DATA& gameData) {
	const auto controller = CController::getInstance(gameData);
	if (!controller) 
		return StatusCode::INITIALIZATION_ERROR_UNKNOWN;

	//Connect to remote server
	if (!controller->connectToServer()) 
		return StatusCode::INITIALIZATION_ERROR_CONNECTION;

	//Create controller handler thread
	if (!controller->startHandlerThread()) 
		return StatusCode::INITIALIZATION_ERROR_UNKNOWN;

	return StatusCode::OK;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
	switch (dwReason)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}

	return TRUE;
}