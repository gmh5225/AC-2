#pragma once

#include <iostream>
#include <Windows.h>
#include "ntdll.hpp"
#include "String.hpp"
#include "PEFile.hpp"

namespace Peb
{
	__forceinline HMODULE GetModHandle(std::uint32_t ModuleHash)
	{
#ifdef _WIN64
		const auto pPeb = reinterpret_cast<PPEB>(__readgsqword(0x60));
#else
		const auto pPeb = reinterpret_cast<PPEB>(__readfsdword(0x30));
#endif
		const auto pListHead = &pPeb->Ldr->InMemoryOrderModuleList;
		for (auto pListCurrent = pListHead; pListCurrent != pListHead->Blink; pListCurrent = pListCurrent->Flink)
		{
			const auto pModule =
				reinterpret_cast<ntdll::PLDR_DATA_TABLE_ENTRY_>(CONTAINING_RECORD(pListCurrent->Flink, ntdll::LDR_DATA_TABLE_ENTRY_, InMemoryOrderLinks));

			if (!ModuleHash)
				return reinterpret_cast<HMODULE>(pModule->DllBase);

			auto wModule = std::wstring(pModule->BaseDllName.Buffer);
			if (String::HashW(String::LowerW(wModule).c_str()) == ModuleHash
				|| String::HashW(String::UpperW(wModule).c_str()) == ModuleHash)
				return reinterpret_cast<HMODULE>(pModule->DllBase);
		}

		return nullptr;
	}

	__forceinline std::unordered_map<std::uint32_t, void*> getExportedRoutines(HMODULE hModule)
	{
		std::unordered_map<std::uint32_t, void*> exportedRoutines;
		PEFile pe(reinterpret_cast<std::uint8_t*>(hModule));
		const auto pExportDescriptor = pe.GetExportDir();
		const auto pOffsetArray = reinterpret_cast<PDWORD>(pe.GetImageBase() + pExportDescriptor->AddressOfFunctions);
		const auto pNameArray = reinterpret_cast<PDWORD>(pe.GetImageBase() + pExportDescriptor->AddressOfNames);
		const auto pOrdinalArrray = reinterpret_cast<PWORD>(pe.GetImageBase() + pExportDescriptor->AddressOfNameOrdinals);

		for (std::uint32_t i = 0; i < pExportDescriptor->NumberOfNames; i++)
		{
			const auto szCurrentExport = reinterpret_cast<char*>(pe.GetImageBase() + pNameArray[i]);
			const auto pExport = reinterpret_cast<std::uint64_t*>(pe.GetImageBase() + pOffsetArray[pOrdinalArrray[i]]);

			if (pOffsetArray[pOrdinalArrray[i]] > pe.GetOptHeader()->DataDirectory[0].VirtualAddress
				&& pOffsetArray[pOrdinalArrray[i]] < pe.GetOptHeader()->DataDirectory[0].VirtualAddress + pe.GetOptHeader()->DataDirectory[0].Size)
				continue;

			exportedRoutines.insert(std::make_pair(String::HashA(szCurrentExport), pExport));
		}

		return exportedRoutines;
	}

	__forceinline void* GetExportedRoutine(HMODULE hModule, std::uint32_t ExportHash, bool IsOrdinal)
	{
		PEFile pe(reinterpret_cast<std::uint8_t*>(hModule));
		const auto pExportDescriptor = pe.GetExportDir();
		const auto pOffsetArray = reinterpret_cast<PDWORD>(pe.GetImageBase() + pExportDescriptor->AddressOfFunctions);
		const auto pNameArray = reinterpret_cast<PDWORD>(pe.GetImageBase() + pExportDescriptor->AddressOfNames);
		const auto pOrdinalArrray = reinterpret_cast<PWORD>(pe.GetImageBase() + pExportDescriptor->AddressOfNameOrdinals);

		if (IsOrdinal)
			return (std::uint8_t*)hModule + pOffsetArray[ExportHash - pExportDescriptor->Base];

		auto m = getExportedRoutines(hModule);
		auto it = m.find(ExportHash);

		return it != m.end() ? it->second : nullptr;
	}
}