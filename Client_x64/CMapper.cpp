#include <Windows.h>
#include <iostream>
#include <algorithm>
#include "CMapper.hpp"
#include "PEFile.hpp"
#include "WinAPI.hpp"
#include "ntdll.hpp"
#include "Memory.hpp"
#include "PEB.hpp"
#include "String.hpp"

CMapper::~CMapper()
{
}

bool CMapper::mapExecute(void* lpReserved)
{
	using fn_LoadLibraryA = HMODULE(WINAPI*)(LPCSTR lpLibFileName);
	using fn_GetProcAddress = FARPROC(WINAPI*)(HMODULE hModule, LPCSTR lpProcName);

	//Resolve LoadLibraryA and GetProcAddress
	const auto hKernel32 = Peb::GetModHandle(String::HashA("kernel32.dll"));
	if (!hKernel32) return false;
	auto pLoadLibraryA = reinterpret_cast<fn_LoadLibraryA>(Peb::GetExportedRoutine(hKernel32, String::HashA("LoadLibraryA"), false));
	auto pGetProcAddress = reinterpret_cast<fn_GetProcAddress>(Peb::GetExportedRoutine(hKernel32, String::HashA("GetProcAddress"), false));

	PEFile pe(m_PeBuffer);
	const auto peSections = pe.getSections();
	auto peBuffer = m_PeBuffer;
	
	//Allocate memory for pe
	PVOID imageBase = nullptr;
	SIZE_T regionSize = pe.getImageSize();
	NTSTATUS status = ntdll::STATUS_UNSUCCESSFUL;

	status = WinAPI::VirtualAlloc(NtCurrentProcess, &imageBase, &regionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (status != ntdll::STATUS_SUCCESS || !imageBase) return false;

	//Map sections
	std::for_each(peSections.begin(), peSections.end(), [&imageBase, &peBuffer](const IMAGE_SECTION_HEADER& section) {
		Memory::memcpy((PVOID)((std::uint8_t*)imageBase + section.VirtualAddress), (PVOID)(peBuffer + section.PointerToRawData), section.SizeOfRawData);
	});

	//Perform relocations

	const auto relocationRVA = pe.GetOptHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	const auto relocationSize = pe.GetOptHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	if (!relocationRVA || !relocationSize) {
		WinAPI::VirtualFree(NtCurrentProcess, &imageBase, &regionSize, MEM_RELEASE);
		return false;
	}

	const auto deltaImageBase = (std::uint64_t)imageBase - pe.GetOptHeader()->ImageBase;

	//Iterate relocation blocks (each block contains a set of relocations for a specific 4k page)
	for (auto currRelocation = (PIMAGE_BASE_RELOCATION)((std::uint8_t*)imageBase + relocationRVA);
		currRelocation->VirtualAddress; currRelocation = (PIMAGE_BASE_RELOCATION)((std::uint8_t*)currRelocation + currRelocation->SizeOfBlock))
	{
		const auto numRelocations = (currRelocation->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);
		auto relocationData = (std::uint16_t*)((std::uint8_t*)currRelocation + sizeof(IMAGE_BASE_RELOCATION));

		//Iterate relocation entries
		for (auto i = 0U; i < numRelocations; i++)
		{
			//Get reloc data entry for current block
			const auto type = relocationData[i] >> 12;
			const auto offset = relocationData[i] & 0xFFF;

			if (type == IMAGE_REL_BASED_DIR64)
			{
				//Patch target
				auto relocationTarget = (std::uint64_t*)((std::uint8_t*)imageBase + currRelocation->VirtualAddress + offset);
				*relocationTarget += deltaImageBase;
			}
		}
	}

	//Resolve imports

	const auto iatRVA = pe.GetOptHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	const auto iatSize = pe.GetOptHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	if (!iatRVA || !iatSize) {
		WinAPI::VirtualFree(NtCurrentProcess, &imageBase, &regionSize, MEM_RELEASE);
		return false;
	}

	const auto pImportDirectory = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>(((std::uint8_t*)imageBase + iatRVA));
	for (auto currImportDesc = pImportDirectory; currImportDesc->Name; currImportDesc++) {

		//Get name of imported DLL
		const auto szDllName = reinterpret_cast<const char*>((std::uint8_t*)imageBase + currImportDesc->Name);
		auto currThunkRef = reinterpret_cast<PIMAGE_THUNK_DATA>((std::uint8_t*)imageBase + currImportDesc->OriginalFirstThunk);
		auto currFuncRef = reinterpret_cast<std::uint64_t*>((std::uint8_t*)imageBase + currImportDesc->FirstThunk);

			//Iterate through the thunk data
		for (; currThunkRef->u1.AddressOfData; currThunkRef++, currFuncRef++)
		{
			//Get name of imported function
			const auto pImportByName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((std::uint8_t*)imageBase + currThunkRef->u1.AddressOfData);
			const auto szFuncName = reinterpret_cast<const char*>(pImportByName->Name);

			auto hModule = Peb::GetModHandle(String::HashA(szDllName));
			if (!hModule && !(hModule = pLoadLibraryA(szDllName))) {
				WinAPI::VirtualFree(NtCurrentProcess, &imageBase, &regionSize, MEM_RELEASE);
				return false;
			}

			void* pFuncAddr = nullptr;
			if (currThunkRef->u1.Ordinal & IMAGE_ORDINAL_FLAG64) {
				pFuncAddr = Peb::GetExportedRoutine(hModule, IMAGE_ORDINAL(currThunkRef->u1.Ordinal), true);
			}
			else {
				pFuncAddr = Peb::GetExportedRoutine(hModule, String::HashA(szFuncName), false);
			}

			//Import could not be resolved
			if (!pFuncAddr && !(pFuncAddr = pGetProcAddress(hModule, szDllName))) {
				WinAPI::VirtualFree(NtCurrentProcess, &imageBase, &regionSize, MEM_RELEASE);
				return false;
			}

			//Patch IAT
			*currFuncRef = reinterpret_cast<std::uint64_t>(pFuncAddr);
		}
	}

	//Adjust page permissions
	std::for_each(peSections.begin(), peSections.end(), [&imageBase](const IMAGE_SECTION_HEADER& section) {
		DWORD protect = 0;
		if (section.Characteristics & IMAGE_SCN_MEM_EXECUTE) {
			if (section.Characteristics & IMAGE_SCN_MEM_READ) protect = PAGE_EXECUTE_READ;
			else if (section.Characteristics & IMAGE_SCN_MEM_WRITE) protect = PAGE_EXECUTE_READWRITE;
		}
		else {
			if (section.Characteristics & IMAGE_SCN_MEM_WRITE) protect = PAGE_READWRITE;
			else if (section.Characteristics & IMAGE_SCN_MEM_READ) protect = PAGE_READONLY;
		}

		auto pPage = reinterpret_cast<PVOID>((std::uint8_t*)imageBase + section.VirtualAddress);
		SIZE_T size = section.Misc.VirtualSize;
		ULONG old = 0;

		WinAPI::VirtualProtect(NtCurrentProcess, 
			&pPage,
			&size, protect, &old);
	});

	//Execute TLS callbacks
	if (pe.GetOptHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size) {
		const auto pTlsDir = reinterpret_cast<PIMAGE_TLS_DIRECTORY>((std::uint8_t*)imageBase + pe.GetOptHeader()->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		const auto pCallback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pTlsDir->AddressOfCallBacks);

		for (auto i = 0; pCallback && pCallback[i]; i++)
			pCallback[i](imageBase, DLL_PROCESS_ATTACH, nullptr);
	}

	m_ImageBase = imageBase;

	//Call entry point
	using fnDllMain = BOOL(APIENTRY*)(HMODULE, DWORD, LPVOID);
	const auto pEntryPoint = reinterpret_cast<fnDllMain>((std::uint8_t*)imageBase + pe.GetOptHeader()->AddressOfEntryPoint);
	pEntryPoint((HMODULE)imageBase, DLL_PROCESS_ATTACH, lpReserved);

	return true;
}