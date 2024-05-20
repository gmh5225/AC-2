#pragma once

#include <Windows.h>
#include <iostream>
#include <vector>
#include "String.hpp"

#define GetImgDirEntryRVA( pNTHdr, IDE ) \
	(pNTHdr->OptionalHeader.DataDirectory[IDE].VirtualAddress)

#define GetImgDirEntrySize( pNTHdr, IDE ) \
	(pNTHdr->OptionalHeader.DataDirectory[IDE].Size)

class PEFile
{
	PIMAGE_DOS_HEADER m_DosHeader;
	PIMAGE_NT_HEADERS m_NtHeader;
	PIMAGE_OPTIONAL_HEADER m_OptHeader;
	PIMAGE_FILE_HEADER m_FileHeader;
	std::uint8_t* m_ImageBase;
	std::vector<IMAGE_SECTION_HEADER> m_SectionsPE;
	PIMAGE_SECTION_HEADER m_TextSection;

	void InitPeSections() {
		for (std::uint16_t i = 0; i < m_FileHeader->NumberOfSections; i++) {
			const auto pSection = IMAGE_FIRST_SECTION(m_NtHeader) + i;
			if (!m_TextSection && String::HashA((char*)pSection->Name) == HASH_STR_A(".text")) {
				m_TextSection = pSection;
			}

			m_SectionsPE.push_back(*pSection);
		}
	}

public:

	PEFile(std::uint8_t* pe_buffer) : m_ImageBase(pe_buffer)
	{
		m_DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(m_ImageBase);
		m_NtHeader = reinterpret_cast<PIMAGE_NT_HEADERS>(m_ImageBase + m_DosHeader->e_lfanew);
		m_OptHeader = &m_NtHeader->OptionalHeader;
		m_FileHeader = &m_NtHeader->FileHeader;
		InitPeSections();
	}

	inline void* GetPtrFromRVA(std::uint64_t RVA) const
	{
		auto pSecHeader = IMAGE_FIRST_SECTION(m_NtHeader);
		for (std::uint8_t i = 0; i < m_NtHeader->FileHeader.NumberOfSections; i++, pSecHeader++)
		{
			if (RVA >= pSecHeader->VirtualAddress && RVA <=
				(pSecHeader->VirtualAddress + pSecHeader->Misc.VirtualSize))
			{
				const auto delta = pSecHeader->VirtualAddress - pSecHeader->PointerToRawData;
				return m_ImageBase + RVA - delta;
			}
		}

		return nullptr;
	}

	inline auto getImageSize() const {
		return m_OptHeader->SizeOfImage;
	}

	inline const auto& getSections() const { return m_SectionsPE; }
	inline auto GetImageBase() const { return m_ImageBase; }
	inline auto GetDosHeader() const { return m_DosHeader; }
	inline auto GetNtHeader() const { return m_NtHeader; }
	inline auto GetOptHeader() const { return m_OptHeader; }
	inline auto GetFileHeader() const { return m_FileHeader; }
	inline auto Isx64() const { return m_FileHeader->Machine; }
	inline auto GetSubsystem() const { return m_OptHeader->Subsystem; }
	inline void SetSubsystem(WORD s) { m_OptHeader->Subsystem = s; }
	inline auto GetImageDirSize(DWORD ImageDir) const { return m_OptHeader->DataDirectory[ImageDir].Size; }
	inline void* GetTextStartPtr() const { return m_ImageBase + m_TextSection->VirtualAddress; }
	inline auto GetTextSize() const { return m_TextSection->Misc.VirtualSize; }
	inline void* GetTextEndPtr() const { return (std::uint8_t*)GetTextStartPtr() + GetTextSize(); }

	inline auto GetSectionByName(std::uint32_t Hash) {
		IMAGE_SECTION_HEADER empty = {};
		for (const auto& section : m_SectionsPE) {
			if (String::HashA((char*)section.Name) == Hash) return section;
		}

		return empty;
	}

	inline auto GetImageDirPtr(DWORD ImageDir) const
	{
		const auto RVA = GetImgDirEntryRVA(m_NtHeader, ImageDir);
		return GetPtrFromRVA(RVA);
	}

	inline auto GetExportDir() const { 
		return (PIMAGE_EXPORT_DIRECTORY)(m_ImageBase + m_OptHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	}

};