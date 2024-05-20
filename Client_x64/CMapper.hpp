#pragma once

#include <vector>

class CMapper
{
	std::uint8_t* m_PeBuffer;
	void* m_ImageBase;

public:
	
	CMapper(const std::vector<std::uint8_t>& peBuffer) : m_PeBuffer(const_cast<std::uint8_t*>(peBuffer.data())), m_ImageBase(nullptr) {}
	CMapper(std::uint8_t* peBuffer) : m_PeBuffer(peBuffer), m_ImageBase(nullptr) {};
	~CMapper();

	bool mapExecute(void* lpReserved);
};