#include <iostream>
#include <functional>
#include <memory>
#include "CSyscall.hpp"

std::shared_ptr<CSyscall> CSyscall::m_Instance;
std::once_flag CSyscall::m_OnlyOneFlag;

CSyscall::CSyscall()
{
	createSyscallMap();
}

void CSyscall::createSyscallMap()
{
	constexpr auto SYSCALL_ID_OFFSET = 4U;
	const auto exportedRoutines = Peb::getExportedRoutines(Peb::GetModHandle(HASH_STR_A("ntdll.dll")));

	for (auto routine : exportedRoutines)
	{
		if (!routine.second) continue;
		m_syscallMap.insert(
			std::make_pair(routine.first,
				*reinterpret_cast<std::uint32_t*>((std::uint8_t*)routine.second + SYSCALL_ID_OFFSET)));
	}
}