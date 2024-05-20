#pragma once

#include <iostream>
#include <vector>
#include <unordered_map>
#include "PEB.hpp"

class CSyscall {

	static std::shared_ptr<CSyscall> m_Instance;
	static std::once_flag m_OnlyOneFlag;
	std::unordered_map<std::uint32_t, std::uint32_t> m_syscallMap;

	void createSyscallMap();
	CSyscall();

public:

	__forceinline static auto getInstance()
	{
		std::call_once(m_OnlyOneFlag, []() { m_Instance.reset(new CSyscall()); });
		return m_Instance.get();
	}

	__forceinline std::uint64_t get(const std::uint32_t syscallHash) const
	{
		const auto it = m_syscallMap.find(syscallHash);
		if (it != m_syscallMap.end())
			return it->second;
		return 0;
	}
};

#define SYSCALL_ID(x) CSyscall::getInstance()->get(HASH_STR_A(x))