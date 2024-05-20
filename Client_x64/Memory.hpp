#pragma once

#include <iostream>

namespace Memory {

	__forceinline void* memcpy(void* dst, const void* src, size_t len)
	{
		for (size_t i = 0; i < len; i++)
			((char*)dst)[i] = ((char*)src)[i];
		return dst;
	}

	__forceinline void* memset(void* dst, int val, size_t len)
	{
		for (size_t i = 0; i < len; i++)
			((char*)dst)[i] = (char)val;
		return dst;
	}

	__forceinline void* memchr(const void* ptr, int value, size_t num)
	{
		for (size_t i = 0; i < num; i++)
		{
			if (((char*)ptr)[i] == (char)value)
				return (void*)((char*)ptr + i);
		}
		return nullptr;
	}

	__forceinline int memcmp(const void* ptr1, const void* ptr2, size_t num)
	{
		for (size_t i = 0; i < num; i++)
		{
			if (((char*)ptr1)[i] != ((char*)ptr2)[i])
				return ((char*)ptr1)[i] - ((char*)ptr2)[i];
		}
		return 0;
	}
}