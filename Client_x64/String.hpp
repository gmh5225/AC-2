#pragma once

#include <iostream>
#include <string>

namespace String
{
	__forceinline size_t strlen(const char* str)
	{
		size_t len = 0;
		for (; str[len]; len++);
		return len;
	}

	__forceinline void strcpy(char* dst, char* src)
	{
		for (; *src; dst++, src++) *dst = *src;
	}

	__forceinline char* strcat(char* dst, int dst_size, char* src)
	{
		const size_t len_dst = strlen(dst);
		const size_t len_src = strlen(src);
		const size_t newLen = len_dst + len_src;

		if (dst_size < newLen)
			return nullptr;

		char* currPos = (char*)(dst + len_dst);
		for (size_t i = 0; i < len_src; i++, currPos++)
			*currPos = src[i];

		dst[newLen] = 0;
		return (char*)(dst + newLen);
	}

	__forceinline size_t wcslen(wchar_t* wStr)
	{
		size_t len = 0;
		for (; wStr[len]; len++);
		return len;
	}

	__forceinline bool wcscmp(wchar_t* w1, wchar_t* w2)
	{
		const size_t len = wcslen(w1);
		if (len != wcslen(w2))
			return false;

		for (size_t i = 0; i < len; i++)
		{
			if (w1[i] != w2[i])
				return false;
		}

		return true;
	}

	__forceinline bool strcmp(const char* str1, const char* str2)
	{
		if (!str1 || !str2) return false;
		for (; *str1 && *str2; str1++, str2++)
			if (*str1 != *str2) return false;

		return (*str1 == 0 && *str2 == 0);
	}

	template <typename T>
	__forceinline auto HexStr(T p)
	{
		std::stringstream ss;
		ss << std::hex << p;
		std::string result = ss.str();
		return result == "0" ? result
			: result.erase(0, result.find_first_not_of('0'));
	}


	constexpr std::uint32_t HashA(const char* str)
	{
		std::uint32_t hash = 7759;
		int c = 0;

		while (c = *str++)
			hash = ((hash << 5) + hash) + c;

		return hash;
	}

	consteval std::uint32_t HashACompileTime(const char* str)
	{
		return HashA(str);
	}

	constexpr std::uint32_t HashW(const wchar_t* str)
	{
		std::uint32_t hash = 7759;
		int c = 0;

		while (c = *str++)
			hash = ((hash << 5) + hash) + c;

		return hash;
	}

	//Wrapper to force compiler to replace strings with hash at compile time
	consteval std::uint32_t HashWCompileTime(const wchar_t* str)
	{
		return HashW(str);
	}

	__forceinline auto LowerA(const std::string& s) {
		std::string result = s;
		for (size_t j = 0; j < result.length(); j++) {
			if (result[j] >= 'A' && result[j] <= 'Z')
				result[j] += 32;
		}
		return result;
	}

	__forceinline auto LowerW(const std::wstring& s) {
		std::wstring result = s;
		for (size_t j = 0; j < s.length(); j++) {
			if (result[j] >= 'A' && result[j] <= 'Z')
				result[j] += 32;
		}
		return result;
	}

	__forceinline auto UpperA(const std::string& s) {
		std::string result = s;
		for (size_t j = 0; j < result.length(); j++) {
			if (result[j] >= 'a' && result[j] <= 'z')
				result[j] -= 32;
		}
		return result;
	}

	__forceinline auto UpperW(const std::wstring& s) {
		std::wstring result = s;
		for (size_t j = 0; j < result.length(); j++) {
			if (result[j] >= 'a' && result[j] <= 'z')
				result[j] -= 32;
		}
		return result;
	}
}

#define HASH_STR_A(x) (String::HashACompileTime(x))
#define HASH_STR_W(x) (String::HashWCompileTime(x))