#pragma once

#include <iostream>

enum class StatusCode : std::uint32_t {
	OK = 0,
	INITIALIZATION_ERROR_CONNECTION = 0xC00000C0,
	INITIALIZATION_ERROR_UNKNOWN
};