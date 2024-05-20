#pragma once

#include <Windows.h>
#include <string>
#include <list>
#include "ntdll.hpp"

typedef struct {
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ThreadState;
    ULONG WaitReason;
} THREAD_ENTRY, *PTHREAD_ENTRY;

typedef struct {
	std::wstring ImageName;
	std::list<THREAD_ENTRY> Threads;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
} PROCESS_ENTRY, *PPROCESS_ENTRY;

//Struct for storing aes key and rsa public key
typedef struct {
	std::vector<unsigned char> aesKey;
	std::string rsaPublicKey;
} ENCRYPTION_CONTEXT, *PENCRYPTION_CONTEXT;