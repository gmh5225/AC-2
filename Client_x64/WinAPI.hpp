#pragma once

#include <iostream>
#include <vector>
#include <Windows.h>
#include "ntdll.hpp"
#include "CSyscall.hpp"
#include "Syscall.hpp"
#include "Structs.hpp"

namespace WinAPI
{
	__forceinline std::pair<NTSTATUS, HANDLE> CreateThread(PVOID StartAddress, PVOID arg, ULONG CreateFlags)
	{
		HANDLE hThread = INVALID_HANDLE_VALUE;
		const auto status = Syscall<NTSTATUS>(SYSCALL_ID("NtCreateThreadEx"), 
			&hThread, (ACCESS_MASK)THREAD_ALL_ACCESS,
			nullptr, NtCurrentProcess, 
			(LPTHREAD_START_ROUTINE)StartAddress, arg,
				(ULONG)CreateFlags, (SIZE_T)0, (SIZE_T)0, (SIZE_T)0, nullptr);

		return { status, hThread };
	}

	__forceinline NTSTATUS WaitForSingleObject(HANDLE hHandle, BOOLEAN Alertable, DWORD dwMilliseconds)
	{
		LARGE_INTEGER timeout = {};
		timeout.QuadPart = TIMEOUT_MS(dwMilliseconds);
		PLARGE_INTEGER pTimeout = dwMilliseconds == 0 ? nullptr : &timeout;

		return Syscall<NTSTATUS>(SYSCALL_ID("NtWaitForSingleObject"), hHandle, Alertable, pTimeout);
	}

	__forceinline NTSTATUS QueueApcThread(HANDLE ThreadHandle,
		IN PIO_APC_ROUTINE      ApcRoutine,
		IN PVOID                ApcRoutineContext OPTIONAL,
		IN PIO_STATUS_BLOCK     ApcStatusBlock OPTIONAL,
		IN ULONG                ApcReserved OPTIONAL)
	{
		return Syscall<NTSTATUS>(SYSCALL_ID("NtQueueApcThread"), ThreadHandle, ApcRoutine, ApcRoutineContext, ApcStatusBlock, ApcReserved);
	}

	__forceinline void SleepEx(int dwMilliseconds, BOOLEAN bAlertable)
	{
		LARGE_INTEGER timeout = {};
		timeout.QuadPart = TIMEOUT_MS(dwMilliseconds);

		Syscall(SYSCALL_ID("NtDelayExecution"), bAlertable, &timeout);
	}

	__forceinline auto QueryProcesses()
	{
		NTSTATUS status = 0;
		ULONG ReturnLength = 0;
		std::vector<PROCESS_ENTRY> vecProcess;

		status = Syscall<NTSTATUS>(SYSCALL_ID("NtQuerySystemInformation"), ntdll::SystemProcessInformation, nullptr, (ULONG)0, &ReturnLength);
		if (!NT_SUCCESS(status) || !ReturnLength) vecProcess;

		std::vector<std::uint8_t> procInfoBuffer(ReturnLength);
		while (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			status = Syscall<NTSTATUS>(SYSCALL_ID("NtQuerySystemInformation"), 
				ntdll::SystemProcessInformation, procInfoBuffer.data(), ReturnLength, &ReturnLength);

			if (status == STATUS_INFO_LENGTH_MISMATCH)
				procInfoBuffer.resize(ReturnLength);
		}

		const auto pProcStart = reinterpret_cast<ntdll::PSYSTEM_PROCESS_INFORMATION>(procInfoBuffer.data());
		auto pCurrProc = reinterpret_cast<ntdll::PSYSTEM_PROCESS_INFORMATION>
			((PBYTE)pProcStart + pProcStart->NextEntryOffset);

		while (pCurrProc->NextEntryOffset)
		{
			PROCESS_ENTRY procEntry = {};
			procEntry.ImageName = pCurrProc->ImageName.Buffer;
			procEntry.UniqueProcessId = pCurrProc->UniqueProcessId;
			procEntry.InheritedFromUniqueProcessId = pCurrProc->InheritedFromUniqueProcessId;
			procEntry.HandleCount = pCurrProc->HandleCount;
			procEntry.CreateTime = pCurrProc->CreateTime;
			procEntry.UserTime = pCurrProc->UserTime;
			procEntry.KernelTime = pCurrProc->KernelTime;

			for (ULONG i = 0; i < pCurrProc->NumberOfThreads; i++)
			{
				THREAD_ENTRY threadEntry = {};
				threadEntry.ClientId = pCurrProc->Threads[i].ClientId;
				threadEntry.Priority = pCurrProc->Threads[i].Priority;
				threadEntry.BasePriority = pCurrProc->Threads[i].BasePriority;
				threadEntry.StartAddress = pCurrProc->Threads[i].StartAddress;
				threadEntry.ThreadState = pCurrProc->Threads[i].ThreadState;
				threadEntry.WaitReason = pCurrProc->Threads[i].WaitReason;

				procEntry.Threads.push_back(threadEntry);
			}

			vecProcess.push_back(procEntry);
			pCurrProc = reinterpret_cast<ntdll::PSYSTEM_PROCESS_INFORMATION>
				((PBYTE)pCurrProc + pCurrProc->NextEntryOffset);
		}

		return vecProcess;
	}

	__forceinline std::vector<MEMORY_BASIC_INFORMATION> QueryMemory()
	{
		NTSTATUS status = 0;
		MEMORY_BASIC_INFORMATION mbi = {};
		std::uint8_t* pStart = nullptr;
		SIZE_T resultLen = 0;
		std::vector<MEMORY_BASIC_INFORMATION> vecRwxMem;

		status = Syscall<NTSTATUS>(SYSCALL_ID("NtQueryVirtualMemory"), 
			NtCurrentProcess, pStart, ntdll::MemoryBasicInformation, 
			&mbi, (SIZE_T)sizeof(MEMORY_BASIC_INFORMATION), &resultLen);
		if (!NT_SUCCESS(status)) return vecRwxMem;

		while (NT_SUCCESS(status) && resultLen)
		{
			vecRwxMem.push_back(mbi);
			pStart += mbi.RegionSize;
			status = Syscall<NTSTATUS>(SYSCALL_ID("NtQueryVirtualMemory"), 
				NtCurrentProcess, pStart, ntdll::MemoryBasicInformation, 
				&mbi, (SIZE_T)sizeof(MEMORY_BASIC_INFORMATION), &resultLen);
		}

		return vecRwxMem;
	}

	__forceinline NTSTATUS CloseHandle(HANDLE handle) {
		return Syscall<NTSTATUS>(SYSCALL_ID("NtClose"), handle);
	}

	__forceinline NTSTATUS VirtualAlloc(HANDLE hProcess, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {
		return Syscall<NTSTATUS>(SYSCALL_ID("NtAllocateVirtualMemory"), 
			hProcess, BaseAddress, (ULONG_PTR)0, RegionSize, AllocationType, Protect);
	}

	__forceinline NTSTATUS VirtualFree(HANDLE hProcess, PVOID BaseAddress, PSIZE_T RegionSize, ULONG FreeType) {
		return Syscall<NTSTATUS>(SYSCALL_ID("NtFreeVirtualMemory"), hProcess, &BaseAddress, RegionSize, FreeType);
	}

	__forceinline NTSTATUS VirtualProtect(HANDLE hProcess, PVOID* BaseAddress, PSIZE_T NumberOfBytesToProtect, ULONG NewProtect, PULONG OldProtect) {
		return Syscall<NTSTATUS>(SYSCALL_ID("NtProtectVirtualMemory"), 
						hProcess, BaseAddress, NumberOfBytesToProtect, NewProtect, OldProtect);
	}

	__forceinline std::pair<NTSTATUS, HANDLE> OpenProcess(ACCESS_MASK DesiredAccess, HANDLE PID) {
		OBJECT_ATTRIBUTES obj = {};
		HANDLE result = nullptr;
		InitializeObjectAttributes(&obj, nullptr, 0, nullptr, nullptr);
		ntdll::CLIENT_ID cid = { PID, nullptr };
		const auto status = Syscall<NTSTATUS>(SYSCALL_ID("NtOpenProcess"), &result, (ACCESS_MASK)DesiredAccess, &obj, &cid);

		return { status, result };
	}

	__forceinline std::pair<NTSTATUS, CONTEXT> GetContextThread(HANDLE hThread) {
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_FULL;
		const auto status = Syscall<NTSTATUS>(SYSCALL_ID("NtGetContextThread"), hThread, &ctx);
		return {status, ctx};
	}

	__forceinline NTSTATUS SetContextThread(HANDLE hThread, PCONTEXT ctx) {
		const auto status = Syscall<NTSTATUS>(SYSCALL_ID("NtSetContextThread"), hThread, ctx);
		return status;
	}

	__forceinline auto ResumeThread(HANDLE hThread) {
		return Syscall<NTSTATUS>(SYSCALL_ID("NtResumeThread"), hThread, nullptr);
	}

	__forceinline auto SuspendThread(HANDLE hThread) {
		return Syscall<NTSTATUS>(SYSCALL_ID("NtSuspendThread"), hThread, nullptr);
	}

	__forceinline auto TerminateThread(HANDLE hThread) {
		return Syscall<NTSTATUS>(SYSCALL_ID("NtTerminateThread"), hThread, ntdll::STATUS_SUCCESS);
	}

	__forceinline bool IsElevated() {
		HANDLE hToken = nullptr;
		auto status = Syscall<NTSTATUS>(SYSCALL_ID("NtOpenProcessToken"), NtCurrentProcess, (ACCESS_MASK)TOKEN_QUERY, &hToken);

		if (!NT_SUCCESS(status) || !hToken)
			return false;

		TOKEN_ELEVATION Elevation = {};
		ULONG Length = sizeof(TOKEN_ELEVATION);
		status = Syscall<NTSTATUS>(SYSCALL_ID("NtQueryInformationToken"), hToken, ntdll::TokenElevation, &Elevation, Length, &Length);

		WinAPI::CloseHandle(hToken);
		return NT_SUCCESS(status) && Elevation.TokenIsElevated;
	}

	__forceinline auto NTAPI RtlNtMajorVersion() { return *(PULONG)(0x7FFE0000 + 0x26C); }
	__forceinline auto NTAPI RtlNtMinorVersion() { return *(PULONG)(0x7FFE0000 + 0x270); }
	__forceinline auto NTAPI RtlGetTickCount() { return (ULONG)(*(PULONG64)(0x7FFE0000 + 0x320) * *(PULONG)(0x7FFE0000 + 0x4) >> 24); }
	__forceinline auto GetTEB64() { return reinterpret_cast<ntdll::PTEB64>(NtCurrentTeb()); }
	__forceinline auto NtCurrentProcessId() { return GetTEB64()->ClientId.UniqueProcess; }
	__forceinline auto NtCurrentThreadId() { return GetTEB64()->ClientId.UniqueThread; }
}