#pragma once
#include "base.h"
#include <winternl.h>

namespace process_manager {

// Forward declarations of Windows API functions
typedef NTSTATUS(NTAPI* NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtWow64QueryInformationProcess32Fn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
extern "C" NTSTATUS NTAPI NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

#ifdef _WIN64
// 32-bit structure layouts for accessing 32-bit process information from 64-bit code
typedef struct _PROCESS_BASIC_INFORMATION32 {
    NTSTATUS ExitStatus;
    ULONG PebBaseAddress;
    ULONG AffinityMask;
    ULONG BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;

typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} UNICODE_STRING32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
    BYTE Reserved1[16];
    ULONG Reserved2[10];
    UNICODE_STRING32 ImagePathName;
    UNICODE_STRING32 CommandLine;
} RTL_USER_PROCESS_PARAMETERS32;

typedef struct _PEB32 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    ULONG Reserved3[2];
    ULONG Ldr;
    ULONG ProcessParameters;
} PEB32;
#endif

} // namespace process_manager 