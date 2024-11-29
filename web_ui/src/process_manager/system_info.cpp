#include "process_manager/system_info.h"
#include <psapi.h>

namespace process_manager {

bool SystemInfo::IsProcess64Bit(HANDLE process) {
    BOOL isWow64 = FALSE;
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

    // Try to use IsWow64Process2 if available (Windows 10 and later)
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS2)(HANDLE, USHORT*, USHORT*);
        LPFN_ISWOW64PROCESS2 fnIsWow64Process2 = reinterpret_cast<LPFN_ISWOW64PROCESS2>(
            GetProcAddress(hKernel32, "IsWow64Process2")
        );
        if (fnIsWow64Process2) {
            if (fnIsWow64Process2(process, &processMachine, &nativeMachine)) {
                if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN || processMachine == nativeMachine) {
                    return (nativeMachine == IMAGE_FILE_MACHINE_AMD64 ||
                            nativeMachine == IMAGE_FILE_MACHINE_ARM64 ||
                            nativeMachine == IMAGE_FILE_MACHINE_IA64);
                }
                return false;
            }
        }
    }

    // Fallback to IsWow64Process
    if (IsWow64Process(process, &isWow64)) {
        if (isWow64) {
            return false;
        } else {
            SYSTEM_INFO systemInfo = { 0 };
            GetNativeSystemInfo(&systemInfo);
            return (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                    systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ||
                    systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
        }
    }

    // Check if it's a system process
    DWORD pid = GetProcessId(process);
    if (pid == 0 || pid == 4) {
        SYSTEM_INFO systemInfo = { 0 };
        GetNativeSystemInfo(&systemInfo);
        return (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ||
                systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
    }

    return false;
}

bool SystemInfo::EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        std::cout << "[EnableDebugPrivilege] OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        std::cout << "[EnableDebugPrivilege] LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        std::cout << "[EnableDebugPrivilege] AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    DWORD error = GetLastError();
    if (error == ERROR_NOT_ALL_ASSIGNED) {
        std::cout << "[EnableDebugPrivilege] The token does not have the specified privilege. Error: " << error << std::endl;
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return true;
}

} // namespace process_manager 