#pragma once
#include <string>
#include <vector>
#include <windows.h>
#include <gdiplus.h>
#include <unordered_map>
#include <shared_mutex>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>
#pragma comment (lib,"Gdiplus.lib")
#pragma comment (lib,"psapi.lib")
#pragma comment (lib,"ntdll.lib")

// Forward declarations of Windows API functions
typedef NTSTATUS(NTAPI* NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtWow64QueryInformationProcess64Fn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

extern "C" NTSTATUS NTAPI NtSuspendThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);
extern "C" NTSTATUS NTAPI NtResumeThread(HANDLE ThreadHandle, PULONG PreviousSuspendCount);

struct ProcessInfo {
    DWORD pid;
    std::string name;
    bool isProtected;
    std::string iconBase64;    // Base64 encoded icon data
    bool is64Bit;              // Whether the process is 64-bit
    
    // Additional process details
    std::string status;        // Running/Suspended
    std::string username;      // User account running the process
    double cpuUsage;          // CPU usage percentage
    SIZE_T workingSetPrivate; // Private working set memory
    std::string imagePath;    // Full path to the executable
    std::string commandLine;  // Command line arguments
};

class ProcessManager {
public:
    static std::vector<ProcessInfo> GetRunningProcesses();
    static bool InjectProtectionDLL(DWORD pid, std::string& errorMsg);
    static bool IsProcessProtected(DWORD pid);
    static ProcessInfo GetProcessDetails(DWORD pid); // New function for detailed info

private:
    static std::string GetProcessIconBase64(DWORD pid);
    static std::vector<uint8_t> ExtractIconFromExe(const std::wstring& exePath);
    static std::string Base64Encode(const std::vector<uint8_t>& data);
    static bool IsProcess64Bit(HANDLE process);
    static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid);
    static Gdiplus::Bitmap* IconToBitmapPARGB32(HICON hIcon);
    static std::vector<uint8_t> CreatePlaceholderIcon();
    
    // Helper functions for process details
    static std::string GetProcessUsername(HANDLE hProcess);
    static double GetProcessCpuUsage(HANDLE hProcess);
    static SIZE_T GetProcessPrivateWorkingSet(HANDLE hProcess);
    static std::string GetProcessCommandLine(HANDLE hProcess);
    static std::string GetProcessStatus(HANDLE hProcess);
    static std::wstring ConvertToWideString(const std::string& str);
    static std::string ConvertToString(const std::wstring& wstr);

    // Icon cache
    static std::unordered_map<std::wstring, std::string> iconCache;
    static std::shared_mutex cacheMutex;
};
