#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include "process_manager.h"
#include <filesystem>
#include <nlohmann/json.hpp>
#include <Windows.h>
#include <sstream>
#include <iomanip>
#include <lmcons.h>
#include <codecvt>
#include <locale>
#include <unordered_map>
#include <winternl.h>

using json = nlohmann::json;

// Structure to cache PE metadata before encryption
struct PEMetadataCache {
    bool isValid = false;
    HMODULE moduleBase = NULL;
    FARPROC encryptFunction = NULL;
    FARPROC decryptFunction = NULL;
    FARPROC statusFunction = NULL;
    bool* statusVariable = NULL;
    bool* memoryScanVariable = NULL;
    FARPROC enableMemoryScanFunction = NULL;
    FARPROC disableMemoryScanFunction = NULL;
    bool* antiTamperingVariable = NULL;
    FARPROC enableAntiTamperingFunction = NULL;
    FARPROC disableAntiTamperingFunction = NULL;
    bool* threadMonitoringVariable = NULL;
    FARPROC enableThreadMonitoringFunction = NULL;
    FARPROC disableThreadMonitoringFunction = NULL;
};

// Global cache for process PE metadata (pid -> metadata)
std::unordered_map<DWORD, PEMetadataCache> g_peMetadataCache;

// Define ZwCreateThreadEx function
typedef NTSTATUS (NTAPI *ZwCreateThreadExFunc)(
    OUT PHANDLE ThreadHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN HANDLE ProcessHandle,
    IN PVOID StartRoutine,
    IN PVOID Parameter OPTIONAL,
    IN ULONG Flags,
    IN SIZE_T StackZeroBits OPTIONAL,
    IN SIZE_T StackCommit OPTIONAL,
    IN SIZE_T StackReserve OPTIONAL,
    OUT PVOID AttributeList OPTIONAL
);

// Original RtlCreateUserThread definition (not simplified)
typedef NTSTATUS(NTAPI* RtlCreateUserThreadFunc)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG_PTR ZeroBits OPTIONAL,
    IN SIZE_T MaximumStackSize OPTIONAL,
    IN SIZE_T CommittedStackSize OPTIONAL,
    IN LPVOID StartAddress,
    IN LPVOID Parameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT LPVOID ClientId OPTIONAL
);

// Function to create thread using direct syscall
HANDLE CreateRemoteThreadLow(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) {
    HANDLE hThread = NULL;
    
    // Get ZwCreateThreadEx function address from ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cout << "[CreateRemoteThreadLow] Failed to get ntdll.dll handle" << std::endl;
        return NULL;
    }
    
    ZwCreateThreadExFunc ZwCreateThreadEx = (ZwCreateThreadExFunc)GetProcAddress(hNtdll, "ZwCreateThreadEx");
    if (!ZwCreateThreadEx) {
        std::cout << "[CreateRemoteThreadLow] Failed to get ZwCreateThreadEx function" << std::endl;
        return NULL;
    }
    
    std::cout << "[CreateRemoteThreadLow] Using ZwCreateThreadEx at " << (LPVOID)ZwCreateThreadEx << std::endl;
    
    // Simplify the call to increase chances of success
    NTSTATUS status = ZwCreateThreadEx(
        &hThread,                  // ThreadHandle
        THREAD_ALL_ACCESS,         // DesiredAccess
        NULL,                      // ObjectAttributes
        hProcess,                  // ProcessHandle
        lpStartAddress,            // StartRoutine
        lpParameter,               // Parameter
        0,                         // Flags - using 0 instead of any flags
        0,                         // StackZeroBits - 0 for default
        0,                         // StackCommit - 0 for default
        0,                         // StackReserve - 0 for default
        NULL                       // AttributeList - NULL for simplicity
    );
    
    if (!NT_SUCCESS(status)) {
        std::cout << "[CreateRemoteThreadLow] ZwCreateThreadEx failed with status: 0x" 
                  << std::hex << status << std::dec
                  << " (decimal: " << status << ")" << std::endl;
        
        // Log common NTSTATUS errors
        switch (status) {
            case 0xC0000022: // STATUS_ACCESS_DENIED
                std::cout << "[CreateRemoteThreadLow] Status indicates ACCESS_DENIED" << std::endl;
                break;
            case 0xC000007B: // STATUS_INVALID_PARAMETER_1
                std::cout << "[CreateRemoteThreadLow] Status indicates INVALID_PARAMETER_1" << std::endl;
                break;
            case 0xC0000225: // STATUS_NOT_FOUND
                std::cout << "[CreateRemoteThreadLow] Status indicates NOT_FOUND" << std::endl;
                break;
        }
        
        return NULL;
    }
    
    std::cout << "[CreateRemoteThreadLow] Successfully created thread using ZwCreateThreadEx" << std::endl;
    return hThread;
}

// Fixed CreateRemoteThreadUsingRtl function
HANDLE CreateRemoteThreadUsingRtl(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) {
    HANDLE hThread = NULL;
    
    // Get RtlCreateUserThread function address from ntdll.dll
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (!hNtdll) {
        std::cout << "[CreateRemoteThreadUsingRtl] Failed to get ntdll.dll handle" << std::endl;
        return NULL;
    }
    
    RtlCreateUserThreadFunc RtlCreateUserThread = 
        (RtlCreateUserThreadFunc)GetProcAddress(hNtdll, "RtlCreateUserThread");
    if (!RtlCreateUserThread) {
        std::cout << "[CreateRemoteThreadUsingRtl] Failed to get RtlCreateUserThread function" << std::endl;
        return NULL;
    }
    
    std::cout << "[CreateRemoteThreadUsingRtl] Using RtlCreateUserThread at " << (LPVOID)RtlCreateUserThread << std::endl;
    
    // Using the updated parameter types for the function call
    SIZE_T MaximumStackSize = 0;  // Use system default
    SIZE_T CommittedStackSize = 0;  // Use system default
    
    // Call RtlCreateUserThread with updated signature
    NTSTATUS status = RtlCreateUserThread(
        hProcess,             // ProcessHandle
        NULL,                 // SecurityDescriptor 
        FALSE,                // CreateSuspended
        0,                    // ZeroBits
        MaximumStackSize,     // MaximumStackSize
        CommittedStackSize,   // CommittedStackSize
        lpStartAddress,       // StartAddress
        lpParameter,          // Parameter
        &hThread,             // ThreadHandle
        NULL                  // ClientId - pass NULL to avoid issues
    );
    
    if (!NT_SUCCESS(status)) {
        std::cout << "[CreateRemoteThreadUsingRtl] RtlCreateUserThread failed with status: " 
                  << std::hex << status << std::dec << std::endl;
        return NULL;
    }
    
    std::cout << "[CreateRemoteThreadUsingRtl] Successfully created thread using RtlCreateUserThread" << std::endl;
    return hThread;
}

// Add this function below the other remote thread creation functions
HANDLE CreateRemoteThreadViaShellcode(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) {
    std::cout << "[CreateRemoteThreadViaShellcode] Creating shellcode to execute function at " << lpStartAddress << std::endl;
    
    // Allocate memory in the target process for our shellcode
    LPVOID shellcodeAddr = VirtualAllocEx(
        hProcess, 
        NULL, 
        1024,  // More than enough for our small shellcode
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );
    
    if (!shellcodeAddr) {
        std::cout << "[CreateRemoteThreadViaShellcode] Failed to allocate memory for shellcode: " 
                  << GetLastError() << std::endl;
        return NULL;
    }
    
    std::cout << "[CreateRemoteThreadViaShellcode] Allocated memory at " << shellcodeAddr << std::endl;
    
    // Create x64 shellcode that calls the target function and returns its result
    // This is a very simple shellcode that just makes a call to lpStartAddress and returns
    unsigned char shellcode[] = {
        0x48, 0x83, 0xEC, 0x28,                 // sub rsp, 28h (reserve shadow space)
        0x48, 0xB9, 0x00, 0x00, 0x00, 0x00,     // mov rcx, lpParameter (placeholder)
        0x00, 0x00, 0x00, 0x00,                 // ...continuation of address
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,     // mov rax, lpStartAddress (placeholder)
        0x00, 0x00, 0x00, 0x00,                 // ...continuation of address
        0xFF, 0xD0,                             // call rax
        0x48, 0x83, 0xC4, 0x28,                 // add rsp, 28h
        0xC3                                    // ret
    };
    
    // Patch the shellcode with the actual addresses
    *(LPVOID*)&shellcode[6] = lpParameter;
    *(LPVOID*)&shellcode[16] = lpStartAddress;
    
    // Write the shellcode to the target process
    if (!WriteProcessMemory(hProcess, shellcodeAddr, shellcode, sizeof(shellcode), NULL)) {
        std::cout << "[CreateRemoteThreadViaShellcode] Failed to write shellcode: " 
                  << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return NULL;
    }
    
    std::cout << "[CreateRemoteThreadViaShellcode] Shellcode written successfully" << std::endl;
    
    // Create a thread to execute our shellcode
    HANDLE hThread = CreateRemoteThread(
        hProcess, 
        NULL, 
        0, 
        (LPTHREAD_START_ROUTINE)shellcodeAddr, 
        NULL, 
        0, 
        NULL
    );
    
    if (!hThread) {
        std::cout << "[CreateRemoteThreadViaShellcode] Failed to create thread: " 
                  << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, shellcodeAddr, 0, MEM_RELEASE);
        return NULL;
    }
    
    std::cout << "[CreateRemoteThreadViaShellcode] Thread created successfully" << std::endl;
    return hThread;
}

// Add this function before the ws2s function
HANDLE CreateAndInjectCodeCave(HANDLE hProcess, LPVOID lpStartAddress, LPVOID lpParameter) {
    std::cout << "[CreateAndInjectCodeCave] Setting up code cave to call " << lpStartAddress << std::endl;
    
    // Allocate a memory block for our code cave
    LPVOID codeAddress = VirtualAllocEx(
        hProcess, 
        NULL, 
        4096,  // 4KB should be plenty
        MEM_COMMIT | MEM_RESERVE, 
        PAGE_EXECUTE_READWRITE
    );
    
    if (!codeAddress) {
        std::cout << "[CreateAndInjectCodeCave] Failed to allocate memory: " << GetLastError() << std::endl;
        return NULL;
    }
    
    std::cout << "[CreateAndInjectCodeCave] Allocated code cave at " << codeAddress << std::endl;
    
    // Create x64 assembly that will:
    // 1. Call the target function
    // 2. Return the result code
    // This bypasses any PE header validation by being a standalone memory region
    
    unsigned char code[] = {
        // Save registers
        0x48, 0x89, 0xF8,                     // mov rax, rdi (save rdi)
        0x48, 0x89, 0xF9,                     // mov rcx, rdi (parameter)
        
        // Set up call to our function
        0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,   // mov rax, lpStartAddress (placeholder)
        0x00, 0x00, 0x00, 0x00,               // (upper 32-bits of address)
        
        // Call the function
        0xFF, 0xD0,                           // call rax
        
        // Exit thread with function's return value already in rax
        0xC3                                  // ret
    };
    
    // Patch the real address into our code
    *(LPVOID *)&code[8] = lpStartAddress;
    
    // Write the code to the target process
    if (!WriteProcessMemory(hProcess, codeAddress, code, sizeof(code), NULL)) {
        std::cout << "[CreateAndInjectCodeCave] Failed to write code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, codeAddress, 0, MEM_RELEASE);
        return NULL;
    }
    
    // Create a thread that starts at our code cave
    HANDLE hThread = CreateRemoteThread(
        hProcess,
        NULL,
        0,
        (LPTHREAD_START_ROUTINE)codeAddress,
        lpParameter,
        0,
        NULL
    );
    
    if (!hThread) {
        std::cout << "[CreateAndInjectCodeCave] Failed to create thread: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, codeAddress, 0, MEM_RELEASE);
        return NULL;
    }
    
    std::cout << "[CreateAndInjectCodeCave] Successfully created thread with code cave" << std::endl;
    return hThread;
}

std::string ws2s(const std::wstring& wstr) {
    std::string str;
    for (wchar_t wc : wstr) {
        str += static_cast<char>(wc);
    }
    return str;
}

std::string GetWindowsVersion() {
    OSVERSIONINFOEXW osInfo;
    ZeroMemory(&osInfo, sizeof(OSVERSIONINFOEXW));
    osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
        if (RtlGetVersion) {
            RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo);
        }
    }

    std::ostringstream oss;
    if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber >= 22000) {
        oss << "Windows 11";
    } else {
        oss << "Windows " << osInfo.dwMajorVersion;
    }

    // Get edition information
    DWORD bufferSize = 0;
    GetProductInfo(osInfo.dwMajorVersion, osInfo.dwMinorVersion, 
                  osInfo.wServicePackMajor, osInfo.wServicePackMinor, &bufferSize);

    wchar_t buffer[256];
    DWORD size = sizeof(buffer);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, 
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"DisplayVersion",
                     RRF_RT_REG_SZ,
                     nullptr,
                     buffer,
                     &size) == ERROR_SUCCESS) {
        oss << " Version " << ws2s(buffer);
    }

    oss << " (Build " << osInfo.dwBuildNumber;
    
    // Get UBR (Update Build Revision)
    DWORD ubr = 0;
    size = sizeof(ubr);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"UBR",
                     RRF_RT_REG_DWORD,
                     nullptr,
                     &ubr,
                     &size) == ERROR_SUCCESS) {
        oss << "." << ubr;
    }
    oss << ")";

    // Get edition (Pro, Home, etc.)
    size = sizeof(buffer);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"EditionID",
                     RRF_RT_REG_SZ,
                     nullptr,
                     buffer,
                     &size) == ERROR_SUCCESS) {
        oss << " " << ws2s(buffer);
    }

    return oss.str();
}

std::string GetComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer)/sizeof(buffer[0]);
    if (GetComputerNameW(buffer, &size)) {
        return ws2s(buffer);
    }
    return "Unknown";
}

std::string GetUsername() {
    wchar_t buffer[UNLEN + 1];
    DWORD size = sizeof(buffer)/sizeof(buffer[0]);
    if (GetUserNameW(buffer, &size)) {
        return ws2s(buffer);
    }
    return "Unknown";
}

const char* HTML_HEAD = R"html(
<!DOCTYPE html>
<html>
<head>
    <title>Windows Process Protector</title>
    <link rel="stylesheet" href="/static/css/styles.css">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
</head>
)html";

const char* HTML_BODY = R"html(
<body>
    <div class="container">
        <h1>Windows Process Protector</h1>

        <div class="system-info">
            <h2><i class="material-icons">computer</i>System Information</h2>
            <div class="system-info-grid">
                <div class="system-info-item">
                    <span class="system-info-label">Computer Name</span>
                    <span class="system-info-value" id="computerName">Loading...</span>
                </div>
                <div class="system-info-item">
                    <span class="system-info-label">Username</span>
                    <span class="system-info-value" id="username">Loading...</span>
                </div>
                <div class="system-info-item">
                    <span class="system-info-label">OS Version</span>
                    <span class="system-info-value" id="osVersion">Loading...</span>
                </div>
            </div>
        </div>

        <div class="control-layout">
            <div class="top-controls">
                <div class="control-panel filter-panel">
                    <h3><i class="material-icons">filter_list</i>Process Filters</h3>
                    <div class="filter-controls">
                        <div class="filter-group">
                            <label>Architecture:</label>
                            <select id="archFilter">
                                <option value="all">All</option>
                                <option value="x64">x64</option>
                                <option value="x86">x86</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label>Status:</label>
                            <select id="protectionFilter">
                                <option value="all">All</option>
                                <option value="protected">Protected</option>
                                <option value="unprotected">Unprotected</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label>Type:</label>
                            <select id="systemFilter">
                                <option value="all">All Processes</option>
                                <option value="user">User Processes</option>
                                <option value="system">System Processes</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label>Window:</label>
                            <select id="windowFilter">
                                <option value="all">All Processes</option>
                                <option value="visible">With Window</option>
                                <option value="hidden">Without Window</option>
                            </select>
                        </div>
                    </div>
                </div>

                <div class="control-panel refresh-panel">
                    <h3><i class="material-icons">refresh</i>Refresh Settings</h3>
                    <div class="refresh-controls">
                        <div class="refresh-group">
                            <label>
                                <input type="checkbox" id="autoRefresh" checked>
                                Auto-refresh
                            </label>
                            <select id="refreshInterval">
                                <option value="1000">1 second</option>
                                <option value="2000">2 seconds</option>
                                <option value="5000" selected>5 seconds</option>
                                <option value="10000">10 seconds</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <div class="search-row">
                <div class="control-panel search-panel">
                    <h3><i class="material-icons">search</i>Process Search</h3>
                    <div class="search-controls">
                        <div class="search-container">
                            <input type="text" id="searchInput" placeholder="Search processes..." />
                            <button type="button" class="search-clear" id="searchClear" aria-label="Clear search">
                                <i class="material-icons">close</i>
                            </button>
                        </div>
                        <div class="help-text">Search by process name or PID (updates in real-time)</div>
                    </div>
                </div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th data-column="name">Process Name</th>
                    <th data-column="pid">PID</th>
                    <th data-column="arch">Architecture</th>
                    <th data-column="protection">Protection Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="processTable">
            </tbody>
        </table>
    </div>
    <script src="/static/js/main.js"></script>
</body>
</html>
)html";

void SendHTML(httplib::Response& res) {
    std::stringstream ss;
    ss << HTML_HEAD << HTML_BODY;
    
    res.set_content(ss.str(), "text/html");
}

BOOL GetRemoteProcAddress(
    IN HANDLE hProcess,
    IN HMODULE hModule,
    IN LPCSTR lpProcName,
    OUT FARPROC* lpProcAddress
) {
    if (!hProcess || !hModule || !lpProcName || !lpProcAddress)
        return FALSE;

    // First, read the DOS header
    IMAGE_DOS_HEADER dosHeader;
    if (!ReadProcessMemory(hProcess, hModule, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL)) {
        std::cout << "[GetRemoteProcAddress] Failed to read DOS header, error: " << GetLastError() << std::endl;
        return FALSE;
    }

    if (dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        std::cout << "[GetRemoteProcAddress] Invalid DOS signature: " << std::hex << dosHeader.e_magic << std::dec << std::endl;
        return FALSE;
    }

    std::cout << "[GetRemoteProcAddress] DOS Header OK, e_lfanew: " << std::hex << dosHeader.e_lfanew << std::dec << std::endl;

    // Read the NT headers
    BYTE ntHeadersBuffer[sizeof(IMAGE_NT_HEADERS64)];
    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + dosHeader.e_lfanew, ntHeadersBuffer, sizeof(ntHeadersBuffer), NULL)) {
        std::cout << "[GetRemoteProcAddress] Failed to read NT headers, error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Determine if it's a 32-bit or 64-bit module
    PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)ntHeadersBuffer;
    DWORD exportDirRVA = 0;
    DWORD exportDirSize = 0;

    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        std::cout << "[GetRemoteProcAddress] Invalid NT signature: " << std::hex << ntHeaders->Signature << std::dec << std::endl;
        return FALSE;
    }

    std::cout << "[GetRemoteProcAddress] NT Header OK, Magic: " << std::hex << ntHeaders->OptionalHeader.Magic << std::dec << std::endl;

    if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        // 32-bit module
        PIMAGE_NT_HEADERS32 ntHeaders32 = (PIMAGE_NT_HEADERS32)ntHeadersBuffer;
        exportDirRVA = ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        std::cout << "[GetRemoteProcAddress] 32-bit module detected" << std::endl;
    } else if (ntHeaders->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        // 64-bit module
        PIMAGE_NT_HEADERS64 ntHeaders64 = (PIMAGE_NT_HEADERS64)ntHeadersBuffer;
        exportDirRVA = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        exportDirSize = ntHeaders64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        std::cout << "[GetRemoteProcAddress] 64-bit module detected" << std::endl;
    } else {
        std::cout << "[GetRemoteProcAddress] Unknown module type with magic: " << std::hex << ntHeaders->OptionalHeader.Magic << std::dec << std::endl;
        return FALSE;
    }

    if (!exportDirRVA || !exportDirSize) {
        std::cout << "[GetRemoteProcAddress] No export directory found. RVA: " << std::hex << exportDirRVA 
                  << ", Size: " << exportDirSize << std::dec << std::endl;
        return FALSE;
    }

    std::cout << "[GetRemoteProcAddress] Export directory found at RVA: " << std::hex << exportDirRVA 
              << ", Size: " << exportDirSize << std::dec << std::endl;

    // Read the export directory
    IMAGE_EXPORT_DIRECTORY exportDir;
    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + exportDirRVA, &exportDir, sizeof(IMAGE_EXPORT_DIRECTORY), NULL)) {
        std::cout << "[GetRemoteProcAddress] Failed to read export directory, error: " << GetLastError() << std::endl;
        return FALSE;
    }

    std::cout << "[GetRemoteProcAddress] Export directory read successfully" << std::endl;
    std::cout << "[GetRemoteProcAddress] Number of functions: " << exportDir.NumberOfFunctions << std::endl;
    std::cout << "[GetRemoteProcAddress] Number of names: " << exportDir.NumberOfNames << std::endl;
    std::cout << "[GetRemoteProcAddress] Address of functions: " << std::hex << exportDir.AddressOfFunctions << std::dec << std::endl;
    std::cout << "[GetRemoteProcAddress] Address of names: " << std::hex << exportDir.AddressOfNames << std::dec << std::endl;
    std::cout << "[GetRemoteProcAddress] Address of ordinals: " << std::hex << exportDir.AddressOfNameOrdinals << std::dec << std::endl;

    // Read address of functions array
    std::vector<DWORD> functionRVAs(exportDir.NumberOfFunctions);
    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + exportDir.AddressOfFunctions, 
                          functionRVAs.data(), exportDir.NumberOfFunctions * sizeof(DWORD), NULL)) {
        std::cout << "[GetRemoteProcAddress] Failed to read function RVAs, error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Read address of names array
    std::vector<DWORD> nameRVAs(exportDir.NumberOfNames);
    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + exportDir.AddressOfNames, 
                          nameRVAs.data(), exportDir.NumberOfNames * sizeof(DWORD), NULL)) {
        std::cout << "[GetRemoteProcAddress] Failed to read name RVAs, error: " << GetLastError() << std::endl;
        return FALSE;
    }

    // Read address of ordinals array
    std::vector<WORD> nameOrdinals(exportDir.NumberOfNames);
    if (!ReadProcessMemory(hProcess, (BYTE*)hModule + exportDir.AddressOfNameOrdinals, 
                          nameOrdinals.data(), exportDir.NumberOfNames * sizeof(WORD), NULL)) {
        std::cout << "[GetRemoteProcAddress] Failed to read name ordinals, error: " << GetLastError() << std::endl;
        return FALSE;
    }

    std::cout << "[GetRemoteProcAddress] Looking for procedure: " << lpProcName << std::endl;
    std::cout << "[GetRemoteProcAddress] Scanning " << exportDir.NumberOfNames << " export names..." << std::endl;

    // Read through all exports to check for names matching our target
    bool isNameFound = false;
    DWORD functionIndex = 0;

    for (DWORD i = 0; i < exportDir.NumberOfNames && !isNameFound; i++) {
        // Read each function name string - allocate large enough buffer for each name
        std::vector<char> nameBuffer(256, 0);

        if (!ReadProcessMemory(hProcess, (BYTE*)hModule + nameRVAs[i], 
                              nameBuffer.data(), nameBuffer.size() - 1, NULL)) {
            std::cout << "[GetRemoteProcAddress] Failed to read export name at index " << i 
                     << ", error: " << GetLastError() << std::endl;
            continue;
        }

        // For debugging, print every 50th export we find
        if (i % 50 == 0 || strcmp(nameBuffer.data(), lpProcName) == 0) {
            WORD ordinal = nameOrdinals[i];
            std::cout << "[GetRemoteProcAddress] Export #" << i << ": Name='" << nameBuffer.data() 
                     << "', Ordinal=" << ordinal << ", NameRVA=0x" << std::hex << nameRVAs[i] << std::dec << std::endl;
        }

        // Check if this is the function we're looking for
        if (strcmp(nameBuffer.data(), lpProcName) == 0) {
            isNameFound = true;
            functionIndex = nameOrdinals[i]; // Get the function index from the ordinal
            std::cout << "[GetRemoteProcAddress] Found match at index " << i 
                     << ", function index (ordinal): " << functionIndex << std::endl;
            break;
        }
    }

    // If we found our function by name, get its address
    if (isNameFound) {
        if (functionIndex < exportDir.NumberOfFunctions) {
            DWORD functionRVA = functionRVAs[functionIndex];
            *lpProcAddress = (FARPROC)((BYTE*)hModule + functionRVA);
            std::cout << "[GetRemoteProcAddress] Found function address: " << *lpProcAddress 
                     << " (RVA: 0x" << std::hex << functionRVA << std::dec << ")" << std::endl;
            return TRUE;
        } else {
            std::cout << "[GetRemoteProcAddress] Function index out of range: " << functionIndex 
                     << " >= " << exportDir.NumberOfFunctions << std::endl;
        }
    }

    // Special case for Protection_* functions - search for them specifically at expected ordinals
    // Based on your export table screenshot
    if (strcmp(lpProcName, "Protection_DecryptPEHeaders") == 0) {
        // Try to find it by ordinal 0x157 (343)
        for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
            if (nameOrdinals[i] == 0x157) {
                std::vector<char> nameBuffer(256, 0);
                if (ReadProcessMemory(hProcess, (BYTE*)hModule + nameRVAs[i], 
                                      nameBuffer.data(), nameBuffer.size() - 1, NULL)) {
                    std::cout << "[GetRemoteProcAddress] Found at ordinal 0x157: " << nameBuffer.data() << std::endl;
                }
                
                DWORD functionRVA = functionRVAs[0x157];
                *lpProcAddress = (FARPROC)((BYTE*)hModule + functionRVA);
                std::cout << "[GetRemoteProcAddress] Using ordinal 0x157 for " << lpProcName 
                         << ", address: " << *lpProcAddress << std::endl;
                return TRUE;
            }
        }
    } else if (strcmp(lpProcName, "Protection_EncryptPEHeaders") == 0) {
        // Try to find it by ordinal 0x158 (344)
        for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
            if (nameOrdinals[i] == 0x158) {
                std::vector<char> nameBuffer(256, 0);
                if (ReadProcessMemory(hProcess, (BYTE*)hModule + nameRVAs[i], 
                                      nameBuffer.data(), nameBuffer.size() - 1, NULL)) {
                    std::cout << "[GetRemoteProcAddress] Found at ordinal 0x158: " << nameBuffer.data() << std::endl;
                }
                
                DWORD functionRVA = functionRVAs[0x158];
                *lpProcAddress = (FARPROC)((BYTE*)hModule + functionRVA);
                std::cout << "[GetRemoteProcAddress] Using ordinal 0x158 for " << lpProcName 
                         << ", address: " << *lpProcAddress << std::endl;
                return TRUE;
            }
        }
    } else if (strcmp(lpProcName, "Protection_IsPEHeadersEncrypted") == 0) {
        // Try to find it by ordinal 0x159 (345)
        for (DWORD i = 0; i < exportDir.NumberOfNames; i++) {
            if (nameOrdinals[i] == 0x159) {
                std::vector<char> nameBuffer(256, 0);
                if (ReadProcessMemory(hProcess, (BYTE*)hModule + nameRVAs[i], 
                                      nameBuffer.data(), nameBuffer.size() - 1, NULL)) {
                    std::cout << "[GetRemoteProcAddress] Found at ordinal 0x159: " << nameBuffer.data() << std::endl;
                }
                
                DWORD functionRVA = functionRVAs[0x159];
                *lpProcAddress = (FARPROC)((BYTE*)hModule + functionRVA);
                std::cout << "[GetRemoteProcAddress] Using ordinal 0x159 for " << lpProcName 
                         << ", address: " << *lpProcAddress << std::endl;
                return TRUE;
            }
        }
    }

    // Last resort: search by ordinal directly if we know the ordinal from the export table
    if (strcmp(lpProcName, "Protection_DecryptPEHeaders") == 0) {
        DWORD ordinal = 0x157; // From your export table screenshot
        if (ordinal < exportDir.NumberOfFunctions) {
            DWORD functionRVA = functionRVAs[ordinal];
            *lpProcAddress = (FARPROC)((BYTE*)hModule + functionRVA);
            std::cout << "[GetRemoteProcAddress] Using direct ordinal 0x157 for " << lpProcName 
                     << ", function RVA: 0x" << std::hex << functionRVA << std::dec 
                     << ", address: " << *lpProcAddress << std::endl;
            return TRUE;
        }
    } else if (strcmp(lpProcName, "Protection_EncryptPEHeaders") == 0) {
        DWORD ordinal = 0x158; // From your export table screenshot
        if (ordinal < exportDir.NumberOfFunctions) {
            DWORD functionRVA = functionRVAs[ordinal];
            *lpProcAddress = (FARPROC)((BYTE*)hModule + functionRVA);
            std::cout << "[GetRemoteProcAddress] Using direct ordinal 0x158 for " << lpProcName 
                     << ", function RVA: 0x" << std::hex << functionRVA << std::dec 
                     << ", address: " << *lpProcAddress << std::endl;
            return TRUE;
        }
    } else if (strcmp(lpProcName, "Protection_IsPEHeadersEncrypted") == 0) {
        DWORD ordinal = 0x159; // From your export table screenshot
        if (ordinal < exportDir.NumberOfFunctions) {
            DWORD functionRVA = functionRVAs[ordinal];
            *lpProcAddress = (FARPROC)((BYTE*)hModule + functionRVA);
            std::cout << "[GetRemoteProcAddress] Using direct ordinal 0x159 for " << lpProcName 
                     << ", function RVA: 0x" << std::hex << functionRVA << std::dec 
                     << ", address: " << *lpProcAddress << std::endl;
            return TRUE;
        }
    }

    std::cout << "[GetRemoteProcAddress] Procedure " << lpProcName << " not found in export table" << std::endl;
    return FALSE;
}

int main() {
    httplib::Server svr;
    process_manager::ProcessManager pm;

    // Enable debug privilege
    if (!process_manager::SystemInfo::EnableDebugPrivilege()) {
        std::cout << "Warning: Failed to enable debug privilege. Some process information may be limited." << std::endl;
    } else {
        std::cout << "Successfully enabled debug privilege." << std::endl;
    }

    // Get the executable directory
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir = std::filesystem::path(exePath).parent_path().string();
    std::string staticPath = exeDir + "/static";

    // Create static directories if they don't exist
    std::filesystem::create_directories(staticPath + "/css");
    std::filesystem::create_directories(staticPath + "/js");

    // Serve static files
    svr.set_mount_point("/static", staticPath.c_str());

    // Main page
    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        SendHTML(res);
    });

    // Get system info
    svr.Get("/api/system-info", [](const httplib::Request& req, httplib::Response& res) {
        json info;
        info["osVersion"] = GetWindowsVersion();
        info["computerName"] = GetComputerName();
        info["username"] = GetUsername();
        res.set_content(info.dump(), "application/json");
    });

    // Get processes
    svr.Get("/api/processes", [&pm](const httplib::Request& req, httplib::Response& res) {
        auto processes = pm.GetRunningProcesses();
        json j = json::array();
        
        for (const auto& proc : processes) {
            json process;
            process["name"] = proc.name;
            process["pid"] = proc.pid;
            process["icon"] = proc.iconBase64;
            process["is64Bit"] = proc.is64Bit;
            process["isProtected"] = proc.isProtected;
            process["isSystemProcess"] = process_manager::ProcessInfoManager::IsWindowsSystemProcess(
                std::wstring(proc.name.begin(), proc.name.end()), 
                proc.pid
            );
            process["hasVisibleWindow"] = proc.hasVisibleWindow;
            j.push_back(process);
        }
        
        res.set_content(j.dump(), "application/json");
    });

    // Get process details
    svr.Get(R"(/api/process/(\d+))", [&pm](const httplib::Request& req, httplib::Response& res) {
        auto pid = std::stoi(req.matches[1].str());
        auto procInfo = pm.GetProcessDetails(pid);
        
        // Format PID in hex
        std::stringstream hexPid;
        hexPid << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(4) << procInfo.pid;
        
        json result = {
            {"pid", procInfo.pid},
            {"pidHex", hexPid.str()},
            {"name", procInfo.name},
            {"isProtected", procInfo.isProtected},
            {"iconBase64", procInfo.iconBase64},
            {"is64Bit", procInfo.is64Bit},
            {"status", procInfo.status},
            {"username", procInfo.username},
            {"cpuUsage", procInfo.cpuUsage},
            {"workingSetPrivate", procInfo.workingSetPrivate},
            {"imagePath", procInfo.imagePath},
            {"commandLine", procInfo.commandLine},
            {"description", procInfo.description}
        };
        res.set_content(result.dump(), "application/json");
    });

    // Protect process
    svr.Post("/api/protect", [&pm](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        std::string errorMsg;
        
        if (pm.InjectProtectionDLL(pid, errorMsg)) {
            // Check if the process is actually protected
            if (process_manager::ProcessInfoManager::IsProcessProtected(pid)) {
                json response;
                response["success"] = true;
                response["message"] = "Process protected successfully";
                std::cout << "Success response: " << response.dump(2) << std::endl;
                res.set_content(response.dump(), "application/json");
            } else {
                json response;
                response["success"] = false;
                response["error"] = "DLL injection succeeded but protection features failed to initialize";
                response["error_code"] = GetLastError();
                response["error_details"] = [&]() -> std::string {
                    char* lpMsgBuf;
                    DWORD dw = GetLastError();
                    FormatMessageA(
                        FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL,
                        dw,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPSTR)&lpMsgBuf,
                        0, NULL);
                    std::string msg(lpMsgBuf);
                    LocalFree(lpMsgBuf);
                    return msg;
                }();
                std::cout << "Error response (protection failed): " << response.dump(2) << std::endl;
                res.set_content(response.dump(), "application/json");
                res.status = 400;
            }
        } else {
            json response;
            response["success"] = false;
            response["error"] = errorMsg;
            response["error_code"] = GetLastError();
            response["error_details"] = [&]() -> std::string {
                char* lpMsgBuf;
                DWORD dw = GetLastError();
                FormatMessageA(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    dw,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPSTR)&lpMsgBuf,
                    0, NULL);
                std::string msg(lpMsgBuf);
                LocalFree(lpMsgBuf);
                return msg;
            }();
            std::cout << "Error response (injection failed): " << response.dump(2) << std::endl;
            res.set_content(response.dump(), "application/json");
            res.status = 400;
        }
    });

    // Add these endpoints
    svr.Post("/api/process/terminate", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) {
            json response = {
                {"success", false},
                {"error", "Failed to open process"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        if (TerminateProcess(hProcess, 1)) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to terminate process"}
            };
            res.set_content(response.dump(), "application/json");
        }
        CloseHandle(hProcess);
    });

    svr.Post("/api/process/suspend", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        bool success = process_manager::ProcessInfoManager::SuspendProcess(pid);
        
        json response = {
            {"success", success},
            {"error", success ? "" : "Failed to suspend process"}
        };
        res.set_content(response.dump(), "application/json");
    });

    svr.Post("/api/process/resume", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        bool success = process_manager::ProcessInfoManager::ResumeProcess(pid);
        
        json response = {
            {"success", success},
            {"error", success ? "" : "Failed to resume process"}
        };
        res.set_content(response.dump(), "application/json");
    });

    // Get process modules
    svr.Get(R"(/api/process/(\d+)/modules)", [](const httplib::Request& req, httplib::Response& res) {
        auto pid = std::stoi(req.matches[1].str());
        auto modules = process_manager::ProcessInfoManager::GetProcessModules(pid);
        
        json j = json::array();
        for (const auto& mod : modules) {
            json module = {
                {"name", mod.name},
                {"path", mod.path},
                {"description", mod.description},
                {"baseAddress", [&mod]() {
                    std::stringstream ss;
                    ss << "0x" << std::uppercase << std::hex << mod.baseAddress;
                    return ss.str();
                }()},
                {"size", mod.size}
            };
            j.push_back(module);
        }
        
        res.set_content(j.dump(), "application/json");
    });

    // Unprotect process
    svr.Post("/api/unprotect", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            json response = {
                {"success", false},
                {"error", "Failed to open process"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE protectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        protectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        CloseHandle(hProcess);
        
        if (!found) {
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Unload the DLL
        HANDLE hUnloadProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
            PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        
        if (!hUnloadProcess) {
            json response = {
                {"success", false},
                {"error", "Failed to open process for unprotection"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        LPVOID pFreeLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
        HANDLE hThread = CreateRemoteThread(hUnloadProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pFreeLibrary, protectionDll, 0, NULL);
        
        if (!hThread) {
            CloseHandle(hUnloadProcess);
            json response = {
                {"success", false},
                {"error", "Failed to create unload thread"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        CloseHandle(hUnloadProcess);
        
        json response = {{"success", true}};
        res.set_content(response.dump(), "application/json");
    });

    // Check PE Headers Encryption Status
    svr.Post("/api/process/check_pe_headers", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Checking PE headers encryption status for process ID: " << pid << std::endl;
        
        // Check if we have cached metadata for this process
        bool isEncrypted = false;
        bool usedCache = false;
        
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && g_peMetadataCache[pid].isValid) {
            std::cout << "[WEB_UI] Using cached PE metadata for process " << pid << std::endl;
            
            if (g_peMetadataCache[pid].statusVariable) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hProcess) {
                    BOOL status = FALSE;
                    if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].statusVariable, &status, sizeof(status), NULL)) {
                        isEncrypted = (status != FALSE);
                        usedCache = true;
                        std::cout << "[WEB_UI] Read encryption status from cached address: " 
                                  << (isEncrypted ? "encrypted" : "not encrypted") << std::endl;
                    } else {
                        DWORD error = GetLastError();
                        std::cout << "[WEB_UI] Failed to read from cached status variable. Error: " << error << std::endl;
                    }
                    CloseHandle(hProcess);
                } else {
                    DWORD error = GetLastError();
                    std::cout << "[WEB_UI] Failed to open process for cached check. Error: " << error << std::endl;
                }
            } else {
                std::cout << "[WEB_UI] No cached status variable available" << std::endl;
            }
        }
        
        // If we successfully used the cache, we can return the result now
        if (usedCache) {
            std::cout << "[WEB_UI] PE header status check completed using cache. Headers are " 
                      << (isEncrypted ? "encrypted" : "not encrypted") << std::endl;
            
            json response = {
                {"success", true},
                {"isEncrypted", isEncrypted}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Otherwise, proceed with the standard check
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        std::cout << "[WEB_UI] Successfully opened process" << std::endl;
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        std::cout << "[WEB_UI] Searching for protection_dll.dll in process modules..." << std::endl;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        std::cout << "[WEB_UI] Found protection_dll.dll module at address: " << remoteProtectionDll << std::endl;
                        break;
                    }
                }
            }
        } else {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] EnumProcessModules failed with error: " << error << std::endl;
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }

        // Try to directly read the g_encryptionStatus variable from the DLL
        FARPROC pEncryptionStatus = NULL;
        
        std::cout << "[WEB_UI] Getting address of g_encryptionStatus variable using PE parser..." << std::endl;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "g_encryptionStatus", &pEncryptionStatus)) {
            std::cout << "[WEB_UI] Failed to find g_encryptionStatus export. Using alternative method." << std::endl;
        } else {
            std::cout << "[WEB_UI] Found g_encryptionStatus at address: " << pEncryptionStatus << std::endl;
            
            // Read the boolean value from the remote process memory
            BOOL status = FALSE;
            if (ReadProcessMemory(hProcess, pEncryptionStatus, &status, sizeof(status), NULL)) {
                isEncrypted = (status != FALSE);
                std::cout << "[WEB_UI] Successfully read encryption status: " 
                          << (isEncrypted ? "encrypted" : "not encrypted") << std::endl;
                
                // Cache this information for future use
                PEMetadataCache metadataCache;
                metadataCache.moduleBase = remoteProtectionDll;
                metadataCache.statusVariable = (bool*)pEncryptionStatus;
                metadataCache.isValid = true;
                g_peMetadataCache[pid] = metadataCache;
                std::cout << "[WEB_UI] Cached status variable for future use" << std::endl;
            } else {
                DWORD error = GetLastError();
                std::cout << "[WEB_UI] Failed to read encryption status memory. Error: " << error << std::endl;
            }
        }
        
        CloseHandle(hProcess);
        
        std::cout << "[WEB_UI] PE header status check completed. Headers are " 
                  << (isEncrypted ? "encrypted" : "not encrypted") << std::endl;
        
        json response = {
            {"success", true},
            {"isEncrypted", isEncrypted}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // Encrypt PE Headers
    svr.Post("/api/process/encrypt_pe_headers", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Attempting to encrypt PE headers for process ID: " << pid << std::endl;
        
        // Check if we already have cached metadata for this process
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && g_peMetadataCache[pid].isValid) {
            std::cout << "[WEB_UI] Using cached PE metadata for process " << pid << std::endl;
            
            // We already have cached data, check if encryption is already enabled
            bool isEncrypted = false;
            if (g_peMetadataCache[pid].statusVariable) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hProcess) {
                    BOOL status = FALSE;
                    if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].statusVariable, &status, sizeof(status), NULL)) {
                        isEncrypted = (status != FALSE);
                    }
                    CloseHandle(hProcess);
                }
            }
            
            if (isEncrypted) {
                std::cout << "[WEB_UI] PE headers are already encrypted" << std::endl;
                json response = {{"success", true}};
                res.set_content(response.dump(), "application/json");
                return;
            }
        }
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | 
                                     PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        std::cout << "[WEB_UI] Successfully opened process" << std::endl;
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        std::cout << "[WEB_UI] Searching for protection_dll.dll in process modules..." << std::endl;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        std::cout << "[WEB_UI] Found protection_dll.dll module at address: " << remoteProtectionDll << std::endl;
                        break;
                    }
                }
            }
        } else {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] EnumProcessModules failed with error: " << error << std::endl;
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Create a new PE metadata cache entry for this process
        PEMetadataCache metadataCache;
        metadataCache.moduleBase = remoteProtectionDll;
        metadataCache.isValid = true;
        
        // Cache all function addresses before encryption
        std::cout << "[WEB_UI] Caching PE metadata before encryption..." << std::endl;
        
        // Cache encryption function
        std::cout << "[WEB_UI] Getting address of Protection_EncryptPEHeaders function..." << std::endl;
        FARPROC pEncryptPEHeaders = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_EncryptPEHeaders", &pEncryptPEHeaders)) {
            std::cout << "[WEB_UI] Failed to find Protection_EncryptPEHeaders export" << std::endl;
            
            // Fallback to try with mangled name
            if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "?Protection_EncryptPEHeaders@@YAHXZ", &pEncryptPEHeaders)) {
                // Try the WINAPI version as a last resort
                if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_EncryptPEHeaders_WINAPI", &pEncryptPEHeaders)) {
                    CloseHandle(hProcess);
                    json response = {
                        {"success", false},
                        {"error", "Failed to find encryption function in DLL"}
                    };
                    res.set_content(response.dump(), "application/json");
                    return;
                }
            }
        }
        metadataCache.encryptFunction = pEncryptPEHeaders;
        std::cout << "[WEB_UI] Cached Protection_EncryptPEHeaders at address: " << pEncryptPEHeaders << std::endl;
        
        // Cache decryption function
        std::cout << "[WEB_UI] Getting address of Protection_DecryptPEHeaders function..." << std::endl;
        FARPROC pDecryptPEHeaders = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_DecryptPEHeaders", &pDecryptPEHeaders)) {
            std::cout << "[WEB_UI] Failed to find Protection_DecryptPEHeaders export" << std::endl;
            
            // Fallback to try with mangled name
            if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "?Protection_DecryptPEHeaders@@YAHXZ", &pDecryptPEHeaders)) {
                // Try the WINAPI version as a last resort
                if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_DecryptPEHeaders_WINAPI", &pDecryptPEHeaders)) {
                    std::cout << "[WEB_UI] Warning: Could not cache decryption function" << std::endl;
                }
            }
        }
        metadataCache.decryptFunction = pDecryptPEHeaders;
        if (pDecryptPEHeaders) {
            std::cout << "[WEB_UI] Cached Protection_DecryptPEHeaders at address: " << pDecryptPEHeaders << std::endl;
        }
        
        // Cache status variable
        std::cout << "[WEB_UI] Getting address of g_encryptionStatus variable..." << std::endl;
        FARPROC pEncryptionStatus = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "g_encryptionStatus", &pEncryptionStatus)) {
            std::cout << "[WEB_UI] Failed to find g_encryptionStatus export" << std::endl;
        } else {
            metadataCache.statusVariable = (bool*)pEncryptionStatus;
            std::cout << "[WEB_UI] Cached g_encryptionStatus at address: " << pEncryptionStatus << std::endl;
        }
        
        // Store the metadata cache
        g_peMetadataCache[pid] = metadataCache;
        std::cout << "[WEB_UI] Successfully cached PE metadata for process " << pid << std::endl;
        
        // Now execute the encryption function
        std::cout << "[WEB_UI] Creating remote thread to execute encrypt function..." << std::endl;
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pEncryptPEHeaders, NULL, 0, NULL);
        
        bool success = false;
        
        if (hThread) {
            std::cout << "[WEB_UI] Remote thread created successfully. Waiting for completion..." << std::endl;
            
            // Wait for thread completion with timeout (5 seconds)
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode)) {
                    success = (exitCode != 0);
                    std::cout << "[WEB_UI] Thread completed with exit code: " << exitCode 
                              << " (success: " << (success ? "true" : "false") << ")" << std::endl;
                } else {
                    DWORD error = GetLastError();
                    std::cout << "[WEB_UI] Failed to get thread exit code. Error: " << error << std::endl;
                }
            } else if (waitResult == WAIT_TIMEOUT) {
                std::cout << "[WEB_UI] Thread execution timed out after 5 seconds" << std::endl;
            } else {
                std::cout << "[WEB_UI] WaitForSingleObject failed with result: " << waitResult << std::endl;
            }
            
            CloseHandle(hThread);
        } else {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to create remote thread. Error: " << error << std::endl;
        }
        
        CloseHandle(hProcess);
        
        std::cout << "[WEB_UI] PE header encryption " << (success ? "succeeded" : "failed") << std::endl;
        
        if (success) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to encrypt PE headers"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // Decrypt PE Headers
    svr.Post("/api/process/decrypt_pe_headers", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Attempting to decrypt PE headers for process ID: " << pid << std::endl;
        
        FARPROC pDecryptPEHeaders = NULL;
        bool usedCache = false;
        
        // Check if we have cached metadata for this process
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && g_peMetadataCache[pid].isValid) {
            std::cout << "[WEB_UI] Found cached PE metadata for process " << pid << std::endl;
            
            if (g_peMetadataCache[pid].decryptFunction) {
                pDecryptPEHeaders = g_peMetadataCache[pid].decryptFunction;
                usedCache = true;
                std::cout << "[WEB_UI] Using cached decryption function address: " << pDecryptPEHeaders << std::endl;
            } else {
                std::cout << "[WEB_UI] No cached decryption function available" << std::endl;
            }
        }
        
        // Request all possible permissions to the process
        HANDLE hProcess = OpenProcess(
            PROCESS_ALL_ACCESS,  // Use PROCESS_ALL_ACCESS for maximum permissions
            FALSE, pid);
            
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        std::cout << "[WEB_UI] Successfully opened process" << std::endl;
        
        HMODULE remoteProtectionDll = NULL;
        
        // If we didn't use cache, we need to find the module and function
        if (!usedCache) {
            // Find the protection DLL
            HMODULE hMods[1024];
            DWORD cbNeeded;
            bool found = false;
            
            std::cout << "[WEB_UI] Searching for protection_dll.dll in process modules..." << std::endl;
            
            if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
                for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                    wchar_t szModName[MAX_PATH];
                    if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                        std::wstring moduleName = szModName;
                        if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                            remoteProtectionDll = hMods[i];
                            found = true;
                            std::cout << "[WEB_UI] Found protection_dll.dll module at address: " << remoteProtectionDll << std::endl;
                            break;
                        }
                    }
                }
            } else {
                DWORD error = GetLastError();
                std::cout << "[WEB_UI] EnumProcessModules failed with error: " << error << std::endl;
            }
            
            if (!found) {
                std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
                CloseHandle(hProcess);
                json response = {
                    {"success", false},
                    {"error", "Process is not protected"}
                };
                res.set_content(response.dump(), "application/json");
                return;
            }
            
            // Use our new function to get the address of DecryptPEHeaders - this may not work if headers are encrypted!
            std::cout << "[WEB_UI] Warning: No cached data available. Trying to get Protection_DecryptPEHeaders address..." << std::endl;
            std::cout << "[WEB_UI] Note: This will likely fail if the PE headers are already encrypted" << std::endl;
            
            if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_DecryptPEHeaders", &pDecryptPEHeaders)) {
                std::cout << "[WEB_UI] Failed to find Protection_DecryptPEHeaders export" << std::endl;
                
                // Fallback to try with mangled name
                if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "?Protection_DecryptPEHeaders@@YAHXZ", &pDecryptPEHeaders)) {
                    // Try the WINAPI version as a last resort
                    if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_DecryptPEHeaders_WINAPI", &pDecryptPEHeaders)) {
                        CloseHandle(hProcess);
                        json response = {
                            {"success", false},
                            {"error", "Failed to find decryption function in DLL (headers may already be encrypted)"}
                        };
                        res.set_content(response.dump(), "application/json");
                        return;
                    }
                }
            }
            
            std::cout << "[WEB_UI] Found Protection_DecryptPEHeaders function at address: " << pDecryptPEHeaders << std::endl;
        }
        
        // Try multiple methods to execute the decryption function
        std::cout << "[WEB_UI] Creating remote thread to execute decrypt function..." << std::endl;
        
        // Use RtlCreateUserThread as it's the only method that works reliably
        std::cout << "[WEB_UI] Using RtlCreateUserThread to create thread..." << std::endl;
        HANDLE hThread = CreateRemoteThreadUsingRtl(hProcess, pDecryptPEHeaders, NULL);
        
        bool success = false;
        
        // Check if any thread creation method succeeded
        if (hThread) {
            std::cout << "[WEB_UI] Remote thread created successfully. Waiting for completion..." << std::endl;
            
            // Wait for thread completion with timeout (5 seconds)
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode)) {
                    success = (exitCode != 0);
                    std::cout << "[WEB_UI] Thread completed with exit code: " << exitCode 
                              << " (success: " << (success ? "true" : "false") << ")" << std::endl;
                } else {
                    DWORD error = GetLastError();
                    std::cout << "[WEB_UI] Failed to get thread exit code. Error: " << error << std::endl;
                }
            } else if (waitResult == WAIT_TIMEOUT) {
                std::cout << "[WEB_UI] Thread execution timed out after 5 seconds" << std::endl;
            } else {
                std::cout << "[WEB_UI] WaitForSingleObject failed with result: " << waitResult << std::endl;
            }
            
            CloseHandle(hThread);
        } else {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] All thread creation methods failed. Last error: " << error << std::endl;
        }
        
        CloseHandle(hProcess);
        
        std::cout << "[WEB_UI] PE header decryption " << (success ? "succeeded" : "failed") << std::endl;
        
        if (success) {
            // If successful, clear the cache entry since the process is no longer protected
            if (g_peMetadataCache.find(pid) != g_peMetadataCache.end()) {
                std::cout << "[WEB_UI] Clearing cached PE metadata for process " << pid << std::endl;
                g_peMetadataCache.erase(pid);
            }
            
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to decrypt PE headers"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });

    // Check Memory Scan Detection Status
    svr.Post("/api/process/check_memory_scan", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Checking memory scan detection status for process ID: " << pid << std::endl;
        
        // Check if we have cached metadata for this process
        bool isEnabled = false;
        bool usedCache = false;
        
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && g_peMetadataCache[pid].isValid) {
            std::cout << "[WEB_UI] Using cached PE metadata for process " << pid << std::endl;
            
            // Try to read the g_memoryScanStatus variable directly if we have it cached
            if (g_peMetadataCache[pid].memoryScanVariable) {
                HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
                if (hProcess) {
                    BOOL status = FALSE;
                    if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].memoryScanVariable, &status, sizeof(status), NULL)) {
                        isEnabled = (status != FALSE);
                        usedCache = true;
                        std::cout << "[WEB_UI] Read memory scan status from cached address: " 
                                  << (isEnabled ? "enabled" : "disabled") << std::endl;
                    } else {
                        DWORD error = GetLastError();
                        std::cout << "[WEB_UI] Failed to read from cached memory scan status variable. Error: " << error << std::endl;
                    }
                    CloseHandle(hProcess);
                }
            }
        }
        
        // If we successfully used the cache, we can return the result now
        if (usedCache) {
            std::cout << "[WEB_UI] Memory scan detection status check completed using cache. Memory scan is " 
                      << (isEnabled ? "enabled" : "disabled") << std::endl;
            
            json response = {
                {"success", true},
                {"isEnabled", isEnabled}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Otherwise, proceed with the standard check
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }

        // Try to directly read the g_memoryScanStatus variable from the DLL
        FARPROC pMemoryScanStatus = NULL;
        
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "g_memoryScanStatus", &pMemoryScanStatus)) {
            std::cout << "[WEB_UI] Failed to find g_memoryScanStatus export." << std::endl;
        } else {
            // Read the boolean value from the remote process memory
            BOOL status = FALSE;
            if (ReadProcessMemory(hProcess, pMemoryScanStatus, &status, sizeof(status), NULL)) {
                isEnabled = (status != FALSE);
                
                // Cache this information for future use
                if (g_peMetadataCache.find(pid) != g_peMetadataCache.end()) {
                    g_peMetadataCache[pid].memoryScanVariable = (bool*)pMemoryScanStatus;
                } else {
                    PEMetadataCache metadataCache;
                    metadataCache.moduleBase = remoteProtectionDll;
                    metadataCache.memoryScanVariable = (bool*)pMemoryScanStatus;
                    metadataCache.isValid = true;
                    g_peMetadataCache[pid] = metadataCache;
                }
            }
        }
        
        CloseHandle(hProcess);
        
        std::cout << "[WEB_UI] Memory scan detection status check completed. Memory scan is " 
                  << (isEnabled ? "enabled" : "disabled") << std::endl;
        
        json response = {
            {"success", true},
            {"isEnabled", isEnabled}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // Enable Memory Scan Detection
    svr.Post("/api/process/enable_memory_scan", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Attempting to enable memory scan detection for process ID: " << pid << std::endl;
        
        // Check if memory scan detection is already enabled
        bool isEnabled = false;
        HANDLE hProcess = NULL;
        
        // Check cache first
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && 
            g_peMetadataCache[pid].isValid && g_peMetadataCache[pid].memoryScanVariable) {
            
            hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (hProcess) {
                BOOL status = FALSE;
                if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].memoryScanVariable, &status, sizeof(status), NULL)) {
                    isEnabled = (status != FALSE);
                    if (isEnabled) {
                        std::cout << "[WEB_UI] Memory scan detection is already enabled" << std::endl;
                        CloseHandle(hProcess);
                        json response = {{"success", true}};
                        res.set_content(response.dump(), "application/json");
                        return;
                    }
                }
                CloseHandle(hProcess);
            }
        }
        
        // Open process with all necessary permissions
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the memory scan enable function
        FARPROC pEnableMemoryScan = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_EnableMemoryScanDetection", &pEnableMemoryScan)) {
            std::cout << "[WEB_UI] Failed to find Protection_EnableMemoryScanDetection export" << std::endl;
            
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Failed to find memory scan detection function"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the memory scan status variable
        FARPROC pMemoryScanStatus = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "g_memoryScanStatus", &pMemoryScanStatus)) {
            std::cout << "[WEB_UI] Failed to find g_memoryScanStatus export" << std::endl;
        }
        
        // Cache this information
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end()) {
            g_peMetadataCache[pid].enableMemoryScanFunction = pEnableMemoryScan;
            g_peMetadataCache[pid].memoryScanVariable = (bool*)pMemoryScanStatus;
        } else {
            PEMetadataCache metadataCache;
            metadataCache.moduleBase = remoteProtectionDll;
            metadataCache.enableMemoryScanFunction = pEnableMemoryScan;
            metadataCache.memoryScanVariable = (bool*)pMemoryScanStatus;
            metadataCache.isValid = true;
            g_peMetadataCache[pid] = metadataCache;
        }
        
        // Execute the memory scan enable function
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pEnableMemoryScan, NULL, 0, NULL);
        
        bool success = false;
        
        if (hThread) {
            // Wait for thread completion with timeout (5 seconds)
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode)) {
                    success = (exitCode != 0);
                }
            }
            
            CloseHandle(hThread);
        }
        
        CloseHandle(hProcess);
        
        if (success) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to enable memory scan detection"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // Disable Memory Scan Detection
    svr.Post("/api/process/disable_memory_scan", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Attempting to disable memory scan detection for process ID: " << pid << std::endl;
        
        // Check if memory scan detection is already disabled
        bool isEnabled = true;
        HANDLE hProcess = NULL;
        
        // Check cache first
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && 
            g_peMetadataCache[pid].isValid && g_peMetadataCache[pid].memoryScanVariable) {
            
            hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (hProcess) {
                BOOL status = TRUE;
                if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].memoryScanVariable, &status, sizeof(status), NULL)) {
                    isEnabled = (status != FALSE);
                    if (!isEnabled) {
                        std::cout << "[WEB_UI] Memory scan detection is already disabled" << std::endl;
                        CloseHandle(hProcess);
                        json response = {{"success", true}};
                        res.set_content(response.dump(), "application/json");
                        return;
                    }
                }
                CloseHandle(hProcess);
            }
        }
        
        // Open process with all necessary permissions
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the memory scan disable function
        FARPROC pDisableMemoryScan = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_DisableMemoryScanDetection", &pDisableMemoryScan)) {
            std::cout << "[WEB_UI] Failed to find Protection_DisableMemoryScanDetection export" << std::endl;
            
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Failed to find memory scan detection function"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Execute the memory scan disable function
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pDisableMemoryScan, NULL, 0, NULL);
        
        bool success = false;
        
        if (hThread) {
            // Wait for thread completion with timeout (5 seconds)
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode)) {
                    success = (exitCode != 0);
                }
            }
            
            CloseHandle(hThread);
        }
        
        CloseHandle(hProcess);
        
        if (success) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to disable memory scan detection"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // Check Anti-Tampering Status
    svr.Post("/api/process/check_anti_tampering", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Checking anti-tampering status for process ID: " << pid << std::endl;
        
        // Check if we have cached metadata for this process
        bool isEnabled = false;
        bool usedCache = false;
        
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && g_peMetadataCache[pid].isValid) {
            std::cout << "[WEB_UI] Using cached PE metadata for process " << pid << std::endl;
            
            // Try to read the g_antiTamperingStatus variable directly if we have it cached
            if (g_peMetadataCache[pid].antiTamperingVariable) {
                HANDLE hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
                if (hProcess) {
                    BOOL status = FALSE;
                    if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].antiTamperingVariable, &status, sizeof(status), NULL)) {
                        isEnabled = (status != FALSE);
                        usedCache = true;
                        std::cout << "[WEB_UI] Read anti-tampering status from cached address: " 
                                  << (isEnabled ? "enabled" : "disabled") << std::endl;
                    } else {
                        DWORD error = GetLastError();
                        std::cout << "[WEB_UI] Failed to read from cached anti-tampering status variable. Error: " << error << std::endl;
                    }
                    CloseHandle(hProcess);
                }
            }
        }
        
        // If we successfully used the cache, we can return the result now
        if (usedCache) {
            std::cout << "[WEB_UI] Anti-tampering status check completed using cache. Anti-tampering is " 
                      << (isEnabled ? "enabled" : "disabled") << std::endl;
            
            json response = {
                {"success", true},
                {"isEnabled", isEnabled}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Otherwise, proceed with the standard check
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Try to directly read the g_antiTamperingStatus variable from the DLL
        FARPROC pAntiTamperingStatus = NULL;
        
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "g_antiTamperingStatus", &pAntiTamperingStatus)) {
            std::cout << "[WEB_UI] Failed to find g_antiTamperingStatus export." << std::endl;
        } else {
            // Read the boolean value from the remote process memory
            BOOL status = FALSE;
            if (ReadProcessMemory(hProcess, pAntiTamperingStatus, &status, sizeof(status), NULL)) {
                isEnabled = (status != FALSE);
                
                // Cache this information for future use
                if (g_peMetadataCache.find(pid) != g_peMetadataCache.end()) {
                    g_peMetadataCache[pid].antiTamperingVariable = (bool*)pAntiTamperingStatus;
                } else {
                    PEMetadataCache metadataCache;
                    metadataCache.moduleBase = remoteProtectionDll;
                    metadataCache.antiTamperingVariable = (bool*)pAntiTamperingStatus;
                    metadataCache.isValid = true;
                    g_peMetadataCache[pid] = metadataCache;
                }
            }
        }
        
        CloseHandle(hProcess);
        
        std::cout << "[WEB_UI] Anti-tampering status check completed. Anti-tampering is " 
                  << (isEnabled ? "enabled" : "disabled") << std::endl;
        
        json response = {
            {"success", true},
            {"isEnabled", isEnabled}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // Enable Anti-Tampering
    svr.Post("/api/process/enable_anti_tampering", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Attempting to enable anti-tampering for process ID: " << pid << std::endl;
        
        // Check if anti-tampering is already enabled
        bool isEnabled = false;
        HANDLE hProcess = NULL;
        
        // Check cache first
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && 
            g_peMetadataCache[pid].isValid && g_peMetadataCache[pid].antiTamperingVariable) {
            
            hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (hProcess) {
                BOOL status = FALSE;
                if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].antiTamperingVariable, &status, sizeof(status), NULL)) {
                    isEnabled = (status != FALSE);
                    if (isEnabled) {
                        std::cout << "[WEB_UI] Anti-tampering is already enabled" << std::endl;
                        CloseHandle(hProcess);
                        json response = {{"success", true}};
                        res.set_content(response.dump(), "application/json");
                        return;
                    }
                }
                CloseHandle(hProcess);
            }
        }
        
        // Open process with all necessary permissions
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the anti-tampering enable function
        FARPROC pEnableAntiTampering = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_EnableAntiTampering", &pEnableAntiTampering)) {
            std::cout << "[WEB_UI] Failed to find Protection_EnableAntiTampering export" << std::endl;
            
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Failed to find anti-tampering function"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the anti-tampering status variable
        FARPROC pAntiTamperingStatus = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "g_antiTamperingStatus", &pAntiTamperingStatus)) {
            std::cout << "[WEB_UI] Failed to find g_antiTamperingStatus export" << std::endl;
        }
        
        // Cache this information
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end()) {
            g_peMetadataCache[pid].enableAntiTamperingFunction = pEnableAntiTampering;
            g_peMetadataCache[pid].antiTamperingVariable = (bool*)pAntiTamperingStatus;
        } else {
            PEMetadataCache metadataCache;
            metadataCache.moduleBase = remoteProtectionDll;
            metadataCache.enableAntiTamperingFunction = pEnableAntiTampering;
            metadataCache.antiTamperingVariable = (bool*)pAntiTamperingStatus;
            metadataCache.isValid = true;
            g_peMetadataCache[pid] = metadataCache;
        }
        
        // Execute the anti-tampering enable function
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pEnableAntiTampering, NULL, 0, NULL);
        
        bool success = false;
        
        if (hThread) {
            // Wait for thread completion with timeout (5 seconds)
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode)) {
                    success = (exitCode != 0);
                }
            }
            
            CloseHandle(hThread);
        }
        
        CloseHandle(hProcess);
        
        if (success) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to enable anti-tampering"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // Disable Anti-Tampering
    svr.Post("/api/process/disable_anti_tampering", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Attempting to disable anti-tampering for process ID: " << pid << std::endl;
        
        // Check if anti-tampering is already disabled
        bool isEnabled = true;
        HANDLE hProcess = NULL;
        
        // Check cache first
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && 
            g_peMetadataCache[pid].isValid && g_peMetadataCache[pid].antiTamperingVariable) {
            
            hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (hProcess) {
                BOOL status = TRUE;
                if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].antiTamperingVariable, &status, sizeof(status), NULL)) {
                    isEnabled = (status != FALSE);
                    if (!isEnabled) {
                        std::cout << "[WEB_UI] Anti-tampering is already disabled" << std::endl;
                        CloseHandle(hProcess);
                        json response = {{"success", true}};
                        res.set_content(response.dump(), "application/json");
                        return;
                    }
                }
                CloseHandle(hProcess);
            }
        }
        
        // Open process with all necessary permissions
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the anti-tampering disable function
        FARPROC pDisableAntiTampering = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_DisableAntiTampering", &pDisableAntiTampering)) {
            std::cout << "[WEB_UI] Failed to find Protection_DisableAntiTampering export" << std::endl;
            
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Failed to find anti-tampering function"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Execute the anti-tampering disable function
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pDisableAntiTampering, NULL, 0, NULL);
        
        bool success = false;
        
        if (hThread) {
            // Wait for thread completion with timeout (5 seconds)
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode)) {
                    success = (exitCode != 0);
                }
            }
            
            CloseHandle(hThread);
        }
        
        CloseHandle(hProcess);
        
        if (success) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to disable anti-tampering"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // Check Thread Monitoring Status
    svr.Post("/api/process/check_thread_monitoring", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Checking thread monitoring status for process ID: " << pid << std::endl;
        
        // Check if we have cached metadata for this process
        bool isEnabled = false;
        bool usedCache = false;
        
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && g_peMetadataCache[pid].isValid) {
            std::cout << "[WEB_UI] Using cached PE metadata for process " << pid << std::endl;
            
            // Try to read the g_threadMonitoringStatus variable directly if we have it cached
            if (g_peMetadataCache[pid].threadMonitoringVariable) {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
                if (hProcess) {
                    BOOL status = FALSE;
                    if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].threadMonitoringVariable, &status, sizeof(status), NULL)) {
                        isEnabled = (status != FALSE);
                        usedCache = true;
                        std::cout << "[WEB_UI] Read thread monitoring status from cached address: " 
                                  << (isEnabled ? "enabled" : "disabled") << std::endl;
                    } else {
                        DWORD error = GetLastError();
                        std::cout << "[WEB_UI] Failed to read from cached thread monitoring status variable. Error: " << error << std::endl;
                    }
                    CloseHandle(hProcess);
                }
            }
        }
        
        // If we successfully used the cache, we can return the result now
        if (usedCache) {
            std::cout << "[WEB_UI] Thread monitoring status check completed using cache. Thread monitoring is " 
                      << (isEnabled ? "enabled" : "disabled") << std::endl;
            
            json response = {
                {"success", true},
                {"isEnabled", isEnabled}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Otherwise, proceed with the standard check
        HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Try to directly read the g_threadMonitoringStatus variable from the DLL
        FARPROC pThreadMonitoringStatus = NULL;
        
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "g_threadMonitoringStatus", &pThreadMonitoringStatus)) {
            std::cout << "[WEB_UI] Failed to find g_threadMonitoringStatus export." << std::endl;
        } else {
            // Read the boolean value from the remote process memory
            BOOL status = FALSE;
            if (ReadProcessMemory(hProcess, pThreadMonitoringStatus, &status, sizeof(status), NULL)) {
                isEnabled = (status != FALSE);
                
                // Cache this information for future use
                if (g_peMetadataCache.find(pid) != g_peMetadataCache.end()) {
                    g_peMetadataCache[pid].threadMonitoringVariable = (bool*)pThreadMonitoringStatus;
                } else {
                    PEMetadataCache metadataCache;
                    metadataCache.moduleBase = remoteProtectionDll;
                    metadataCache.threadMonitoringVariable = (bool*)pThreadMonitoringStatus;
                    metadataCache.isValid = true;
                    g_peMetadataCache[pid] = metadataCache;
                }
            }
        }
        
        CloseHandle(hProcess);
        
        std::cout << "[WEB_UI] Thread monitoring status check completed. Thread monitoring is " 
                  << (isEnabled ? "enabled" : "disabled") << std::endl;
        
        json response = {
            {"success", true},
            {"isEnabled", isEnabled}
        };
        res.set_content(response.dump(), "application/json");
    });
    
    // Enable Thread Monitoring
    svr.Post("/api/process/enable_thread_monitoring", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Attempting to enable thread monitoring for process ID: " << pid << std::endl;
        
        // Check if thread monitoring is already enabled
        bool isEnabled = false;
        HANDLE hProcess = NULL;
        
        // Check cache first
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && 
            g_peMetadataCache[pid].isValid && g_peMetadataCache[pid].threadMonitoringVariable) {
            
            hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (hProcess) {
                BOOL status = FALSE;
                if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].threadMonitoringVariable, &status, sizeof(status), NULL)) {
                    isEnabled = (status != FALSE);
                    if (isEnabled) {
                        std::cout << "[WEB_UI] Thread monitoring is already enabled" << std::endl;
                        CloseHandle(hProcess);
                        json response = {{"success", true}};
                        res.set_content(response.dump(), "application/json");
                        return;
                    }
                }
                CloseHandle(hProcess);
            }
        }
        
        // Open process with all necessary permissions
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the thread monitoring enable function
        FARPROC pEnableThreadMonitoring = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_EnableThreadMonitoring", &pEnableThreadMonitoring)) {
            std::cout << "[WEB_UI] Failed to find Protection_EnableThreadMonitoring export" << std::endl;
            
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Failed to find thread monitoring function"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the thread monitoring status variable
        FARPROC pThreadMonitoringStatus = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "g_threadMonitoringStatus", &pThreadMonitoringStatus)) {
            std::cout << "[WEB_UI] Failed to find g_threadMonitoringStatus export" << std::endl;
        }
        
        // Cache this information
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end()) {
            g_peMetadataCache[pid].enableThreadMonitoringFunction = pEnableThreadMonitoring;
            g_peMetadataCache[pid].threadMonitoringVariable = (bool*)pThreadMonitoringStatus;
        } else {
            PEMetadataCache metadataCache;
            metadataCache.moduleBase = remoteProtectionDll;
            metadataCache.enableThreadMonitoringFunction = pEnableThreadMonitoring;
            metadataCache.threadMonitoringVariable = (bool*)pThreadMonitoringStatus;
            metadataCache.isValid = true;
            g_peMetadataCache[pid] = metadataCache;
        }
        
        // Execute the thread monitoring enable function
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pEnableThreadMonitoring, NULL, 0, NULL);
        
        bool success = false;
        
        if (hThread) {
            // Wait for thread completion with timeout (5 seconds)
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode)) {
                    success = (exitCode != 0);
                }
            }
            
            CloseHandle(hThread);
        }
        
        CloseHandle(hProcess);
        
        if (success) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to enable thread monitoring"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });
    
    // Disable Thread Monitoring
    svr.Post("/api/process/disable_thread_monitoring", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        std::cout << "\n[WEB_UI] Attempting to disable thread monitoring for process ID: " << pid << std::endl;
        
        // Check if thread monitoring is already disabled
        bool isEnabled = true;
        HANDLE hProcess = NULL;
        
        // Check cache first
        if (g_peMetadataCache.find(pid) != g_peMetadataCache.end() && 
            g_peMetadataCache[pid].isValid && g_peMetadataCache[pid].threadMonitoringVariable) {
            
            hProcess = OpenProcess(PROCESS_VM_READ, FALSE, pid);
            if (hProcess) {
                BOOL status = TRUE;
                if (ReadProcessMemory(hProcess, g_peMetadataCache[pid].threadMonitoringVariable, &status, sizeof(status), NULL)) {
                    isEnabled = (status != FALSE);
                    if (!isEnabled) {
                        std::cout << "[WEB_UI] Thread monitoring is already disabled" << std::endl;
                        CloseHandle(hProcess);
                        json response = {{"success", true}};
                        res.set_content(response.dump(), "application/json");
                        return;
                    }
                }
                CloseHandle(hProcess);
            }
        }
        
        // Open process with all necessary permissions
        hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!hProcess) {
            DWORD error = GetLastError();
            std::cout << "[WEB_UI] Failed to open process with error code: " << error << std::endl;
            
            json response = {
                {"success", false},
                {"error", "Failed to open process (Error: " + std::to_string(error) + ")"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE remoteProtectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        remoteProtectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        if (!found) {
            std::cout << "[WEB_UI] Protection DLL not found in process" << std::endl;
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Cache the thread monitoring disable function
        FARPROC pDisableThreadMonitoring = NULL;
        if (!GetRemoteProcAddress(hProcess, remoteProtectionDll, "Protection_DisableThreadMonitoring", &pDisableThreadMonitoring)) {
            std::cout << "[WEB_UI] Failed to find Protection_DisableThreadMonitoring export" << std::endl;
            
            CloseHandle(hProcess);
            json response = {
                {"success", false},
                {"error", "Failed to find thread monitoring function"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Execute the thread monitoring disable function
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pDisableThreadMonitoring, NULL, 0, NULL);
        
        bool success = false;
        
        if (hThread) {
            // Wait for thread completion with timeout (5 seconds)
            DWORD waitResult = WaitForSingleObject(hThread, 5000);
            
            if (waitResult == WAIT_OBJECT_0) {
                DWORD exitCode = 0;
                if (GetExitCodeThread(hThread, &exitCode)) {
                    success = (exitCode != 0);
                }
            }
            
            CloseHandle(hThread);
        }
        
        CloseHandle(hProcess);
        
        if (success) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to disable thread monitoring"}
            };
            res.set_content(response.dump(), "application/json");
        }
    });

    std::cout << "Server started on http://localhost:8080" << std::endl;
    svr.listen("localhost", 8080);
    
    return 0;
}
