#include "process_manager.h"
#include "process_manager/windows_api.h"
#include <TlHelp32.h>
#include <filesystem>
#include <psapi.h>

namespace process_manager {

std::vector<ProcessInfo> ProcessManager::GetRunningProcesses(bool includeSystemProcesses) {
    std::vector<ProcessInfo> processes;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    
    if (snapshot != INVALID_HANDLE_VALUE) {
        PROCESSENTRY32W processEntry;
        processEntry.dwSize = sizeof(processEntry);
        
        if (Process32FirstW(snapshot, &processEntry)) {
            do {
                ProcessInfo info;
                info.pid = processEntry.th32ProcessID;
                
                // Convert wide string to UTF-8
                int size = WideCharToMultiByte(CP_UTF8, 0, processEntry.szExeFile, -1, nullptr, 0, nullptr, nullptr);
                if (size > 0) {
                    std::string utf8Name(size - 1, 0);
                    WideCharToMultiByte(CP_UTF8, 0, processEntry.szExeFile, -1, &utf8Name[0], size, nullptr, nullptr);
                    info.name = utf8Name;
                }
                
                if (!includeSystemProcesses && ProcessInfoManager::IsWindowsSystemProcess(processEntry.szExeFile, info.pid)) {
                    continue;
                }
                
                info.isProtected = ProcessInfoManager::IsProcessProtected(info.pid);
                info.iconBase64 = IconManager::GetProcessIconBase64(info.pid);
                info.hasVisibleWindow = ProcessInfoManager::HasVisibleWindow(info.pid);
                
                // Get process architecture
                HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, info.pid);
                if (processHandle != NULL) {
                    info.is64Bit = SystemInfo::IsProcess64Bit(processHandle);
                    CloseHandle(processHandle);
                } else {
                    info.is64Bit = false;  // Default to 32-bit if we can't access the process
                }
                
                processes.push_back(info);
            } while (Process32NextW(snapshot, &processEntry));
        }
        CloseHandle(snapshot);
    }
    return processes;
}

bool ProcessManager::InjectProtectionDLL(DWORD pid, std::string& errorMsg) {
    // Get process name and architecture for logging
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    std::string processName = "Unknown";
    bool targetIs64Bit = false;

    if (hProcess) {
        wchar_t processPath[MAX_PATH];
        if (GetModuleFileNameExW(hProcess, NULL, processPath, MAX_PATH)) {
            processName = std::filesystem::path(processPath).filename().string();
        }
        targetIs64Bit = SystemInfo::IsProcess64Bit(hProcess);
        CloseHandle(hProcess);
    }
    
    std::cout << "\nAttempting to inject protection DLL into process: " << processName << " (PID: " << pid << ")" << std::endl;
    std::cout << "Target process architecture: " << (targetIs64Bit ? "x64" : "x86") << std::endl;

    // Check architecture compatibility
    BOOL isWow64;
    IsWow64Process(GetCurrentProcess(), &isWow64);
    bool currentIs64Bit = !isWow64;

    if (currentIs64Bit != targetIs64Bit) {
        errorMsg = "Architecture mismatch: Cannot inject " + 
                  std::string(currentIs64Bit ? "64-bit" : "32-bit") + 
                  " DLL into " + 
                  std::string(targetIs64Bit ? "64-bit" : "32-bit") + 
                  " process";
        std::cout << "Error: " << errorMsg << std::endl;
        return false;
    }
    
    // Get the full path of the DLL
    std::filesystem::path dllPath = L"C:\\Users\\BK\\Documents\\GitHub\\WPP\\build\\protection_dll\\Release\\protection_dll.dll";

    std::wcout << L"DLL Path: " << dllPath.wstring() << std::endl;
    
    if (!std::filesystem::exists(dllPath)) {
        errorMsg = "Protection DLL not found at: " + dllPath.string();
        std::cout << "Error: " << errorMsg << std::endl;
        return false;
    }

    // Get process handle with all necessary access rights
    hProcess = OpenProcess(
        PROCESS_CREATE_THREAD | 
        PROCESS_QUERY_INFORMATION | 
        PROCESS_VM_OPERATION | 
        PROCESS_VM_WRITE | 
        PROCESS_VM_READ,
        FALSE, 
        pid
    );

    if (!hProcess) {
        DWORD error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL);
        
        errorMsg = "Failed to open process '" + processName + "': " + (char*)lpMsgBuf;
        std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        return false;
    }

    // Get LoadLibraryW address
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (!loadLibraryAddr) {
        DWORD error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL);
        
        errorMsg = "Failed to get LoadLibraryW address: " + std::string((char*)lpMsgBuf);
        std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        CloseHandle(hProcess);
        return false;
    }

    // Allocate memory for DLL path
    size_t dllPathSize = (dllPath.wstring().length() + 1) * sizeof(wchar_t);
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!dllPathAddr) {
        DWORD error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL);
        
        errorMsg = "Failed to allocate memory in process '" + processName + "': " + (char*)lpMsgBuf;
        std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        CloseHandle(hProcess);
        return false;
    }

    // Write DLL path
    if (!WriteProcessMemory(hProcess, dllPathAddr, dllPath.wstring().c_str(), dllPathSize, NULL)) {
        DWORD error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL);
        
        errorMsg = "Failed to write to process memory '" + processName + "': " + (char*)lpMsgBuf;
        std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Creating remote thread to load DLL..." << std::endl;
    
    // Create remote thread
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, NULL);
    if (!hThread) {
        DWORD error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL);
        
        errorMsg = "Failed to create remote thread in process '" + processName + "': " + (char*)lpMsgBuf;
        std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Waiting for thread completion..." << std::endl;
    
    // Wait for thread completion
    DWORD waitResult = WaitForSingleObject(hThread, 5000); // 5 second timeout
    if (waitResult != WAIT_OBJECT_0) {
        DWORD error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL);
        
        errorMsg = "DLL injection timed out for process '" + processName + "': " + (char*)lpMsgBuf;
        std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get thread exit code
    DWORD exitCode;
    if (!GetExitCodeThread(hThread, &exitCode)) {
        DWORD error = GetLastError();
        LPVOID lpMsgBuf;
        FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL);
            
        errorMsg = "Failed to get thread exit code from process '" + processName + "': " + (char*)lpMsgBuf;
        std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "Thread exit code (LoadLibrary result): 0x" << std::hex << exitCode << std::dec << std::endl;

    if (exitCode == 0) {
        // Try to determine why LoadLibrary failed
        DWORD error = 0;
        BOOL isTarget32Bit = FALSE;
        BOOL isTarget64Bit = FALSE;
        
        HANDLE hFile = CreateFileW(dllPath.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            error = GetLastError();
        } else {
            CloseHandle(hFile);
            
            BOOL isSystem64Bit = FALSE;
            SYSTEM_INFO sysInfo;
            GetNativeSystemInfo(&sysInfo);
            isSystem64Bit = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);

#ifdef _WIN64
            IsWow64Process(hProcess, &isTarget32Bit);
            if (isTarget32Bit) {
                error = ERROR_BAD_EXE_FORMAT;
            }
#else
            IsWow64Process(hProcess, &isTarget64Bit);
            if (!isTarget64Bit && isSystem64Bit) {
                error = ERROR_BAD_EXE_FORMAT;
            }
#endif
            if (error == 0) {
                error = ERROR_BAD_EXE_FORMAT;
            }
        }
        
        std::string additionalInfo;
        if (error == ERROR_BAD_EXE_FORMAT) {
#ifdef _WIN64
            additionalInfo = " (Architecture mismatch: trying to inject 64-bit DLL into ";
            additionalInfo += isTarget32Bit ? "32-bit" : "64-bit";
            additionalInfo += " process)";
#else
            additionalInfo = " (Architecture mismatch: trying to inject 32-bit DLL into ";
            additionalInfo += isTarget64Bit ? "64-bit" : "32-bit";
            additionalInfo += " process)";
#endif
        }

        LPVOID lpMsgBuf;
        if (FormatMessage(
            FORMAT_MESSAGE_ALLOCATE_BUFFER | 
            FORMAT_MESSAGE_FROM_SYSTEM |
            FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL,
            error,
            MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
            (LPTSTR) &lpMsgBuf,
            0, NULL) == 0) {
            errorMsg = "Failed to inject DLL into process '" + processName + "': Unable to load DLL (Error code: " + 
                      std::to_string(error) + ")" + additionalInfo;
        } else {
            std::string errorText = (char*)lpMsgBuf;
            size_t pos;
            while ((pos = errorText.find("%1")) != std::string::npos) {
                errorText.replace(pos, 2, "DLL");
            }
            errorMsg = "Failed to inject DLL into process '" + processName + "': " + errorText + additionalInfo;
            LocalFree(lpMsgBuf);
        }
        
        std::cout << "Error: " << errorMsg << std::endl;
        
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    std::cout << "DLL injection successful!" << std::endl;

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

ProcessInfo ProcessManager::GetProcessDetails(DWORD pid) {
    return ProcessInfoManager::GetProcessDetails(pid);
}

} // namespace process_manager 