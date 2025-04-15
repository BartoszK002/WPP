#include "process_manager/process_info.h"
#include "process_manager/windows_api.h"
#include "process_manager/system_info.h"
#include "process_manager/icon_manager.h"
#include <psapi.h>
#include <tlhelp32.h>

#pragma comment(lib, "version.lib")

namespace process_manager {

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    DWORD* processId = (DWORD*)lParam;
    DWORD windowProcessId = 0;
    GetWindowThreadProcessId(hwnd, &windowProcessId);
    
    if (*processId == windowProcessId) {
        if (IsWindowVisible(hwnd) && 
            !(GetWindowLongW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) &&
            GetWindow(hwnd, GW_OWNER) == NULL) {
            *processId = 0;  // Flag to indicate we found a window
            return FALSE;    // Stop enumeration
        }
    }
    return TRUE;  // Continue enumeration
}

bool ProcessInfoManager::HasVisibleWindow(DWORD pid) {
    DWORD processId = pid;
    EnumWindows(EnumWindowsCallback, (LPARAM)&processId);
    return processId == 0;  // If processId is 0, we found a window
}

bool ProcessInfoManager::IsProcessProtected(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        return false;
    }

    HMODULE hModules[1024];
    DWORD cbNeeded;

    if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded)) {
        for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            wchar_t szModName[MAX_PATH];
            if (GetModuleFileNameExW(hProcess, hModules[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                std::wstring moduleName = szModName;
                if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                    CloseHandle(hProcess);
                    return true;
                }
            }
        }
    }

    CloseHandle(hProcess);
    return false;
}

bool ProcessInfoManager::IsWindowsSystemProcess(const std::wstring& processName, DWORD pid) {
    static const std::unordered_set<std::wstring> systemProcesses = {
        L"System",
        L"Registry",
        L"smss.exe",
        L"csrss.exe",
        L"wininit.exe",
        L"services.exe",
        L"lsass.exe",
        L"winlogon.exe",
        L"fontdrvhost.exe",
        L"dwm.exe",
        L"svchost.exe",
        L"Memory Compression",
        L"System Idle Process",
        L"spoolsv.exe",
        L"SearchIndexer.exe",
        L"WmiPrvSE.exe",
        L"dllhost.exe",
        L"sihost.exe",
        L"taskhostw.exe",
        L"explorer.exe",
        L"RuntimeBroker.exe",
        L"SearchHost.exe",
        L"StartMenuExperienceHost.exe",
        L"TextInputHost.exe",
        L"ctfmon.exe",
        L"conhost.exe",
        L"SecurityHealthService.exe",
        L"SecurityHealthSystray.exe",
        L"SgrmBroker.exe",
        L"audiodg.exe"
    };

    if (pid == 0 || pid == 4) {
        return true;
    }

    return systemProcesses.find(processName) != systemProcesses.end();
}

std::string ProcessInfoManager::GetProcessUsername(HANDLE hProcess) {
    if (!hProcess) return "N/A";

    HANDLE hToken = NULL;
    if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
        return "N/A";
    }

    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);
    if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
        CloseHandle(hToken);
        return "N/A";
    }

    std::vector<BYTE> buffer(dwSize);
    PTOKEN_USER pTokenUser = reinterpret_cast<PTOKEN_USER>(&buffer[0]);

    if (!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize)) {
        CloseHandle(hToken);
        return "N/A";
    }

    WCHAR szUser[256] = {0};
    WCHAR szDomain[256] = {0};
    DWORD cchUser = 256;
    DWORD cchDomain = 256;
    SID_NAME_USE snu;

    if (!LookupAccountSidW(
        NULL,
        pTokenUser->User.Sid,
        szUser,
        &cchUser,
        szDomain,
        &cchDomain,
        &snu)) {
        CloseHandle(hToken);
        return "N/A";
    }

    CloseHandle(hToken);

    std::wstring username = std::wstring(szDomain) + L"\\" + szUser;
    return ConvertToString(username);
}

double ProcessInfoManager::GetProcessCpuUsage(HANDLE hProcess) {
    static ULARGE_INTEGER lastCPU, lastSysCPU, lastUserCPU;
    static DWORD lastProcessTime = 0;
    
    FILETIME ftime, fsys, fuser;
    ULARGE_INTEGER now, sys, user;
    double percent = 0.0;

    GetSystemTimeAsFileTime(&ftime);
    memcpy(&now, &ftime, sizeof(FILETIME));

    GetProcessTimes(hProcess, &ftime, &ftime, &fsys, &fuser);
    memcpy(&sys, &fsys, sizeof(FILETIME));
    memcpy(&user, &fuser, sizeof(FILETIME));

    if (lastProcessTime != 0) {
        percent = (sys.QuadPart - lastSysCPU.QuadPart) +
                 (user.QuadPart - lastUserCPU.QuadPart);
        percent /= (now.QuadPart - lastCPU.QuadPart);
        percent /= GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
        percent *= 100;
    }

    lastCPU = now;
    lastSysCPU = sys;
    lastUserCPU = user;
    lastProcessTime = GetTickCount();

    return percent;
}

SIZE_T ProcessInfoManager::GetProcessPrivateWorkingSet(HANDLE hProcess) {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        return pmc.PrivateUsage;
    }
    return 0;
}

std::string ProcessInfoManager::GetProcessStatus(HANDLE hProcess) {
    DWORD pid = GetProcessId(hProcess);
    // std::cout << "\n[GetProcessStatus] Checking status for PID: " << pid << std::endl;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        // std::cout << "[GetProcessStatus] Failed to create thread snapshot. Error: " << GetLastError() << std::endl;
        return "Running";
    }

    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);
    int threadCount = 0;
    int suspendedCount = 0;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threadCount++;
                // std::cout << "[GetProcessStatus] Checking thread " << te32.th32ThreadID << std::endl;
                
                HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    DWORD suspendCount = SuspendThread(hThread);
                    // std::cout << "[GetProcessStatus] Thread " << te32.th32ThreadID 
                    //          << " initial suspend count: " << suspendCount << std::endl;
                    
                    if (suspendCount != (DWORD)-1) {
                        ResumeThread(hThread);  // Restore the thread state
                        if (suspendCount > 0) {
                            suspendedCount++;
                            // std::cout << "[GetProcessStatus] Thread " << te32.th32ThreadID 
                            //          << " is suspended" << std::endl;
                        } else {
                            // std::cout << "[GetProcessStatus] Thread " << te32.th32ThreadID 
                            //          << " is running" << std::endl;
                            CloseHandle(hThread);
                            CloseHandle(hSnapshot);
                            return "Running";
                        }
                    } else {
                        // std::cout << "[GetProcessStatus] Failed to get suspend count for thread " 
                        //          << te32.th32ThreadID << " Error: " << GetLastError() << std::endl;
                    }
                    CloseHandle(hThread);
                } else {
                    // std::cout << "[GetProcessStatus] Failed to open thread " << te32.th32ThreadID 
                    //          << " Error: " << GetLastError() << std::endl;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }
    CloseHandle(hSnapshot);

    // std::cout << "[GetProcessStatus] Process summary - Total threads: " << threadCount 
    //           << ", Suspended threads: " << suspendedCount << std::endl;

    if (threadCount > 0 && threadCount == suspendedCount) {
        // std::cout << "[GetProcessStatus] All threads are suspended, marking process as Suspended" << std::endl;
        return "Suspended";
    }

    // std::cout << "[GetProcessStatus] Not all threads are suspended, marking process as Running" << std::endl;
    return "Running";
}

std::string ProcessInfoManager::GetProcessCommandLine(HANDLE hProcess) {
    if (!hProcess) {
        // std::cout << "[GetProcessCommandLine] Invalid process handle" << std::endl;
        return "N/A";
    }

    bool is64Bit = SystemInfo::IsProcess64Bit(hProcess);
    // std::cout << "[GetProcessCommandLine] Process architecture: " << (is64Bit ? "64-bit" : "32-bit") << std::endl;
    
#ifdef _WIN64
    if (!is64Bit) {
        // std::cout << "[GetProcessCommandLine] Handling 32-bit process from 64-bit code" << std::endl;
        
        HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
        if (!hNtDll) {
            // std::cout << "[GetProcessCommandLine] GetModuleHandleW failed, error: " << GetLastError() << std::endl;
            return "N/A";
        }

        auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
            GetProcAddress(hNtDll, "NtQueryInformationProcess")
        );
        
        if (!NtQueryInformationProcess) {
            // std::cout << "[GetProcessCommandLine] GetProcAddress failed, error: " << GetLastError() << std::endl;
            return "N/A";
        }
        
        PVOID peb32Address = NULL;
        NTSTATUS status = NtQueryInformationProcess(
            hProcess,
            ProcessWow64Information,
            &peb32Address,
            sizeof(peb32Address),
            NULL
        );
        
        if (!NT_SUCCESS(status) || peb32Address == NULL) {
            // std::cout << "[GetProcessCommandLine] NtQueryInformationProcess failed with status: " << status << std::endl;
            return "N/A";
        }
        
        PEB32 peb32 = { 0 };
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, peb32Address, &peb32, sizeof(peb32), &bytesRead)) {
            DWORD error = GetLastError();
            // std::cout << "[GetProcessCommandLine] Failed to read PEB32, error: " << error << std::endl;
            return "N/A";
        }
        
        RTL_USER_PROCESS_PARAMETERS32 processParams32 = { 0 };
        if (!ReadProcessMemory(hProcess, (PVOID)(ULONG_PTR)peb32.ProcessParameters, &processParams32, sizeof(processParams32), &bytesRead)) {
            DWORD error = GetLastError();
            // std::cout << "[GetProcessCommandLine] Failed to read RTL_USER_PROCESS_PARAMETERS32, error: " << error << std::endl;
            return "N/A";
        }
        
        UNICODE_STRING32 commandLineUnicode = processParams32.CommandLine;
        
        if (commandLineUnicode.Length == 0 || commandLineUnicode.Buffer == 0) {
            // std::cout << "[GetProcessCommandLine] Command line buffer is empty or null" << std::endl;
            return "";
        }
        
        std::wstring cmdLine(commandLineUnicode.Length / sizeof(WCHAR), L'\0');
        if (!ReadProcessMemory(hProcess, (PVOID)(ULONG_PTR)commandLineUnicode.Buffer, &cmdLine[0], commandLineUnicode.Length, &bytesRead)) {
            DWORD error = GetLastError();
            // std::cout << "[GetProcessCommandLine] Failed to read command line buffer, error: " << error << std::endl;
            return "N/A";
        }
        
        // std::cout << "[GetProcessCommandLine] Successfully retrieved command line for 32-bit process" << std::endl;
        return ConvertToString(cmdLine);
    }
#endif

    // std::cout << "[GetProcessCommandLine] Handling native architecture process" << std::endl;
    PROCESS_BASIC_INFORMATION pbi;
    ULONG returnLength;
    
    HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtDll) {
        // std::cout << "[GetProcessCommandLine] Failed to get ntdll.dll handle" << std::endl;
        return "N/A";
    }
    
    auto NtQueryInformationProcess = reinterpret_cast<NtQueryInformationProcessFn>(
        GetProcAddress(hNtDll, "NtQueryInformationProcess")
    );
    
    if (!NtQueryInformationProcess) {
        // std::cout << "[GetProcessCommandLine] Failed to get NtQueryInformationProcess function" << std::endl;
        return "N/A";
    }
    
    NTSTATUS status = NtQueryInformationProcess(
        hProcess,
        ProcessBasicInformation,
        &pbi,
        sizeof(pbi),
        &returnLength
    );
    
    if (status != 0) {
        // std::cout << "[GetProcessCommandLine] NtQueryInformationProcess failed with status: " << status << std::endl;
        return "N/A";
    }
    
    PEB peb;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessCommandLine] Failed to read PEB, error: " << error << std::endl;
        return "N/A";
    }
    
    RTL_USER_PROCESS_PARAMETERS processParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &processParams, sizeof(processParams), &bytesRead)) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessCommandLine] Failed to read RTL_USER_PROCESS_PARAMETERS, error: " << error << std::endl;
        return "N/A";
    }
    
    if (processParams.CommandLine.Length == 0 || processParams.CommandLine.Buffer == 0) {
        // std::cout << "[GetProcessCommandLine] Command line buffer is empty or null" << std::endl;
        return "";
    }
    
    std::wstring cmdLine(processParams.CommandLine.Length / sizeof(WCHAR), L'\0');
    if (!ReadProcessMemory(hProcess, processParams.CommandLine.Buffer, &cmdLine[0], processParams.CommandLine.Length, &bytesRead)) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessCommandLine] Failed to read command line buffer, error: " << error << std::endl;
        return "N/A";
    }
    
    // std::cout << "[GetProcessCommandLine] Successfully retrieved command line" << std::endl;
    return ConvertToString(cmdLine);
}

ProcessInfo ProcessInfoManager::GetProcessDetails(DWORD pid) {
    ProcessInfo info;
    info.pid = pid;
    
    // std::cout << "\n[GetProcessDetails] Starting process details retrieval for PID: " << pid << std::endl;
    
    // Check if process is 64-bit or 32-bit
    bool is64BitProcess = false;
    
    // Open process to check architecture
    HANDLE hArchProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hArchProcess) {
        info.is64Bit = SystemInfo::IsProcess64Bit(hArchProcess);
        // std::cout << "[GetProcessDetails] Process architecture: " << (info.is64Bit ? "64-bit" : "32-bit") << std::endl;
        CloseHandle(hArchProcess);
    } else {
        // Fall back to limited access
        hArchProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hArchProcess) {
            info.is64Bit = SystemInfo::IsProcess64Bit(hArchProcess);
            // std::cout << "[GetProcessDetails] Process architecture (limited access): " << (info.is64Bit ? "64-bit" : "32-bit") << std::endl;
            CloseHandle(hArchProcess);
        } else {
            info.is64Bit = false; // Default to 32-bit
            // std::cout << "[GetProcessDetails] Failed to determine process architecture, defaulting to 32-bit" << std::endl;
        }
    }
    
    // Open process with full access
    HANDLE hProcess = OpenProcess(
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_TERMINATE | PROCESS_SUSPEND_RESUME, 
        FALSE, pid);
        
    if (!hProcess) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessDetails] Failed to open process with full access, error: " << error << ". Trying limited access..." << std::endl;
        
        // Try with limited access
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (!hProcess) {
            error = GetLastError();
            // std::cout << "[GetProcessDetails] Failed to open process with limited access, error: " << error << std::endl;
            return info;
        } else {
            // std::cout << "[GetProcessDetails] Successfully opened process with limited access" << std::endl;
        }
    } else {
        // std::cout << "[GetProcessDetails] Successfully opened process with full access" << std::endl;
    }

    // Get process name and path
    WCHAR pathW[MAX_PATH] = {0};
    DWORD pathSize = MAX_PATH;

    if (!QueryFullProcessImageNameW(hProcess, 0, pathW, &pathSize)) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessDetails] QueryFullProcessImageNameW failed, error: " << error << ". Trying GetModuleFileNameExW..." << std::endl;
        
        if (!GetModuleFileNameExW(hProcess, nullptr, pathW, MAX_PATH)) {
            error = GetLastError();
            // std::cout << "[GetProcessDetails] GetModuleFileNameExW failed, error: " << error << std::endl;
            
            // If both methods fail for 32-bit process, try using NtQueryInformationProcess
            if (!info.is64Bit) {
                // std::cout << "[GetProcessDetails] Attempting to get path using NtQueryInformationProcess for 32-bit process..." << std::endl;
#ifdef _WIN64
                PROCESS_BASIC_INFORMATION32 pbi32;
                ULONG returnLength;

                HMODULE hNtDll = GetModuleHandleW(L"ntdll.dll");
                if (hNtDll) {
                    auto NtWow64QueryInformationProcess32 = reinterpret_cast<NtWow64QueryInformationProcess32Fn>(
                        GetProcAddress(hNtDll, "NtWow64QueryInformationProcess32")
                    );

                    if (NtWow64QueryInformationProcess32) {
                        NTSTATUS status = NtWow64QueryInformationProcess32(
                            hProcess,
                            ProcessBasicInformation,
                            &pbi32,
                            sizeof(pbi32),
                            &returnLength
                        );

                        if (status != 0) {
                            // std::cout << "[GetProcessDetails] NtWow64QueryInformationProcess32 failed, status: " << status << std::endl;
                        } else {
                            // std::cout << "[GetProcessDetails] Successfully got process information, reading PEB..." << std::endl;
                            
                            PEB32 peb32;
                            SIZE_T bytesRead;
                            if (!ReadProcessMemory(hProcess, (PVOID)(ULONG_PTR)pbi32.PebBaseAddress, &peb32, sizeof(peb32), &bytesRead)) {
                                error = GetLastError();
                                // std::cout << "[GetProcessDetails] Failed to read PEB, error: " << error << std::endl;
                            } else {
                                RTL_USER_PROCESS_PARAMETERS32 processParams32;
                                if (!ReadProcessMemory(hProcess, (PVOID)(ULONG_PTR)peb32.ProcessParameters, &processParams32, sizeof(processParams32), &bytesRead)) {
                                    error = GetLastError();
                                    // std::cout << "[GetProcessDetails] Failed to read process parameters, error: " << error << std::endl;
                                } else {
                                    if (processParams32.ImagePathName.Length > 0 && processParams32.ImagePathName.Buffer != 0) {
                                        std::wstring imagePath(processParams32.ImagePathName.Length / sizeof(WCHAR), L'\0');
                                        if (!ReadProcessMemory(hProcess, (PVOID)(ULONG_PTR)processParams32.ImagePathName.Buffer, &imagePath[0], processParams32.ImagePathName.Length, &bytesRead)) {
                                            error = GetLastError();
                                            // std::cout << "[GetProcessDetails] Failed to read image path, error: " << error << std::endl;
                                        } else {
                                            wcscpy_s(pathW, MAX_PATH, imagePath.c_str());
                                            // std::cout << "[GetProcessDetails] Successfully retrieved image path using PEB method" << std::endl;
                                        }
                                    } else {
                                        // std::cout << "[GetProcessDetails] Image path information is empty in process parameters" << std::endl;
                                    }
                                }
                            }
                        }
                    }
                }
#endif
            }
        } else {
            // std::cout << "[GetProcessDetails] Successfully got process path using GetModuleFileNameExW" << std::endl;
        }
    } else {
        // std::cout << "[GetProcessDetails] Successfully got process path using QueryFullProcessImageNameW" << std::endl;
    }

    if (pathW[0] != L'\0') {
        info.imagePath = ConvertToString(pathW);
        std::wstring wpath(pathW);
        info.description = ProcessInfoManager::GetProcessDescription(wpath);
        size_t pos = wpath.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            info.name = ConvertToString(wpath.substr(pos + 1));
            // std::cout << "[GetProcessDetails] Process name: " << info.name << std::endl;
            // std::cout << "[GetProcessDetails] Image path: " << info.imagePath << std::endl;
        }
    } else {
        // std::cout << "[GetProcessDetails] Path retrieval failed, attempting to get name from process handle..." << std::endl;
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            WCHAR szModName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMod, szModName, sizeof(szModName)/sizeof(WCHAR))) {
                info.name = ConvertToString(szModName);
                info.imagePath = info.name;
                // std::cout << "[GetProcessDetails] Got process name from module: " << info.name << std::endl;
            } else {
                DWORD error = GetLastError();
                // std::cout << "[GetProcessDetails] GetModuleBaseNameW failed, error: " << error << std::endl;
                info.name = "N/A";
                info.imagePath = "N/A";
            }
        } else {
            DWORD error = GetLastError();
            // std::cout << "[GetProcessDetails] EnumProcessModules failed, error: " << error << std::endl;
            info.name = "N/A";
            info.imagePath = "N/A";
        }
    }

    // Get other process details
    // std::cout << "[GetProcessDetails] Retrieving additional process information..." << std::endl;
    
    info.username = GetProcessUsername(hProcess);
    // std::cout << "[GetProcessDetails] Username: " << info.username << std::endl;
    
    info.cpuUsage = GetProcessCpuUsage(hProcess);
    // std::cout << "[GetProcessDetails] CPU Usage: " << info.cpuUsage << "%" << std::endl;
    
    info.workingSetPrivate = GetProcessPrivateWorkingSet(hProcess);
    // std::cout << "[GetProcessDetails] Private Working Set: " << info.workingSetPrivate << " bytes" << std::endl;
    
    info.commandLine = GetProcessCommandLine(hProcess);
    // std::cout << "[GetProcessDetails] Command Line: " << (info.commandLine.empty() ? "N/A" : info.commandLine) << std::endl;
    
    info.status = GetProcessStatus(hProcess);
    // std::cout << "[GetProcessDetails] Process Status: " << info.status << std::endl;
    
    info.isProtected = IsProcessProtected(pid);
    // std::cout << "[GetProcessDetails] Protected: " << (info.isProtected ? "Yes" : "No") << std::endl;
    
    info.iconBase64 = IconManager::GetProcessIconBase64(pid);
    // std::cout << "[GetProcessDetails] Icon retrieved: " << (!info.iconBase64.empty() ? "Yes" : "No") << std::endl;
    
    info.hasVisibleWindow = HasVisibleWindow(pid);
    // std::cout << "[GetProcessDetails] Has Visible Window: " << (info.hasVisibleWindow ? "Yes" : "No") << std::endl;

    CloseHandle(hProcess);
    // std::cout << "[GetProcessDetails] Process details retrieval completed for PID: " << pid << "\n" << std::endl;
    return info;
}

std::string ProcessInfoManager::GetProcessDescription(const std::wstring& filePath) {
    // std::cout << "[GetProcessDescription] Attempting to get description for: " << ConvertToString(filePath) << std::endl;

    DWORD handle = 0;
    DWORD size = GetFileVersionInfoSizeW(filePath.c_str(), &handle);
    if (size == 0) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessDescription] GetFileVersionInfoSizeW failed. Error: " << error << std::endl;
        return "";
    }

    // std::cout << "[GetProcessDescription] Version info size: " << size << " bytes" << std::endl;
    std::vector<BYTE> buffer(size);
    if (!GetFileVersionInfoW(filePath.c_str(), handle, size, buffer.data())) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessDescription] GetFileVersionInfoW failed. Error: " << error << std::endl;
        return "";
    }

    struct LANGANDCODEPAGE {
        WORD language;
        WORD codePage;
    } *translations;
    UINT translationSize = 0;

    // Get translation info
    if (!VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation",
        (LPVOID*)&translations, &translationSize)) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessDescription] VerQueryValueW for Translation failed. Error: " << error << std::endl;
        return "";
    }

    // std::cout << "[GetProcessDescription] Found " << (translationSize / sizeof(LANGANDCODEPAGE)) 
    //           << " language translations" << std::endl;

    // Try each translation
    for (UINT i = 0; i < (translationSize / sizeof(LANGANDCODEPAGE)); i++) {
        // Format sub-block string
        wchar_t subBlock[50];
        swprintf_s(subBlock, L"\\StringFileInfo\\%04x%04x\\FileDescription",
            translations[i].language, translations[i].codePage);

        // std::cout << "[GetProcessDescription] Trying language/codepage: " 
        //           << std::hex << translations[i].language << "/" 
        //           << translations[i].codePage << std::dec << std::endl;

        LPWSTR description = nullptr;
        UINT descriptionLen = 0;

        // Get description
        if (VerQueryValueW(buffer.data(), subBlock, (LPVOID*)&description, &descriptionLen)) {
            if (description && descriptionLen) {
                std::string desc = ConvertToString(description);
                // std::cout << "[GetProcessDescription] Found description: " << desc << std::endl;
                return desc;
            }
            // std::cout << "[GetProcessDescription] VerQueryValueW succeeded but description is empty" << std::endl;
        } else {
            DWORD error = GetLastError();
            // std::cout << "[GetProcessDescription] VerQueryValueW for FileDescription failed. Error: " << error << std::endl;
        }
    }

    // std::cout << "[GetProcessDescription] No description found after trying all translations" << std::endl;
    return "";
}

bool ProcessInfoManager::SuspendProcess(DWORD pid) {
    return SetProcessState(pid, true);
}

bool ProcessInfoManager::ResumeProcess(DWORD pid) {
    return SetProcessState(pid, false);
}

bool ProcessInfoManager::SetProcessState(DWORD pid, bool suspend) {
    // std::cout << "\n[SetProcessState] " << (suspend ? "Suspending" : "Resuming") 
    //           << " process " << pid << std::endl;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        // std::cout << "[SetProcessState] Failed to create thread snapshot. Error: " << GetLastError() << std::endl;
        return false;
    }

    bool success = true;
    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);
    std::vector<HANDLE> threadHandles;
    int threadCount = 0;

    if (Thread32First(hSnapshot, &te32)) {
        do {
            if (te32.th32OwnerProcessID == pid) {
                threadCount++;
                // std::cout << "[SetProcessState] Found thread " << te32.th32ThreadID << std::endl;
                
                HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
                if (hThread) {
                    threadHandles.push_back(hThread);
                } else {
                    // std::cout << "[SetProcessState] Failed to open thread " << te32.th32ThreadID 
                    //         << " Error: " << GetLastError() << std::endl;
                    success = false;
                }
            }
        } while (Thread32Next(hSnapshot, &te32));
    }

    CloseHandle(hSnapshot);
    // std::cout << "[SetProcessState] Found " << threadCount << " threads, successfully opened " 
    //           << threadHandles.size() << " threads" << std::endl;

    if (!threadHandles.empty()) {
        for (HANDLE hThread : threadHandles) {
            if (suspend) {
                DWORD prevCount = SuspendThread(hThread);
                // std::cout << "[SetProcessState] Suspended thread, previous suspend count: " 
                //          << prevCount << std::endl;
                if (prevCount == (DWORD)-1) {
                    success = false;
                }
            } else {
                int resumeCount = 0;
                DWORD result;
                do {
                    result = ResumeThread(hThread);
                    resumeCount++;
                    // std::cout << "[SetProcessState] Resume attempt " << resumeCount 
                    //          << ", result: " << result << std::endl;
                } while (result > 0);  // Keep resuming until count is 0
                
                if (result == (DWORD)-1) {
                    success = false;
                }
            }
            CloseHandle(hThread);
        }
    }

    // std::cout << "[SetProcessState] " << (suspend ? "Suspend" : "Resume") 
    //           << " operation completed with " << (success ? "success" : "failure") 
    //           << " for PID: " << pid << "\n" << std::endl;

    return success;
}

std::vector<ModuleInfo> ProcessInfoManager::GetProcessModules(DWORD pid) {
    std::vector<ModuleInfo> modules;
    
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        // std::cout << "[GetProcessModules] Failed to open process. Error: " << GetLastError() << std::endl;
        return modules;
    }

    HMODULE hMods[2048];  // Increased buffer size
    DWORD cbNeeded;

    // Use EnumProcessModulesEx to get all modules including 32-bit ones
    if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL)) {
        // std::cout << "[GetProcessModules] Found " << (cbNeeded / sizeof(HMODULE)) << " modules" << std::endl;
        for (unsigned int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
            ModuleInfo module;
            WCHAR szModPath[MAX_PATH];
            
            // Get module path
            if (GetModuleFileNameExW(hProcess, hMods[i], szModPath, sizeof(szModPath)/sizeof(WCHAR))) {
                module.path = ConvertToString(szModPath);
                
                // Get module name (filename only)
                std::wstring wpath(szModPath);
                size_t pos = wpath.find_last_of(L"\\");
                if (pos != std::wstring::npos) {
                    module.name = ConvertToString(wpath.substr(pos + 1));
                } else {
                    module.name = module.path;
                }

                // Get module info (base address and size)
                MODULEINFO modInfo;
                if (GetModuleInformation(hProcess, hMods[i], &modInfo, sizeof(modInfo))) {
                    module.baseAddress = reinterpret_cast<uintptr_t>(modInfo.lpBaseOfDll);
                    module.size = modInfo.SizeOfImage;
                    // std::cout << "[GetProcessModules] Module: " << module.name 
                    //          << " Base: 0x" << std::hex << module.baseAddress 
                    //          << " Size: " << std::dec << module.size << std::endl;
                }

                // Get module description
                module.description = GetProcessDescription(wpath);
                
                modules.push_back(module);
            }
        }
    } else {
        // std::cout << "[GetProcessModules] EnumProcessModulesEx failed. Error: " << GetLastError() << std::endl;
    }

    CloseHandle(hProcess);
    return modules;
}

} // namespace process_manager 