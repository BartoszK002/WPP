#include "handle_monitor.h"
#include <windows.h>
#include <vector>
#include <tlhelp32.h>

namespace Protection {

bool StripProcessHandles() {
    DWORD currentPid = GetCurrentProcessId();
    
    // Get a list of all processes
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(pe32);
    std::vector<DWORD> processIds;

    if (Process32FirstW(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID != currentPid) {
                processIds.push_back(pe32.th32ProcessID);
            }
        } while (Process32NextW(hSnapshot, &pe32));
    }

    CloseHandle(hSnapshot);

    // For each process, try to close any handles to our process
    for (DWORD pid : processIds) {
        HANDLE hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, pid);
        if (hProcess == NULL) {
            continue;
        }

        // Get a list of handles in the target process
        HANDLE hDupHandle;
        if (DuplicateHandle(hProcess, NULL, GetCurrentProcess(), &hDupHandle, 0, FALSE, DUPLICATE_SAME_ACCESS)) {
            CloseHandle(hDupHandle);
        }

        CloseHandle(hProcess);
    }

    return true;
}

bool MonitorHandleCreation() {
    // TODO: Implement handle creation monitoring using Windows hooks
    return true;
}

} // namespace Protection
