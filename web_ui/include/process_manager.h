#pragma once

#include "process_manager/base.h"
#include "process_manager/process_info.h"
#include "process_manager/icon_manager.h"
#include "process_manager/system_info.h"

namespace process_manager {
    class ProcessManager {
    public:
        // Get list of running processes
        std::vector<ProcessInfo> GetRunningProcesses(bool includeSystemProcesses = true);
        
        // Inject protection DLL into a process
        bool InjectProtectionDLL(DWORD pid, std::string& errorMsg);
        
        // Get detailed information about a specific process
        ProcessInfo GetProcessDetails(DWORD pid);
    };
}
