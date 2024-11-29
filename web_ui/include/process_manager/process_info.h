#pragma once
#include "base.h"

namespace process_manager {
    struct ProcessInfo {
        DWORD pid;
        std::string name;
        bool isProtected;
        std::string iconBase64;    
        bool is64Bit;              
        bool hasVisibleWindow;     
        std::string status;        
        std::string username;      
        double cpuUsage;          
        SIZE_T workingSetPrivate; 
        std::string imagePath;    
        std::string commandLine;  
        std::string description;  
    };

    struct ModuleInfo {
        std::string name;
        std::string path;
        std::string description;
        uintptr_t baseAddress;
        SIZE_T size;
    };

    class ProcessInfoManager {
    public:
        static ProcessInfo GetProcessDetails(DWORD pid);
        static std::string GetProcessUsername(HANDLE hProcess);
        static double GetProcessCpuUsage(HANDLE hProcess);
        static SIZE_T GetProcessPrivateWorkingSet(HANDLE hProcess);
        static std::string GetProcessCommandLine(HANDLE hProcess);
        static std::string GetProcessStatus(HANDLE hProcess);
        static bool HasVisibleWindow(DWORD pid);
        static bool IsProcessProtected(DWORD pid);
        static bool IsWindowsSystemProcess(const std::wstring& processName, DWORD pid);
        static std::string GetProcessDescription(const std::wstring& filePath);
        static bool SuspendProcess(DWORD pid);
        static bool ResumeProcess(DWORD pid);
        static std::vector<ModuleInfo> GetProcessModules(DWORD pid);
    private:
        static bool SetProcessState(DWORD pid, bool suspend);
    };
} 