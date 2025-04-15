#include <windows.h>
#include "protection.h"
#include <fstream>
#include <string>

// Log function to write to a file in a predictable location
void WriteToLog(const std::string& message) {
    std::ofstream logFile("C:\\Windows\\Temp\\protection_dll_log.txt", std::ios::app);
    if (logFile.is_open()) {
        logFile << message << std::endl;
        logFile.close();
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize protection features
        WriteToLog("DLL_PROCESS_ATTACH: Initializing protection features");
        Protection_Initialize();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        // Cleanup protection features
        WriteToLog("DLL_PROCESS_DETACH: Cleaning up protection features");
        Protection_Shutdown();
        break;
    }
    return TRUE;
}

// Create WINAPI wrapper functions that delegate to the existing exports
extern "C" {
    __declspec(dllexport) DWORD WINAPI Protection_IsPEHeadersEncrypted_WINAPI(LPVOID lpParam)
    {
        WriteToLog("Protection_IsPEHeadersEncrypted_WINAPI called");
        return Protection_IsPEHeadersEncrypted();
    }

    __declspec(dllexport) DWORD WINAPI Protection_EncryptPEHeaders_WINAPI(LPVOID lpParam)
    {
        WriteToLog("Protection_EncryptPEHeaders_WINAPI called");
        BOOL result = Protection_EncryptPEHeaders();
        DWORD error = GetLastError();
        
        if (result) {
            WriteToLog("Protection_EncryptPEHeaders_WINAPI succeeded");
        } else {
            char errorMsg[256];
            sprintf_s(errorMsg, "Protection_EncryptPEHeaders_WINAPI failed with error code: %lu", error);
            WriteToLog(errorMsg);
        }
        
        return result;
    }

    __declspec(dllexport) DWORD WINAPI Protection_DecryptPEHeaders_WINAPI(LPVOID lpParam)
    {
        WriteToLog("Protection_DecryptPEHeaders_WINAPI called");
        BOOL result = Protection_DecryptPEHeaders();
        DWORD error = GetLastError();
        
        if (result) {
            WriteToLog("Protection_DecryptPEHeaders_WINAPI succeeded");
        } else {
            char errorMsg[256];
            sprintf_s(errorMsg, "Protection_DecryptPEHeaders_WINAPI failed with error code: %lu", error);
            WriteToLog(errorMsg);
        }
        
        return result;
    }
}
