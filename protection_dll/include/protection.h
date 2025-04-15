#pragma once

#include <Windows.h>
#include <vector>
#include <string>

// Define exports
#ifdef PROTECTION_DLL_EXPORTS
#define PROTECTION_API __declspec(dllexport)
#else
#define PROTECTION_API __declspec(dllimport)
#endif

// Exported functions (accessible from outside the DLL)
extern "C" {
    PROTECTION_API BOOL Protection_Initialize();
    PROTECTION_API BOOL Protection_Shutdown();
    
    PROTECTION_API BOOL Protection_EncryptPEHeaders();
    PROTECTION_API BOOL Protection_DecryptPEHeaders();
    PROTECTION_API BOOL Protection_IsPEHeadersEncrypted();
    
    // Memory scan detection functions
    PROTECTION_API BOOL Protection_EnableMemoryScanDetection();
    PROTECTION_API BOOL Protection_DisableMemoryScanDetection();
    PROTECTION_API BOOL Protection_IsMemoryScanDetectionEnabled();
    
    // Anti-tampering functions
    PROTECTION_API BOOL Protection_EnableAntiTampering();
    PROTECTION_API BOOL Protection_DisableAntiTampering();
    PROTECTION_API BOOL Protection_IsAntiTamperingEnabled();
    
    // Thread monitoring functions
    PROTECTION_API BOOL Protection_EnableThreadMonitoring();
    PROTECTION_API BOOL Protection_DisableThreadMonitoring();
    PROTECTION_API BOOL Protection_IsThreadMonitoringEnabled();
    
    // Export status variables directly
    PROTECTION_API extern BOOL g_encryptionStatus;
    PROTECTION_API extern BOOL g_memoryScanStatus;
    PROTECTION_API extern BOOL g_antiTamperingStatus;
    PROTECTION_API extern BOOL g_threadMonitoringStatus;
}

// Non-exported functions (internal to the DLL)
namespace protection {
    // Size of PE headers to encrypt
    constexpr size_t PE_HEADER_SIZE = 4096;  // Usually PE headers are within first 4KB
    
    // XOR key for PE header encryption (simple demonstration)
    const BYTE g_encryptionKey = 0x77;
    
    // Global variables to track state
    extern HMODULE g_baseAddress;
    extern std::vector<BYTE> g_originalHeaders;
    extern bool g_isPEHeadersEncrypted;
    extern bool g_isMemoryScanDetectionEnabled;
    extern LPVOID g_canaryAddress;
    extern LPVOID g_WSMemList[16384];  // Working set memory list

    // Anti-tampering feature variables
    extern bool g_isAntiTamperingEnabled;
    extern std::vector<std::pair<void*, size_t>> g_monitoredSections;
    extern std::vector<std::pair<void*, uint32_t>> g_sectionHashes;
    extern HANDLE g_antiTamperingThread;
    
    // Thread monitoring feature variables
    extern bool g_isThreadMonitoringEnabled;
    extern std::vector<std::pair<void*, size_t>> g_moduleRegions;
    extern HANDLE g_threadMonitoringThread;
    
    // Function declarations
    bool EncryptPEHeaders();
    bool DecryptPEHeaders();
    bool IsPEHeadersEncrypted();
    
    bool EnableMemoryScanDetection();
    bool DisableMemoryScanDetection();
    bool IsMemoryScanDetectionEnabled();
    bool InitializeMemoryScanDetection();
    bool FindAddressInWorkingSet(LPVOID addr);
    DWORD WINAPI MemoryScanDetectionThread(LPVOID lpParam);

    // Anti-tampering functions
    bool EnableAntiTampering();
    bool DisableAntiTampering();
    bool IsAntiTamperingEnabled();
    bool InitializeAntiTampering();
    uint32_t CalculateCrc32(const void* data, size_t length);
    bool VerifySectionIntegrity();
    DWORD WINAPI AntiTamperingThread(LPVOID lpParam);
    
    // Thread monitoring functions
    bool EnableThreadMonitoring();
    bool DisableThreadMonitoring();
    bool IsThreadMonitoringEnabled();
    bool InitializeThreadMonitoring();
    bool IsAddressInKnownModule(LPVOID address);
    bool UpdateModuleList();
    bool CheckForSuspiciousThreads();
    DWORD WINAPI ThreadMonitoringThread(LPVOID lpParam);
    
    void LogToFile(const std::string& message);
}

namespace Protection {
    bool Initialize();
    void Cleanup();
    bool HookMemoryAllocation();
    bool PreventRemoteThreads();
    bool StripHandles();
    
    // PE Header protection functions
    bool EncryptPEHeaders();
    bool DecryptPEHeaders();
    bool IsPEHeadersEncrypted();
}
