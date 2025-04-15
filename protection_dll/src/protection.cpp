#include <windows.h>
#include <string>
#include "protection.h"
#include "handle_monitor.h"
#include <psapi.h>
#include <vector>
#include <ntstatus.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <ctime>
#include <winnt.h>
#include <tlhelp32.h>

#ifdef _MSC_VER
#pragma warning(disable: 4005) // Disable macro redefinition warnings
#endif

// Link against ntdll.lib for NT API functions
#pragma comment(lib, "ntdll.lib")

// External imports for memory scan detection
extern "C" {
    NTSTATUS NTAPI ZwQueryInformationProcess(HANDLE, ULONG, PVOID, ULONG, PULONG);
    NTSTATUS NTAPI ZwSetInformationProcess(HANDLE, ULONG, PVOID, ULONG);
    NTSTATUS NTAPI ZwQueryVirtualMemory(HANDLE, PVOID, ULONG, PVOID, SIZE_T, PSIZE_T);
}

// Define exported variables - use dllexport only in implementation
extern "C" __declspec(dllexport) BOOL g_encryptionStatus = FALSE;
extern "C" __declspec(dllexport) BOOL g_memoryScanStatus = FALSE;
extern "C" __declspec(dllexport) BOOL g_antiTamperingStatus = FALSE;
extern "C" __declspec(dllexport) BOOL g_threadMonitoringStatus = FALSE;

// Define internal variables
namespace protection {
    HMODULE g_baseAddress = NULL;
    std::vector<BYTE> g_originalHeaders;
    bool g_isPEHeadersEncrypted = false;
    bool g_isMemoryScanDetectionEnabled = false;
    LPVOID g_canaryAddress = NULL;
    LPVOID g_WSMemList[16384] = { 0 };
    HANDLE g_memoryScanThread = NULL;
    
    // Anti-tampering variables
    bool g_isAntiTamperingEnabled = false;
    std::vector<std::pair<void*, size_t>> g_monitoredSections;
    std::vector<std::pair<void*, uint32_t>> g_sectionHashes;
    HANDLE g_antiTamperingThread = NULL;
    
    // Thread monitoring variables
    bool g_isThreadMonitoringEnabled = false;
    std::vector<std::pair<void*, size_t>> g_moduleRegions;
    HANDLE g_threadMonitoringThread = NULL;
}

using namespace protection;

// Log to file function
void protection::LogToFile(const std::string& message) {
    std::ofstream logFile("protection.log", std::ios::app);
    if (!logFile.is_open()) return;
    
    // Get current time
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    
    std::ostringstream timestamp;
    timestamp << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    
    logFile << "[" << timestamp.str() << "] " << message << std::endl;
    logFile.close();
}

// Initialize function - use dllexport only in implementation
extern "C" __declspec(dllexport) BOOL Protection_Initialize() {
    LogToFile("Protection module initialized");
    
    // Initialize base address of main executable
    g_baseAddress = GetModuleHandle(NULL);
    if (!g_baseAddress) {
        LogToFile("ERROR: Failed to get main executable base address");
        return FALSE;
    }
    
    LogToFile("Successfully obtained module base address");
    LogToFile("Main executable base address: " + std::to_string((uintptr_t)g_baseAddress));
    
    return TRUE;
}

// Shutdown function - updated to handle all protections
extern "C" __declspec(dllexport) BOOL Protection_Shutdown() {
    // Disable thread monitoring if enabled
    if (g_isThreadMonitoringEnabled) {
        DisableThreadMonitoring();
    }
    
    // Disable anti-tampering if enabled
    if (g_isAntiTamperingEnabled) {
        DisableAntiTampering();
    }
    
    // Disable memory scan detection if enabled
    if (g_isMemoryScanDetectionEnabled) {
        DisableMemoryScanDetection();
    }
    
    // Decrypt headers if they are encrypted before shutdown
    if (g_isPEHeadersEncrypted) {
        if (!DecryptPEHeaders()) {
            LogToFile("ERROR: Failed to decrypt PE headers during shutdown");
            return FALSE;
        }
    }
    
    LogToFile("Protection module shutdown successfully");
    return TRUE;
}

// Function to encrypt PE headers
bool protection::EncryptPEHeaders() {
    if (g_isPEHeadersEncrypted) {
        LogToFile("PE headers are already encrypted");
        return true;
    }
    
    if (!g_baseAddress) {
        LogToFile("ERROR: Base address not initialized");
        return false;
    }
    
    LogToFile("Starting PE headers encryption process");
    
    // Backup main executable's original headers if not already done
    if (g_originalHeaders.empty()) {
        LogToFile("Backing up main executable's original PE headers");
        g_originalHeaders.resize(PE_HEADER_SIZE);
        memcpy(g_originalHeaders.data(), g_baseAddress, PE_HEADER_SIZE);
        LogToFile("Main executable's original PE headers backed up successfully");
    }
    
    // Encrypt main executable's headers
    LogToFile("Encrypting main executable's PE headers");
    DWORD oldProtect;
    if (!VirtualProtect(g_baseAddress, PE_HEADER_SIZE, PAGE_READWRITE, &oldProtect)) {
        LogToFile("ERROR: Failed to change memory protection for main executable");
        return false;
    }
    
    BYTE* peHeader = reinterpret_cast<BYTE*>(g_baseAddress);
    for (size_t i = 0; i < PE_HEADER_SIZE; i++) {
        peHeader[i] ^= g_encryptionKey;
    }
    
    VirtualProtect(g_baseAddress, PE_HEADER_SIZE, oldProtect, &oldProtect);
    LogToFile("Main executable's PE headers encrypted successfully");
    
    g_isPEHeadersEncrypted = true;
    g_encryptionStatus = TRUE;
    LogToFile("PE headers encryption completed successfully");
    
    return true;
}

// Function to decrypt PE headers
bool protection::DecryptPEHeaders() {
    if (!g_isPEHeadersEncrypted) {
        LogToFile("PE headers are not currently encrypted");
        return true;
    }
    
    if (!g_baseAddress) {
        LogToFile("ERROR: Base address not initialized");
        return false;
    }
    
    LogToFile("Starting PE headers decryption process");
    
    // Main executable decryption
    LogToFile("Decrypting main executable's PE headers");
    DWORD oldProtect;
    if (!VirtualProtect(g_baseAddress, PE_HEADER_SIZE, PAGE_READWRITE, &oldProtect)) {
        LogToFile("ERROR: Failed to change memory protection for main executable during decryption");
        return false;
    }
    
    // Option 1: Restore from backup
    if (!g_originalHeaders.empty()) {
        LogToFile("Restoring main executable's original PE headers from backup");
        memcpy(g_baseAddress, g_originalHeaders.data(), PE_HEADER_SIZE);
    }
    // Option 2: Decrypt in-place (used if we don't have a backup for some reason)
    else {
        LogToFile("WARNING: No backup headers available for main executable, attempting in-place decryption");
        BYTE* peHeader = reinterpret_cast<BYTE*>(g_baseAddress);
        for (size_t i = 0; i < PE_HEADER_SIZE; i++) {
            peHeader[i] ^= g_encryptionKey;  // XOR with the same key to decrypt
        }
    }
    
    VirtualProtect(g_baseAddress, PE_HEADER_SIZE, oldProtect, &oldProtect);
    LogToFile("Main executable's PE headers decrypted successfully");
    
    g_isPEHeadersEncrypted = false;
    g_encryptionStatus = FALSE;
    LogToFile("PE headers decryption completed successfully");
    
    return true;
}

// Check if headers are encrypted
bool protection::IsPEHeadersEncrypted() {
    return g_isPEHeadersEncrypted;
}

// Exported PE header encryption function - use dllexport only in implementation
extern "C" __declspec(dllexport) BOOL Protection_EncryptPEHeaders() {
    return EncryptPEHeaders() ? TRUE : FALSE;
}

// Exported PE header decryption function - use dllexport only in implementation
extern "C" __declspec(dllexport) BOOL Protection_DecryptPEHeaders() {
    return DecryptPEHeaders() ? TRUE : FALSE;
}

// Exported function to check encryption status - use dllexport only in implementation
extern "C" __declspec(dllexport) BOOL Protection_IsPEHeadersEncrypted() {
    return g_isPEHeadersEncrypted ? TRUE : FALSE;
}

// Function to initialize memory scan detection
bool protection::InitializeMemoryScanDetection() {
    LogToFile("Initializing memory scan detection");
    
    // Allocate a canary memory region that we'll monitor
    if (g_canaryAddress == NULL) {
        g_canaryAddress = VirtualAlloc(NULL, sizeof(void*), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!g_canaryAddress) {
            LogToFile("ERROR: Failed to allocate canary memory region");
            return false;
        }
        LogToFile("Canary memory allocated at: " + std::to_string((uintptr_t)g_canaryAddress));
    }
    
    // Initialize working set limits
    // ProcessQuotaLimits = 1
    DWORD parambuf[8] = { 0 };
    ULONG returnLength = 0;
    NTSTATUS status = ZwQueryInformationProcess((HANDLE)-1, 1, parambuf, sizeof(parambuf), &returnLength);
    if (status == 0) {
        // Set minimum and maximum working set size to maximum
        parambuf[2] = 0xffffffff;  // MinimumWorkingSetSize
        parambuf[3] = 0xffffffff;  // MaximumWorkingSetSize
        status = ZwSetInformationProcess((HANDLE)-1, 1, parambuf, sizeof(parambuf));
        if (status != 0) {
            LogToFile("WARNING: Failed to set working set limits");
        } else {
            LogToFile("Working set limits set successfully");
        }
    } else {
        LogToFile("WARNING: Failed to query working set limits");
    }
    
    return true;
}

// Function to check if an address is in the working set
bool protection::FindAddressInWorkingSet(LPVOID addr) {
    // Query the memory working set list
    // MemoryWorkingSetList = 1
    SIZE_T returnLength = 0;
    if (ZwQueryVirtualMemory((HANDLE)-1, NULL, 1, g_WSMemList, sizeof(g_WSMemList), &returnLength) != 0) {
        LogToFile("ERROR: Failed to query working set memory list");
        return false;
    }
    
    int count = (int)g_WSMemList[0];
    for (int i = 1; i <= count; i++) {
        if (((SIZE_T)addr & 0xFFFFF000) == ((SIZE_T)g_WSMemList[i] & 0xFFFFF000)) {
            return true;
        }
    }
    
    return false;
}

// Memory scan detection thread function
DWORD WINAPI protection::MemoryScanDetectionThread(LPVOID lpParam) {
    LogToFile("Memory scan detection thread started");
    
    while (g_isMemoryScanDetectionEnabled) {
        // Check if our canary address has been accessed (appears in working set)
        if (FindAddressInWorkingSet(g_canaryAddress)) {
            LogToFile("WARNING: Unauthorized memory scanning detected!");
            
            // Get process name and ID
            char processName[MAX_PATH] = "Unknown";
            DWORD processId = GetCurrentProcessId();
            HANDLE hProcessName = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (hProcessName) {
                GetModuleFileNameExA(hProcessName, NULL, processName, MAX_PATH);
                // Extract just the filename
                char* lastSlash = strrchr(processName, '\\');
                if (lastSlash) {
                    strcpy(processName, lastSlash + 1);
                }
                CloseHandle(hProcessName);
            }
            
            // Format PID as hex
            std::stringstream pidHex;
            pidHex << std::hex << std::uppercase << processId;
            
            // Create alert message with process information
            std::string alertMessage = "[WPP] Unauthorized Memory Scanning Detected!\n\n"
                                     "Process: " + std::string(processName) + "\n"
                                     "PID: " + std::to_string(processId) + " (0x" + pidHex.str() + ")";
            
            MessageBoxA(NULL, alertMessage.c_str(), "Security Alert", MB_ICONWARNING);
            // Optional: You could take additional actions here like terminating the process
            // ExitProcess(0);
            break;
        }
        
        // Sleep to reduce CPU usage
        Sleep(100);
    }
    
    LogToFile("Memory scan detection thread terminated");
    return 0;
}

// Enable memory scan detection
bool protection::EnableMemoryScanDetection() {
    if (g_isMemoryScanDetectionEnabled) {
        LogToFile("Memory scan detection is already enabled");
        return true;
    }
    
    // Initialize the detection mechanism
    if (!InitializeMemoryScanDetection()) {
        LogToFile("ERROR: Failed to initialize memory scan detection");
        return false;
    }
    
    // Set the status flag
    g_isMemoryScanDetectionEnabled = true;
    g_memoryScanStatus = TRUE;
    
    // Start the detection thread
    g_memoryScanThread = CreateThread(NULL, 0, MemoryScanDetectionThread, NULL, 0, NULL);
    if (!g_memoryScanThread) {
        LogToFile("ERROR: Failed to create memory scan detection thread");
        g_isMemoryScanDetectionEnabled = false;
        g_memoryScanStatus = FALSE;
        return false;
    }
    
    LogToFile("Memory scan detection enabled successfully");
    return true;
}

// Disable memory scan detection
bool protection::DisableMemoryScanDetection() {
    if (!g_isMemoryScanDetectionEnabled) {
        LogToFile("Memory scan detection is already disabled");
        return true;
    }
    
    // Set the status flag to signal the thread to exit
    g_isMemoryScanDetectionEnabled = false;
    g_memoryScanStatus = FALSE;
    
    // Wait for the thread to exit
    if (g_memoryScanThread) {
        WaitForSingleObject(g_memoryScanThread, 1000);  // Wait up to 1 second
        CloseHandle(g_memoryScanThread);
        g_memoryScanThread = NULL;
    }
    
    // Free the canary memory if needed
    if (g_canaryAddress) {
        VirtualFree(g_canaryAddress, 0, MEM_RELEASE);
        g_canaryAddress = NULL;
    }
    
    LogToFile("Memory scan detection disabled successfully");
    return true;
}

// Check if memory scan detection is enabled
bool protection::IsMemoryScanDetectionEnabled() {
    return g_isMemoryScanDetectionEnabled;
}

// Exported memory scan detection functions
extern "C" __declspec(dllexport) BOOL Protection_EnableMemoryScanDetection() {
    return EnableMemoryScanDetection() ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) BOOL Protection_DisableMemoryScanDetection() {
    return DisableMemoryScanDetection() ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) BOOL Protection_IsMemoryScanDetectionEnabled() {
    return g_isMemoryScanDetectionEnabled ? TRUE : FALSE;
}

// *** CRC32 calculation function ***
uint32_t protection::CalculateCrc32(const void* data, size_t length) {
    static uint32_t crc32_table[256] = { 0 };
    static bool tableInitialized = false;
    
    // Initialize the CRC32 table if it hasn't been already
    if (!tableInitialized) {
        const uint32_t polynomial = 0xEDB88320;
        for (uint32_t i = 0; i < 256; i++) {
            uint32_t c = i;
            for (size_t j = 0; j < 8; j++) {
                if (c & 1) {
                    c = polynomial ^ (c >> 1);
                } else {
                    c >>= 1;
                }
            }
            crc32_table[i] = c;
        }
        tableInitialized = true;
    }
    
    const uint8_t* buf = static_cast<const uint8_t*>(data);
    uint32_t crc = 0xFFFFFFFF;
    
    for (size_t i = 0; i < length; i++) {
        crc = crc32_table[(crc ^ buf[i]) & 0xFF] ^ (crc >> 8);
    }
    
    return ~crc;
}

// Function to initialize anti-tampering protection
bool protection::InitializeAntiTampering() {
    LogToFile("Initializing anti-tampering protection");
    
    // Clear any existing data
    g_monitoredSections.clear();
    g_sectionHashes.clear();
    
    if (!g_baseAddress) {
        g_baseAddress = GetModuleHandle(NULL);
        if (!g_baseAddress) {
            LogToFile("ERROR: Failed to get main executable base address");
            return false;
        }
    }
    
    // Get DOS header
    IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(g_baseAddress);
    
    // Validate DOS header
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        LogToFile("ERROR: Invalid DOS header signature");
        return false;
    }
    
    // Get NT headers
    IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
        reinterpret_cast<BYTE*>(g_baseAddress) + dosHeader->e_lfanew);
    
    // Validate NT headers
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        LogToFile("ERROR: Invalid NT header signature");
        return false;
    }
    
    // Get section headers
    IMAGE_SECTION_HEADER* sectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(
        reinterpret_cast<BYTE*>(&ntHeaders->OptionalHeader) + 
        ntHeaders->FileHeader.SizeOfOptionalHeader);
    
    // Process each section
    for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
        char sectionName[9] = { 0 };
        memcpy(sectionName, sectionHeaders[i].Name, 8);
        
        // We only monitor truly read-only sections, not .data or other writable sections
        // Check section characteristics to ensure it's read-only
        bool isReadOnly = (sectionHeaders[i].Characteristics & IMAGE_SCN_MEM_WRITE) == 0;
        bool isExecuteOrReadable = (sectionHeaders[i].Characteristics & (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ)) != 0;
        
        if (isReadOnly && isExecuteOrReadable && 
            (strcmp(sectionName, ".text") == 0 || strcmp(sectionName, ".rdata") == 0 || 
             strcmp(sectionName, "CODE") == 0)) {
            
            BYTE* sectionAddr = reinterpret_cast<BYTE*>(g_baseAddress) + sectionHeaders[i].VirtualAddress;
            size_t sectionSize = sectionHeaders[i].Misc.VirtualSize;
            
            // Store section info
            g_monitoredSections.push_back(std::make_pair(sectionAddr, sectionSize));
            
            // Calculate and store hash
            uint32_t hash = CalculateCrc32(sectionAddr, sectionSize);
            g_sectionHashes.push_back(std::make_pair(sectionAddr, hash));
            
            LogToFile("Monitoring section: " + std::string(sectionName) + 
                      " at address: " + std::to_string(reinterpret_cast<uintptr_t>(sectionAddr)) +
                      " with size: " + std::to_string(sectionSize) +
                      " and initial hash: " + std::to_string(hash) +
                      " (Characteristics: 0x" + std::to_string(sectionHeaders[i].Characteristics) + ")");
        } else {
            LogToFile("Skipping section: " + std::string(sectionName) + 
                      " (Not read-only or not of interest, Characteristics: 0x" + 
                      std::to_string(sectionHeaders[i].Characteristics) + ")");
        }
    }
    
    if (g_monitoredSections.empty()) {
        LogToFile("WARNING: No suitable sections found to monitor");
        return false;
    }
    
    LogToFile("Anti-tampering initialization completed, monitoring " + 
              std::to_string(g_monitoredSections.size()) + " sections");
    return true;
}

// Function to verify the integrity of monitored sections
bool protection::VerifySectionIntegrity() {
    for (size_t i = 0; i < g_sectionHashes.size(); i++) {
        void* sectionAddr = g_sectionHashes[i].first;
        uint32_t originalHash = g_sectionHashes[i].second;
        
        // Find the section size
        size_t sectionSize = 0;
        for (const auto& section : g_monitoredSections) {
            if (section.first == sectionAddr) {
                sectionSize = section.second;
                break;
            }
        }
        
        if (sectionSize == 0) {
            LogToFile("ERROR: Could not find section size for address: " + 
                      std::to_string(reinterpret_cast<uintptr_t>(sectionAddr)));
            continue;
        }
        
        // Calculate current hash
        uint32_t currentHash = CalculateCrc32(sectionAddr, sectionSize);
        
        // Compare hashes
        if (currentHash != originalHash) {
            // Try to identify the section name for better logging
            char sectionName[9] = "Unknown";
            IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(g_baseAddress);
            IMAGE_NT_HEADERS* ntHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(
                reinterpret_cast<BYTE*>(g_baseAddress) + dosHeader->e_lfanew);
            IMAGE_SECTION_HEADER* sectionHeaders = reinterpret_cast<IMAGE_SECTION_HEADER*>(
                reinterpret_cast<BYTE*>(&ntHeaders->OptionalHeader) + 
                ntHeaders->FileHeader.SizeOfOptionalHeader);
                
            for (int j = 0; j < ntHeaders->FileHeader.NumberOfSections; j++) {
                BYTE* currSecAddr = reinterpret_cast<BYTE*>(g_baseAddress) + sectionHeaders[j].VirtualAddress;
                if (currSecAddr == sectionAddr) {
                    memcpy(sectionName, sectionHeaders[j].Name, 8);
                    sectionName[8] = 0;
                    break;
                }
            }
            
            LogToFile("WARNING: Section " + std::string(sectionName) + " at " + 
                      std::to_string(reinterpret_cast<uintptr_t>(sectionAddr)) +
                      " has been modified! Original hash: " + std::to_string(originalHash) +
                      ", Current hash: " + std::to_string(currentHash));
            return false;
        }
    }
    
    return true;
}

// Anti-tampering thread function
DWORD WINAPI protection::AntiTamperingThread(LPVOID lpParam) {
    LogToFile("Anti-tampering thread started");
    
    while (g_isAntiTamperingEnabled) {
        // Check if any sections have been modified
        if (!VerifySectionIntegrity()) {
            LogToFile("WARNING: Code tampering detected! Showing alert immediately.");
            
            // Get process name and ID
            char processName[MAX_PATH] = "Unknown";
            DWORD processId = GetCurrentProcessId();
            HANDLE hProcessName = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
            if (hProcessName) {
                GetModuleFileNameExA(hProcessName, NULL, processName, MAX_PATH);
                // Extract just the filename
                char* lastSlash = strrchr(processName, '\\');
                if (lastSlash) {
                    strcpy(processName, lastSlash + 1);
                }
                CloseHandle(hProcessName);
            }
            
            // Format PID as hex
            std::stringstream pidHex;
            pidHex << std::hex << std::uppercase << processId;
            
            // Create alert message with process information
            std::string alertMessage = "[WPP] Unauthorized Code Tampering Detected!\n\n"
                                     "Process: " + std::string(processName) + "\n"
                                     "PID: " + std::to_string(processId) + " (0x" + pidHex.str() + ")";
            
            MessageBoxA(NULL, alertMessage.c_str(), "Security Alert", MB_ICONWARNING);
            // Optional: You could take additional actions here like terminating the process
            // ExitProcess(0);
            break;
        }
        
        // Sleep to reduce CPU usage (check every 2 seconds)
        Sleep(2000);
    }
    
    LogToFile("Anti-tampering thread terminated");
    return 0;
}

// Enable anti-tampering
bool protection::EnableAntiTampering() {
    if (g_isAntiTamperingEnabled) {
        LogToFile("Anti-tampering is already enabled");
        return true;
    }
    
    // Initialize the detection mechanism
    if (!InitializeAntiTampering()) {
        LogToFile("ERROR: Failed to initialize anti-tampering");
        return false;
    }
    
    // Set the status flag
    g_isAntiTamperingEnabled = true;
    g_antiTamperingStatus = TRUE;
    
    // Start the detection thread
    g_antiTamperingThread = CreateThread(NULL, 0, AntiTamperingThread, NULL, 0, NULL);
    if (!g_antiTamperingThread) {
        LogToFile("ERROR: Failed to create anti-tampering thread");
        g_isAntiTamperingEnabled = false;
        g_antiTamperingStatus = FALSE;
        return false;
    }
    
    LogToFile("Anti-tampering enabled successfully");
    return true;
}

// Disable anti-tampering
bool protection::DisableAntiTampering() {
    if (!g_isAntiTamperingEnabled) {
        LogToFile("Anti-tampering is already disabled");
        return true;
    }
    
    // Set the status flag to signal the thread to exit
    g_isAntiTamperingEnabled = false;
    g_antiTamperingStatus = FALSE;
    
    // Wait for the thread to exit
    if (g_antiTamperingThread) {
        WaitForSingleObject(g_antiTamperingThread, 1000);  // Wait up to 1 second
        CloseHandle(g_antiTamperingThread);
        g_antiTamperingThread = NULL;
    }
    
    // Clear the monitored sections
    g_monitoredSections.clear();
    g_sectionHashes.clear();
    
    LogToFile("Anti-tampering disabled successfully");
    return true;
}

// Check if anti-tampering is enabled
bool protection::IsAntiTamperingEnabled() {
    return g_isAntiTamperingEnabled;
}

// Exported anti-tampering functions
extern "C" __declspec(dllexport) BOOL Protection_EnableAntiTampering() {
    return EnableAntiTampering() ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) BOOL Protection_DisableAntiTampering() {
    return DisableAntiTampering() ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) BOOL Protection_IsAntiTamperingEnabled() {
    return g_isAntiTamperingEnabled ? TRUE : FALSE;
}

// Function to initialize thread monitoring
bool protection::InitializeThreadMonitoring() {
    LogToFile("Initializing thread monitoring");
    
    // Clear any existing module regions
    g_moduleRegions.clear();
    
    // Get the current process ID
    DWORD processId = GetCurrentProcessId();
    
    // Take a snapshot of all modules in the process
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        LogToFile("ERROR: Failed to create module snapshot");
        return false;
    }
    
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    
    // Retrieve information about the first module
    if (!Module32First(hModuleSnap, &me32)) {
        LogToFile("ERROR: Failed to get first module");
        CloseHandle(hModuleSnap);
        return false;
    }
    
    // Now walk the module list
    do {
        void* moduleBase = me32.modBaseAddr;
        size_t moduleSize = me32.modBaseSize;
        
        // Store the module region
        g_moduleRegions.push_back(std::make_pair(moduleBase, moduleSize));
        
        LogToFile("Module: " + std::string(me32.szModule) + 
                  " at address: " + std::to_string(reinterpret_cast<uintptr_t>(moduleBase)) +
                  " with size: " + std::to_string(moduleSize));
                  
    } while (Module32Next(hModuleSnap, &me32));
    
    CloseHandle(hModuleSnap);
    
    if (g_moduleRegions.empty()) {
        LogToFile("WARNING: No modules found!");
        return false;
    }
    
    LogToFile("Thread monitoring initialization completed, monitoring " + 
              std::to_string(g_moduleRegions.size()) + " module regions");
    return true;
}

// Function to update the module list
bool protection::UpdateModuleList() {
    // Clear any existing module regions
    g_moduleRegions.clear();
    
    // Get the current process ID
    DWORD processId = GetCurrentProcessId();
    
    // Take a snapshot of all modules in the process
    HANDLE hModuleSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processId);
    if (hModuleSnap == INVALID_HANDLE_VALUE) {
        LogToFile("ERROR: Failed to create module snapshot for update");
        return false;
    }
    
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    
    // Retrieve information about the first module
    if (!Module32First(hModuleSnap, &me32)) {
        LogToFile("ERROR: Failed to get first module during update");
        CloseHandle(hModuleSnap);
        return false;
    }
    
    // Now walk the module list
    do {
        void* moduleBase = me32.modBaseAddr;
        size_t moduleSize = me32.modBaseSize;
        
        // Store the module region
        g_moduleRegions.push_back(std::make_pair(moduleBase, moduleSize));
        
    } while (Module32Next(hModuleSnap, &me32));
    
    CloseHandle(hModuleSnap);
    
    if (g_moduleRegions.empty()) {
        LogToFile("WARNING: No modules found during update!");
        return false;
    }
    
    return true;
}

// Check if an address is within any known module
bool protection::IsAddressInKnownModule(LPVOID address) {
    for (const auto& region : g_moduleRegions) {
        LPVOID moduleStart = region.first;
        LPVOID moduleEnd = reinterpret_cast<BYTE*>(moduleStart) + region.second;
        
        if (address >= moduleStart && address < moduleEnd) {
            return true;
        }
    }
    
    return false;
}

// Function to check for suspicious threads
bool protection::CheckForSuspiciousThreads() {
    // Take a snapshot of all threads in the system
    HANDLE hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        LogToFile("ERROR: Failed to create thread snapshot");
        return false;
    }
    
    THREADENTRY32 te32;
    te32.dwSize = sizeof(THREADENTRY32);
    
    DWORD currentProcessId = GetCurrentProcessId();
    bool suspicious = false;
    
    // Retrieve information about the first thread
    if (!Thread32First(hThreadSnap, &te32)) {
        LogToFile("ERROR: Failed to get first thread");
        CloseHandle(hThreadSnap);
        return false;
    }
    
    // Traverse the thread list
    do {
        // Only check threads in our process
        if (te32.th32OwnerProcessID == currentProcessId) {
            // Open the thread to get its start address
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
            if (hThread) {
                LPVOID startAddress = NULL;
                
                // Get the thread's start address
                typedef NTSTATUS (NTAPI *pNtQueryInformationThread)(
                    HANDLE ThreadHandle,
                    ULONG ThreadInformationClass,
                    PVOID ThreadInformation,
                    ULONG ThreadInformationLength,
                    PULONG ReturnLength
                );
                
                static pNtQueryInformationThread NtQueryInformationThread = 
                    (pNtQueryInformationThread)GetProcAddress(
                        GetModuleHandleA("ntdll.dll"), 
                        "NtQueryInformationThread"
                    );
                
                if (NtQueryInformationThread) {
                    // ThreadQuerySetWin32StartAddress = 9
                    NTSTATUS status = NtQueryInformationThread(
                        hThread, 
                        9, // ThreadQuerySetWin32StartAddress
                        &startAddress, 
                        sizeof(startAddress), 
                        NULL
                    );
                    
                    if (status == 0 && startAddress) {
                        // Check if the start address is outside known modules
                        if (!IsAddressInKnownModule(startAddress)) {
                            suspicious = true;
                            LogToFile("SUSPICIOUS THREAD DETECTED! Thread ID: " + 
                                     std::to_string(te32.th32ThreadID) + 
                                     " has start address: " + 
                                     std::to_string(reinterpret_cast<uintptr_t>(startAddress)) + 
                                     " which is outside any known module!");
                                     
                            // Convert address and PID to hex string
                            std::stringstream ss;
                            ss << std::hex << std::uppercase << reinterpret_cast<uintptr_t>(startAddress);
                            
                            std::stringstream pidHex;
                            pidHex << std::hex << std::uppercase << currentProcessId;
                            
                            // Get process name
                            char processName[MAX_PATH] = "Unknown";
                            HANDLE hProcessName = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, currentProcessId);
                            if (hProcessName) {
                                GetModuleFileNameExA(hProcessName, NULL, processName, MAX_PATH);
                                // Extract just the filename
                                char* lastSlash = strrchr(processName, '\\');
                                if (lastSlash) {
                                    strcpy(processName, lastSlash + 1);
                                }
                                CloseHandle(hProcessName);
                            }
                            
                            // Show alert
                            std::string alertMessage = "[WPP] Suspicious Thread Detected!\n\n"
                                                     "Process: " + std::string(processName) + "\n"
                                                     "PID: " + std::to_string(currentProcessId) + " (0x" + 
                                                         pidHex.str() + ")\n"
                                                     "Thread ID: " + std::to_string(te32.th32ThreadID) + "\n"
                                                     "Start Address: 0x" + ss.str();
                            
                            MessageBoxA(NULL, alertMessage.c_str(), "Security Alert", MB_ICONWARNING);
                        }
                    }
                }
                
                CloseHandle(hThread);
            }
        }
    } while (Thread32Next(hThreadSnap, &te32));
    
    CloseHandle(hThreadSnap);
    return suspicious;
}

// Thread monitoring thread function
DWORD WINAPI protection::ThreadMonitoringThread(LPVOID lpParam) {
    LogToFile("Thread monitoring thread started");
    
    while (g_isThreadMonitoringEnabled) {
        // Periodically update the module list to catch newly loaded modules
        if (!UpdateModuleList()) {
            LogToFile("WARNING: Failed to update module list");
        }
        
        // Check for suspicious threads
        CheckForSuspiciousThreads();
        
        // Sleep to reduce CPU usage (check every 3 seconds)
        Sleep(3000);
    }
    
    LogToFile("Thread monitoring thread terminated");
    return 0;
}

// Enable thread monitoring
bool protection::EnableThreadMonitoring() {
    if (g_isThreadMonitoringEnabled) {
        LogToFile("Thread monitoring is already enabled");
        return true;
    }
    
    // Initialize the thread monitoring
    if (!InitializeThreadMonitoring()) {
        LogToFile("ERROR: Failed to initialize thread monitoring");
        return false;
    }
    
    // Set the status flag
    g_isThreadMonitoringEnabled = true;
    g_threadMonitoringStatus = TRUE;
    
    // Start the monitoring thread
    g_threadMonitoringThread = CreateThread(NULL, 0, ThreadMonitoringThread, NULL, 0, NULL);
    if (!g_threadMonitoringThread) {
        LogToFile("ERROR: Failed to create thread monitoring thread");
        g_isThreadMonitoringEnabled = false;
        g_threadMonitoringStatus = FALSE;
        return false;
    }
    
    LogToFile("Thread monitoring enabled successfully");
    return true;
}

// Disable thread monitoring
bool protection::DisableThreadMonitoring() {
    if (!g_isThreadMonitoringEnabled) {
        LogToFile("Thread monitoring is already disabled");
        return true;
    }
    
    // Set the status flag to signal the thread to exit
    g_isThreadMonitoringEnabled = false;
    g_threadMonitoringStatus = FALSE;
    
    // Wait for the thread to exit
    if (g_threadMonitoringThread) {
        WaitForSingleObject(g_threadMonitoringThread, 1000);  // Wait up to 1 second
        CloseHandle(g_threadMonitoringThread);
        g_threadMonitoringThread = NULL;
    }
    
    // Clear the module regions
    g_moduleRegions.clear();
    
    LogToFile("Thread monitoring disabled successfully");
    return true;
}

// Check if thread monitoring is enabled
bool protection::IsThreadMonitoringEnabled() {
    return g_isThreadMonitoringEnabled;
}

// Exported thread monitoring functions
extern "C" __declspec(dllexport) BOOL Protection_EnableThreadMonitoring() {
    return EnableThreadMonitoring() ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) BOOL Protection_DisableThreadMonitoring() {
    return DisableThreadMonitoring() ? TRUE : FALSE;
}

extern "C" __declspec(dllexport) BOOL Protection_IsThreadMonitoringEnabled() {
    return g_isThreadMonitoringEnabled ? TRUE : FALSE;
}
