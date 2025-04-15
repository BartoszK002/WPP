#include "process_manager.h"
#include <TlHelp32.h>
#include <Psapi.h>
#include <filesystem>
#include <shellapi.h>
#include <sstream>
#include <iostream>
#include <iomanip>
#include "lodepng.h"
#include <gdiplus.h>
#include <commctrl.h>
#include <commoncontrols.h>
#include <winternl.h>
#include <winnt.h>

#ifdef _WIN64
// Define 32-bit structure layouts for accessing 32-bit process information from 64-bit code
typedef struct _PROCESS_BASIC_INFORMATION32 {
    NTSTATUS ExitStatus;
    ULONG PebBaseAddress;
    ULONG AffinityMask;
    ULONG BasePriority;
    ULONG UniqueProcessId;
    ULONG InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION32;

typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} UNICODE_STRING32;

typedef struct _RTL_USER_PROCESS_PARAMETERS32 {
    BYTE Reserved1[16];
    ULONG Reserved2[10];
    UNICODE_STRING32 ImagePathName;
    UNICODE_STRING32 CommandLine;
} RTL_USER_PROCESS_PARAMETERS32;

typedef struct _PEB32 {
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    ULONG Reserved3[2];
    ULONG Ldr;
    ULONG ProcessParameters;
} PEB32;

typedef NTSTATUS(NTAPI* NtWow64QueryInformationProcess32Fn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);

typedef NTSTATUS(NTAPI* NtWow64ReadVirtualMemory64)(
    HANDLE ProcessHandle,
    PVOID64 BaseAddress,
    PVOID Buffer,
    ULONGLONG BufferSize,
    PULONGLONG NumberOfBytesRead
);

typedef NTSTATUS(NTAPI* NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);
#else
typedef NTSTATUS(NTAPI* NtQueryInformationProcessFn)(
    HANDLE ProcessHandle,
    PROCESSINFOCLASS ProcessInformationClass,
    PVOID ProcessInformation,
    ULONG ProcessInformationLength,
    PULONG ReturnLength
);
#endif

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "ntdll.lib")

std::string ProcessManager::Base64Encode(const std::vector<uint8_t>& data) {
    const char base64_chars[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";

    std::string ret;
    int i = 0;
    int j = 0;
    uint8_t char_array_3[3];
    uint8_t char_array_4[4];
    size_t data_len = data.size();
    const uint8_t* bytes_to_encode = data.data();

    while (data_len--) {
        char_array_3[i++] = *(bytes_to_encode++);
        if (i == 3) {
            char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
            char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
            char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);
            char_array_4[3] = char_array_3[2] & 0x3f;

            for (i = 0; i < 4; i++)
                ret += base64_chars[char_array_4[i]];
            i = 0;
        }
    }

    if (i) {
        for (j = i; j < 3; j++)
            char_array_3[j] = '\0';

        char_array_4[0] = (char_array_3[0] & 0xfc) >> 2;
        char_array_4[1] = ((char_array_3[0] & 0x03) << 4) + ((char_array_3[1] & 0xf0) >> 4);
        char_array_4[2] = ((char_array_3[1] & 0x0f) << 2) + ((char_array_3[2] & 0xc0) >> 6);

        for (j = 0; j < i + 1; j++)
            ret += base64_chars[char_array_4[j]];

        while (i++ < 3)
            ret += '=';
    }

    return ret;
}

std::unordered_map<std::wstring, std::string> ProcessManager::iconCache;
std::shared_mutex ProcessManager::cacheMutex;

std::string ProcessManager::GetProcessIconBase64(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        // std::cout << "Failed to open process " << pid << " - using placeholder" << std::endl;
        // Process access denied or not found - use placeholder
        std::vector<uint8_t> placeholderData = CreatePlaceholderIcon();
        if (!placeholderData.empty()) {
            std::string base64Data = Base64Encode(placeholderData);
            return "data:image/png;base64," + base64Data;
        }
        return "";
    }

    wchar_t exePath[MAX_PATH];
    DWORD pathSize = MAX_PATH;
    if (!QueryFullProcessImageNameW(hProcess, 0, exePath, &pathSize)) {
        CloseHandle(hProcess);
        // std::cout << "Failed to get exe path for process " << pid << " - using placeholder" << std::endl;
        // Failed to get exe path - use placeholder
        std::vector<uint8_t> placeholderData = CreatePlaceholderIcon();
        if (!placeholderData.empty()) {
            std::string base64Data = Base64Encode(placeholderData);
            return "data:image/png;base64," + base64Data;
        }
        return "";
    }
    CloseHandle(hProcess);

    // Check if the icon is already in the cache
    std::wstring exePathStr(exePath);
    {
        std::shared_lock<std::shared_mutex> lock(cacheMutex);
        auto it = iconCache.find(exePathStr);
        if (it != iconCache.end()) {
            // std::cout << "Icon found in cache for: " << std::filesystem::path(exePath).string() << std::endl;
            return it->second;
        }
    }

    // Extract icon data
    std::vector<uint8_t> iconData = ExtractIconFromExe(exePath);
    if (iconData.empty()) {
        // std::cout << "Failed to extract icon for process " << pid << " - using placeholder" << std::endl;
        // Failed to extract icon - use placeholder
        std::vector<uint8_t> placeholderData = CreatePlaceholderIcon();
        if (!placeholderData.empty()) {
            std::string base64Data = Base64Encode(placeholderData);
            std::string fullDataUrl = "data:image/png;base64," + base64Data;
            
            // Cache the placeholder too
            {
                std::unique_lock<std::shared_mutex> lock(cacheMutex);
                iconCache[exePathStr] = fullDataUrl;
            }
            
            return fullDataUrl;
        }
        return "";
    }

    std::string base64Data = Base64Encode(iconData);
    if (base64Data.empty()) {
        // std::cout << "Base64 encoding failed for process " << pid << " - using placeholder" << std::endl;
        // Failed to encode - use placeholder
        std::vector<uint8_t> placeholderData = CreatePlaceholderIcon();
        if (!placeholderData.empty()) {
            std::string base64Data = Base64Encode(placeholderData);
            return "data:image/png;base64," + base64Data;
        }
        return "";
    }

    std::string fullDataUrl = "data:image/png;base64," + base64Data;

    // Store in cache
    {
        std::unique_lock<std::shared_mutex> lock(cacheMutex);
        iconCache[exePathStr] = fullDataUrl;
    }

    return fullDataUrl;
}

Gdiplus::Bitmap* ProcessManager::IconToBitmapPARGB32(HICON hIcon) {
    if (!hIcon) {
        return nullptr;
    }

    ICONINFO iconInfo;
    if (!GetIconInfo(hIcon, &iconInfo)) {
        return nullptr;
    }

    BITMAP bmColor;
    if (!GetObject(iconInfo.hbmColor, sizeof(BITMAP), &bmColor)) {
        DeleteObject(iconInfo.hbmColor);
        DeleteObject(iconInfo.hbmMask);
        return nullptr;
    }

    int width = bmColor.bmWidth;
    int height = bmColor.bmHeight;

    // Create a 32bpp bitmap with premultiplied alpha
    Gdiplus::Bitmap* bitmap = new Gdiplus::Bitmap(width, height, PixelFormat32bppPARGB);
    if (!bitmap) {
        DeleteObject(iconInfo.hbmColor);
        DeleteObject(iconInfo.hbmMask);
        return nullptr;
    }

    // Create graphics to draw onto the bitmap
    Gdiplus::Graphics* graphics = Gdiplus::Graphics::FromImage(bitmap);
    if (!graphics) {
        delete bitmap;
        DeleteObject(iconInfo.hbmColor);
        DeleteObject(iconInfo.hbmMask);
        return nullptr;
    }

    // Set high-quality rendering
    graphics->SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
    graphics->SetSmoothingMode(Gdiplus::SmoothingModeHighQuality);
    graphics->SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);

    // Clear the bitmap with transparent background
    graphics->Clear(Gdiplus::Color::Transparent);

    // Draw the icon using GDI
    HDC hdc = graphics->GetHDC();
    if (hdc) {
        DrawIconEx(hdc, 0, 0, hIcon, width, height, 0, NULL, DI_NORMAL);
        graphics->ReleaseHDC(hdc);
    }

    // Cleanup
    delete graphics;
    DeleteObject(iconInfo.hbmColor);
    DeleteObject(iconInfo.hbmMask);

    return bitmap;
}

std::vector<uint8_t> ProcessManager::ExtractIconFromExe(const std::wstring& exePath) {
    std::vector<uint8_t> result;

    // std::cout << "\nExtracting icon from: " << std::filesystem::path(exePath).string() << std::endl;

    // Initialize GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Gdiplus::Ok) {
        // std::cout << "GdiplusStartup failed" << std::endl;
        return result;
    }

    // Get the icon index
    SHFILEINFOW sfi = { 0 };
    if (!SHGetFileInfoW(
        exePath.c_str(),
        FILE_ATTRIBUTE_NORMAL,
        &sfi,
        sizeof(sfi),
        SHGFI_SYSICONINDEX | SHGFI_USEFILEATTRIBUTES
    )) {
        // std::cout << "SHGetFileInfoW failed" << std::endl;
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // std::cout << "SHGetFileInfoW icon index: " << sfi.iIcon << std::endl;

    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    // Try SHIL_EXTRALARGE (48x48) first for better quality when scaled down
    IImageList* pImageList = NULL;
    HRESULT hr = SHGetImageList(SHIL_EXTRALARGE, IID_IImageList, (void**)&pImageList);
    
    // If EXTRALARGE fails, fall back to LARGE (32x32)
    if (FAILED(hr)) {
        hr = SHGetImageList(SHIL_LARGE, IID_IImageList, (void**)&pImageList);
        if (FAILED(hr)) {
            // std::cout << "SHGetImageList failed, hr = " << hr << std::endl;
            Gdiplus::GdiplusShutdown(gdiplusToken);
            return result;
        }
    }

    // Get the icon from the image list
    HICON hIcon = NULL;
    hr = pImageList->GetIcon(sfi.iIcon, ILD_TRANSPARENT, &hIcon);
    if (FAILED(hr) || hIcon == NULL) {
        // std::cout << "GetIcon failed, hr = " << hr << std::endl;
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Convert HICON to GDI+ Bitmap with proper alpha handling
    Gdiplus::Bitmap* bitmap = IconToBitmapPARGB32(hIcon);
    if (!bitmap) {
        // std::cout << "Failed to convert HICON to Bitmap" << std::endl;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Create a stream to save the PNG
    IStream* istream = nullptr;
    if (CreateStreamOnHGlobal(NULL, TRUE, &istream) != S_OK) {
        // std::cout << "Failed to create stream" << std::endl;
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Get encoder CLSID
    CLSID pngClsid;
    if (GetEncoderClsid(L"image/png", &pngClsid) == -1) {
        // std::cout << "Failed to get PNG encoder CLSID" << std::endl;
        istream->Release();
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Configure PNG encoder parameters for best quality
    Gdiplus::EncoderParameters encoderParams;
    encoderParams.Count = 1;
    encoderParams.Parameter[0].Guid = Gdiplus::EncoderQuality;
    encoderParams.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
    encoderParams.Parameter[0].NumberOfValues = 1;
    ULONG quality = 100;
    encoderParams.Parameter[0].Value = &quality;

    // Save to PNG with high quality settings
    Gdiplus::Status status = bitmap->Save(istream, &pngClsid, &encoderParams);
    if (status != Gdiplus::Ok) {
        // std::cout << "Failed to save bitmap to stream. Status: " << status << std::endl;
        istream->Release();
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Get stream size
    STATSTG statstg;
    if (istream->Stat(&statstg, STATFLAG_NONAME) != S_OK) {
        // std::cout << "Failed to get stream size" << std::endl;
        result.clear();
        istream->Release();
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Read the PNG data from the stream
    result.resize(statstg.cbSize.LowPart);
    LARGE_INTEGER liZero = {};
    if (istream->Seek(liZero, STREAM_SEEK_SET, NULL) != S_OK) {
        // std::cout << "Failed to seek stream" << std::endl;
        result.clear();
        istream->Release();
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    ULONG bytesRead = 0;
    if (istream->Read(result.data(), statstg.cbSize.LowPart, &bytesRead) != S_OK ||
        bytesRead != statstg.cbSize.LowPart) {
        // std::cout << "Failed to read stream data" << std::endl;
        result.clear();
        istream->Release();
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Cleanup
    istream->Release();
    delete bitmap;
    DestroyIcon(hIcon);
    pImageList->Release();
    Gdiplus::GdiplusShutdown(gdiplusToken);

    // Log success and size info
    if (!result.empty()) {
        // std::cout << "Successfully extracted icon, size: " << result.size() << " bytes" << std::endl;
    }

    return result;
}

std::vector<uint8_t> ProcessManager::CreatePlaceholderIcon() {
    // This is our predefined placeholder icon as a base64 string
    const char* base64Icon = "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAM5SURBVGhD7ZnZTlNhEMd7JS2FQlteRMBXUmSTClpRkU1AFFwTHoBHMF4CshRkRxZFNr2WxBfgZszMt/CdbzjJJCex1JxJfqEBMuf3/2fODSQS8cQTTzxlnVuNjVDo6oDeYk9F0dZyB5qbGiGBH/wfXjdKpdKVX7H4hP/LlQYFuLi4qEjiAOXm/w0wPT0NU1NTAfB7/u+NrfyBhg+/oOH9TyL/DjmD/FvkFPJvkBPIvdZMHkNu4hiyE0eQfYX8gJHF32yv9PmhAaSQNIkb6TMrnfekc4509qXhELLjh2yvlMgBgk2f2qZJnsSPPHEljNS/+K4Y+8b2SokeAMVJVgtP6vMw0k7L9eNaWEsTowdQN3rA9koJDSC9QX4eQWm/aSWtxUf2Fc/32V7p80MDSMldKe02rcVReuSAMNJ1w3tEZmiX7ZUSOYArbcVty6rpeqdpI103pMSJwa9sr5TIAWzTVtxrmdiDzPCubRuFiYEdqEX6t9leKaEBpDdoX8SAtD6NYd2wJ23p34HaZ9tQ27fF9kqfHxpASqBp56aVtBbXwtg0CRNbJF7zdBNq+jbZXinRA5ibNm17TV8lTaD4kw3F4w22V0rkAJkhLexLW3HddN+mattKr5N4uncd0r1rbK+U0ADSG3SlM0Zat4zC2LRt25NOP0JWIV1cZXulzw8NIMU9jxpqGsV1y/o8uPQaSVc//GLx90qJHsC8iAFpbHod0oiRLqqmXenqBytQ3bMCqZ5ltldK5ABMGoWtNG9aSS8rupch1V2C1P0S2yslNID0Bm3LJK1aTheVbNoIO9IpK71kSRYW2V4poQGkuC8i4UprcRLWTVvxArIIyXsLkLxXxgDsPKy0xkgb4a5L6WTnAiQ756GqY57tlRI9AJN2mibpJSVtxEl6Aao6Piva5wh/r5TQANJ34FK4dCkcaFrTOa/bdsTbkFm40TrL9koJDSDFNM2kzXkYad20K03cnSH8vVKiBwhIO8Kh0krYx98rJXKAwU9nwdNASHgu2HLrDFQ5jbsMfDxhe6VEDlBu4gDlhgIUutrh/Jz/ee+6g85tLbch0dx0kz5gmkoCi0d3/19m8cQTTzz/dv4ClooDMBDzMO4AAAAASUVORK5CYII=";

    // Create a vector to store the decoded data
    std::vector<uint8_t> decodedData;
    
    try {
        // Skip the "data:image/png;base64," prefix if present
        const char* base64Data = strstr(base64Icon, ",");
        if (base64Data) {
            base64Data++; // Skip the comma
        } else {
            base64Data = base64Icon; // Use the full string if no prefix found
        }

        // Calculate the length of the base64 string
        size_t inputLength = strlen(base64Data);
        
        // Remove any whitespace from the base64 string
        std::string cleanBase64;
        for (size_t i = 0; i < inputLength; i++) {
            if (!isspace(base64Data[i])) {
                cleanBase64 += base64Data[i];
            }
        }

        // Calculate the size of the decoded data
        size_t decodedLength = (cleanBase64.length() * 3) / 4;
        if (cleanBase64[cleanBase64.length() - 1] == '=') decodedLength--;
        if (cleanBase64[cleanBase64.length() - 2] == '=') decodedLength--;

        // Resize the vector to hold the decoded data
        decodedData.resize(decodedLength);

        // Create a lookup table for base64 decoding
        static const unsigned char lookup[] = {
            62,  255, 62,  255, 63,  52,  53, 54, 55, 56, 57, 58, 59, 60, 61, 255,
            255, 255, 255, 255, 255, 255, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
            10,  11,  12,  13,  14,  15,  16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            255, 255, 255, 255, 63,  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
            36,  37,  38,  39,  40,  41,  42, 43, 44, 45, 46, 47, 48, 49, 50, 51
        };

        // Decode the base64 data
        size_t j = 0;
        unsigned int accumulator = 0;
        int bits = 0;
        
        for (char c : cleanBase64) {
            if (c == '=') break; // Stop at padding

            accumulator = (accumulator << 6) | lookup[c - 43];
            bits += 6;

            if (bits >= 8) {
                bits -= 8;
                decodedData[j++] = (accumulator >> bits) & 0xFF;
            }
        }

        // std::cout << "Successfully loaded placeholder icon, size: " << decodedData.size() << " bytes" << std::endl;
    }
    catch (const std::exception& e) {
        // std::cout << "Error loading placeholder icon: " << e.what() << std::endl;
        decodedData.clear();
    }

    return decodedData;
}

std::string ProcessManager::GetProcessCommandLine(HANDLE hProcess) {
    if (!hProcess) {
        // std::cout << "[GetProcessCommandLine] Invalid process handle" << std::endl;
        return "N/A";
    }

    bool is64Bit = IsProcess64Bit(hProcess);
    // std::cout << "[GetProcessCommandLine] Process architecture: " << (is64Bit ? "64-bit" : "32-bit") << std::endl;
    
#ifdef _WIN64
    if (!is64Bit) {
        // std::cout << "[GetProcessCommandLine] Handling 32-bit process from 64-bit code" << std::endl;
        
        // Get NtQueryInformationProcess
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
        
        // Get the address of the 32-bit PEB
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
        
        // Read 32-bit PEB
        PEB32 peb32 = { 0 };
        SIZE_T bytesRead = 0;
        if (!ReadProcessMemory(hProcess, peb32Address, &peb32, sizeof(peb32), &bytesRead)) {
            DWORD error = GetLastError();
            // std::cout << "[GetProcessCommandLine] Failed to read PEB32, error: " << error << std::endl;
            return "N/A";
        }
        
        // Read 32-bit process parameters
        RTL_USER_PROCESS_PARAMETERS32 processParams32 = { 0 };
        if (!ReadProcessMemory(hProcess, (PVOID)(ULONG_PTR)peb32.ProcessParameters, &processParams32, sizeof(processParams32), &bytesRead)) {
            DWORD error = GetLastError();
            // std::cout << "[GetProcessCommandLine] Failed to read RTL_USER_PROCESS_PARAMETERS32, error: " << error << std::endl;
            return "N/A";
        }
        
        // Read CommandLine UNICODE_STRING32
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
    // Handle 64-bit process (or 32-bit process on 32-bit Windows)
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
    
    // Read PEB
    PEB peb;
    SIZE_T bytesRead;
    if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(peb), &bytesRead)) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessCommandLine] Failed to read PEB, error: " << error << std::endl;
        return "N/A";
    }
    
    // Read process parameters
    RTL_USER_PROCESS_PARAMETERS processParams;
    if (!ReadProcessMemory(hProcess, peb.ProcessParameters, &processParams, sizeof(processParams), &bytesRead)) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessCommandLine] Failed to read RTL_USER_PROCESS_PARAMETERS, error: " << error << std::endl;
        return "N/A";
    }
    
    // Read command line
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

bool ProcessManager::IsWindowsSystemProcess(const std::wstring& processName, DWORD pid) {
    // List of known Windows system process names
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

    // Special handling for system processes with PID 0 or 4
    if (pid == 0 || pid == 4) {
        return true;
    }

    return systemProcesses.find(processName) != systemProcesses.end();
}

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
                
                if (!includeSystemProcesses && IsWindowsSystemProcess(processEntry.szExeFile, info.pid)) {
                    continue;
                }
                
                info.isProtected = IsProcessProtected(info.pid);
                info.iconBase64 = GetProcessIconBase64(info.pid);
                info.hasVisibleWindow = HasVisibleWindow(info.pid);
                
                // Get process architecture
                HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, info.pid);
                if (processHandle != NULL) {
                    info.is64Bit = IsProcess64Bit(processHandle);
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

bool ProcessManager::IsProcessProtected(DWORD pid) {
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
        targetIs64Bit = IsProcess64Bit(hProcess);
        CloseHandle(hProcess);
    }
    
    // std::cout << "\nAttempting to inject protection DLL into process: " << processName << " (PID: " << pid << ")" << std::endl;
    // std::cout << "Target process architecture: " << (targetIs64Bit ? "x64" : "x86") << std::endl;

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
        // std::cout << "Error: " << errorMsg << std::endl;
        return false;
    }
    
    // Get the full path of the DLL
    std::filesystem::path dllPath = L"C:\\Users\\BK\\Documents\\GitHub\\WPP\\build\\protection_dll\\Release\\protection_dll.dll";

    // std::wcout << L"DLL Path: " << dllPath.wstring() << std::endl;
    
    if (!std::filesystem::exists(dllPath)) {
        errorMsg = "Protection DLL not found at: " + dllPath.string();
        // std::cout << "Error: " << errorMsg << std::endl;
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

    if (hProcess == NULL) {
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
        // std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        return false;
    }

    // Get LoadLibraryW address
    LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "LoadLibraryW");
    if (loadLibraryAddr == NULL) {
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
        // std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        CloseHandle(hProcess);
        return false;
    }

    // First allocate memory for the DLL path
    size_t dllPathSize = (dllPath.wstring().length() + 1) * sizeof(wchar_t);
    LPVOID dllPathAddr = VirtualAllocEx(hProcess, NULL, dllPathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (dllPathAddr == NULL) {
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
        // std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        CloseHandle(hProcess);
        return false;
    }

    // Write the DLL path to the allocated memory
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
        // std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // std::cout << "Creating remote thread to load DLL..." << std::endl;
    
    // Create remote thread to load DLL
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, dllPathAddr, 0, NULL);
    if (hThread == NULL) {
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
        // std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // std::cout << "Waiting for thread completion..." << std::endl;
    
    // Wait for thread completion with timeout
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
        // std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // Get thread exit code - this will be the return value from LoadLibrary
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
        // std::cout << "Error: " << errorMsg << std::endl;
        LocalFree(lpMsgBuf);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // std::cout << "Thread exit code (LoadLibrary result): 0x" << std::hex << exitCode << std::dec << std::endl;

    if (exitCode == 0) {
        // Try to determine why LoadLibrary failed
        DWORD error = 0;
        BOOL isTarget32Bit = FALSE;
        BOOL isTarget64Bit = FALSE;
        
        // Check if we can access the DLL file
        HANDLE hFile = CreateFileW(dllPath.wstring().c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (hFile == INVALID_HANDLE_VALUE) {
            error = GetLastError();
        } else {
            CloseHandle(hFile);
            
            // Check architecture mismatch
            BOOL isSystem64Bit = FALSE;
            SYSTEM_INFO sysInfo;
            GetNativeSystemInfo(&sysInfo);
            isSystem64Bit = (sysInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64);

#ifdef _WIN64
            // If we're 64-bit, check if target is 32-bit
            IsWow64Process(hProcess, &isTarget32Bit);
            if (isTarget32Bit) {
                error = ERROR_BAD_EXE_FORMAT;
            }
#else
            // If we're 32-bit, check if target is 64-bit
            IsWow64Process(hProcess, &isTarget64Bit);
            if (!isTarget64Bit && isSystem64Bit) {
                error = ERROR_BAD_EXE_FORMAT;
            }
#endif
            if (error == 0) {
                // If architecture is fine, it might be missing dependencies
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
            // If FormatMessage fails, provide a more specific error
            errorMsg = "Failed to inject DLL into process '" + processName + "': Unable to load DLL (Error code: " + 
                      std::to_string(error) + ")" + additionalInfo;
        } else {
            std::string errorText = (char*)lpMsgBuf;
            // Remove any %1 placeholders from the error message
            size_t pos;
            while ((pos = errorText.find("%1")) != std::string::npos) {
                errorText.replace(pos, 2, "DLL");
            }
            errorMsg = "Failed to inject DLL into process '" + processName + "': " + errorText + additionalInfo;
            LocalFree(lpMsgBuf);
        }
        
        // std::cout << "Error: " << errorMsg << std::endl;
        
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return false;
    }

    // std::cout << "DLL injection successful!" << std::endl;

    // Cleanup
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, dllPathAddr, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return true;
}

int ProcessManager::GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;          // Number of image encoders
    UINT size = 0;         // Size of the image encoder array in bytes

    if (Gdiplus::GetImageEncodersSize(&num, &size) != Gdiplus::Ok) {
        // std::cout << "GetImageEncodersSize failed" << std::endl;
        return -1;
    }

    if (size == 0) {
        // std::cout << "No image encoders found" << std::endl;
        return -1;
    }

    Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
    if (pImageCodecInfo == NULL) {
        // std::cout << "Failed to allocate memory for image encoders" << std::endl;
        return -1;
    }

    if (Gdiplus::GetImageEncoders(num, size, pImageCodecInfo) != Gdiplus::Ok) {
        // std::cout << "GetImageEncoders failed" << std::endl;
        free(pImageCodecInfo);
        return -1;
    }

    for (UINT j = 0; j < num; ++j) {
        if (wcscmp(pImageCodecInfo[j].MimeType, format) == 0) {
            *pClsid = pImageCodecInfo[j].Clsid;
            free(pImageCodecInfo);
            return j;
        }
    }

    // std::cout << "PNG encoder not found" << std::endl;
    free(pImageCodecInfo);
    return -1;
}

double ProcessManager::GetProcessCpuUsage(HANDLE hProcess) {
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

SIZE_T ProcessManager::GetProcessPrivateWorkingSet(HANDLE hProcess) {
    PROCESS_MEMORY_COUNTERS_EX pmc;
    if (GetProcessMemoryInfo(hProcess, (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
        return pmc.PrivateUsage;
    }
    return 0;
}

bool ProcessManager::IsProcess64Bit(HANDLE process) {
    BOOL isWow64 = FALSE;
    USHORT processMachine = IMAGE_FILE_MACHINE_UNKNOWN;
    USHORT nativeMachine = IMAGE_FILE_MACHINE_UNKNOWN;

    // Try to use IsWow64Process2 if available (Windows 10 and later)
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32) {
        typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS2)(HANDLE, USHORT*, USHORT*);
        LPFN_ISWOW64PROCESS2 fnIsWow64Process2 = reinterpret_cast<LPFN_ISWOW64PROCESS2>(
            GetProcAddress(hKernel32, "IsWow64Process2")
        );
        if (fnIsWow64Process2) {
            if (fnIsWow64Process2(process, &processMachine, &nativeMachine)) {
                // Check if the process is running under WOW64 emulation
                if (processMachine == IMAGE_FILE_MACHINE_UNKNOWN || processMachine == nativeMachine) {
                    // Process and system architectures are the same
                    if (nativeMachine == IMAGE_FILE_MACHINE_AMD64 ||
                        nativeMachine == IMAGE_FILE_MACHINE_ARM64 ||
                        nativeMachine == IMAGE_FILE_MACHINE_IA64) {
                        // 64-bit process
                        return true;
                    } else {
                        // 32-bit process
                        return false;
                    }
                } else {
                    // Process is running under emulation (WOW64), so it's 32-bit
                    return false;
                }
            }
        }
    }

    // Fallback to IsWow64Process for earlier Windows versions
    if (IsWow64Process(process, &isWow64)) {
        if (isWow64) {
            // Process is running under WOW64, so it's 32-bit
            return false;
        } else {
            // Process is not running under WOW64
            // Determine system architecture
            SYSTEM_INFO systemInfo = { 0 };
            GetNativeSystemInfo(&systemInfo);

            if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ||
                systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64) {
                // System is 64-bit, so the process is also 64-bit
                return true;
            } else {
                // System is 32-bit, so the process is 32-bit
                return false;
            }
        }
    }

    // If we can't determine, check if it's a system process
    DWORD pid = GetProcessId(process);
    if (pid == 0 || pid == 4) {  // System Idle Process (0) and System Process (4)
        // These are always native processes, so on 64-bit Windows they're 64-bit
        SYSTEM_INFO systemInfo = { 0 };
        GetNativeSystemInfo(&systemInfo);
        return (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
                systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64 ||
                systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);
    }

    // Unable to determine, assume 32-bit for safety
    return false;
}

std::string ProcessManager::GetProcessUsername(HANDLE hProcess) {
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

std::string ProcessManager::GetProcessStatus(HANDLE hProcess) {
    if (!hProcess) return "N/A";

    DWORD exitCode;
    if (!GetExitCodeProcess(hProcess, &exitCode)) {
        return "N/A";
    }

    if (exitCode == STILL_ACTIVE) {
        DWORD suspendCount = 0;
        HANDLE hThreadSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hThreadSnapshot != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te32;
            te32.dwSize = sizeof(THREADENTRY32);
            DWORD processId = GetProcessId(hProcess);

            if (Thread32First(hThreadSnapshot, &te32)) {
                do {
                    if (te32.th32OwnerProcessID == processId) {
                        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te32.th32ThreadID);
                        if (hThread) {
                            ULONG prevCount;
                            if (NT_SUCCESS(NtSuspendThread(hThread, &prevCount))) {
                                NtResumeThread(hThread, &prevCount);
                                suspendCount += prevCount;
                            }
                            CloseHandle(hThread);
                        }
                    }
                } while (Thread32Next(hThreadSnapshot, &te32));
            }
            CloseHandle(hThreadSnapshot);
        }

        if (suspendCount > 0) {
            return "Suspended";
        }
        return "Running";
    }
    else {
        return "Terminated";
    }
}

std::wstring ProcessManager::ConvertToWideString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

std::string ProcessManager::ConvertToString(const std::wstring& wstr) {
    if (wstr.empty()) return std::string();
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}

ProcessInfo ProcessManager::GetProcessDetails(DWORD pid) {
    // std::cout << "[GetProcessDetails] Starting process details retrieval for PID: " << pid << std::endl;
    ProcessInfo info;
    info.pid = pid;

    // First, get process architecture using just PROCESS_QUERY_INFORMATION
    HANDLE hArchProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (hArchProcess) {
        info.is64Bit = IsProcess64Bit(hArchProcess);
        // std::cout << "[GetProcessDetails] Process architecture: " << (info.is64Bit ? "64-bit" : "32-bit") << std::endl;
        CloseHandle(hArchProcess);
    } else {
        // If we can't get PROCESS_QUERY_INFORMATION, try with limited info
        hArchProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
        if (hArchProcess) {
            info.is64Bit = IsProcess64Bit(hArchProcess);
            // std::cout << "[GetProcessDetails] Process architecture (limited access): " << (info.is64Bit ? "64-bit" : "32-bit") << std::endl;
            CloseHandle(hArchProcess);
        } else {
            info.is64Bit = false; // Default to 32-bit if we can't determine
            // std::cout << "[GetProcessDetails] Failed to determine process architecture, defaulting to 32-bit" << std::endl;
        }
    }

    // Now open with full access rights needed for process details
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        DWORD error = GetLastError();
        // std::cout << "[GetProcessDetails] Failed to open process with full access, error: " << error << ". Trying limited access..." << std::endl;
        
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            error = GetLastError();
            // std::cout << "[GetProcessDetails] Failed to open process with limited access, error: " << error << std::endl;
            info.name = "N/A";
            info.imagePath = "N/A";
            return info;
        }
        // std::cout << "[GetProcessDetails] Successfully opened process with limited access" << std::endl;
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
                            
                            // Read 32-bit PEB
                            PEB32 peb32;
                            SIZE_T bytesRead;
                            if (!ReadProcessMemory(hProcess, (PVOID)(ULONG_PTR)pbi32.PebBaseAddress, &peb32, sizeof(peb32), &bytesRead)) {
                                error = GetLastError();
                                // std::cout << "[GetProcessDetails] Failed to read PEB, error: " << error << std::endl;
                            } else {
                                // Read 32-bit process parameters
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
#endif
                        }
                    }
                }
            }
        } else {
            // std::cout << "[GetProcessDetails] Successfully got process path using GetModuleFileNameExW" << std::endl;
        }
    } else {
        // std::cout << "[GetProcessDetails] Successfully got process path using QueryFullProcessImageNameW" << std::endl;
    }

    if (pathW[0] != L'\0') {
        info.imagePath = ConvertToString(pathW);
        // Extract process name from path
        std::wstring wpath(pathW);
        size_t pos = wpath.find_last_of(L"\\");
        if (pos != std::wstring::npos) {
            info.name = ConvertToString(wpath.substr(pos + 1));
            // std::cout << "[GetProcessDetails] Process name: " << info.name << std::endl;
            // std::cout << "[GetProcessDetails] Image path: " << info.imagePath << std::endl;
        }
    } else {
        // std::cout << "[GetProcessDetails] Path retrieval failed, attempting to get name from process handle..." << std::endl;
        // If we still don't have a name, try to get it from the process handle
        HMODULE hMod;
        DWORD cbNeeded;
        if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
            WCHAR szModName[MAX_PATH];
            if (GetModuleBaseNameW(hProcess, hMod, szModName, sizeof(szModName)/sizeof(WCHAR))) {
                info.name = ConvertToString(szModName);
                info.imagePath = info.name;  // Use name as path if we couldn't get the full path
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
    
    info.iconBase64 = GetProcessIconBase64(pid);
    // std::cout << "[GetProcessDetails] Icon retrieved: " << (!info.iconBase64.empty() ? "Yes" : "No") << std::endl;
    
    info.hasVisibleWindow = HasVisibleWindow(pid);
    // std::cout << "[GetProcessDetails] Has Visible Window: " << (info.hasVisibleWindow ? "Yes" : "No") << std::endl;

    CloseHandle(hProcess);
    // std::cout << "[GetProcessDetails] Process details retrieval completed for PID: " << pid << "\n" << std::endl;
    return info;
}

BOOL CALLBACK EnumWindowsCallback(HWND hwnd, LPARAM lParam) {
    DWORD* processId = (DWORD*)lParam;
    DWORD windowProcessId = 0;
    GetWindowThreadProcessId(hwnd, &windowProcessId);
    
    if (*processId == windowProcessId) {
        // Check if the window is visible and not a tool window
        if (IsWindowVisible(hwnd) && 
            !(GetWindowLongW(hwnd, GWL_EXSTYLE) & WS_EX_TOOLWINDOW) &&
            GetWindow(hwnd, GW_OWNER) == NULL) {
            // Found a visible main window
            *processId = 0;  // Use as a flag to indicate we found a window
            return FALSE;    // Stop enumeration
        }
    }
    return TRUE;  // Continue enumeration
}

bool ProcessManager::HasVisibleWindow(DWORD pid) {
    DWORD processId = pid;
    EnumWindows(EnumWindowsCallback, (LPARAM)&processId);
    return processId == 0;  // If processId is 0, we found a window
}

// Function to enable SeDebugPrivilege
bool ProcessManager::EnableDebugPrivilege() {
    HANDLE hToken;
    TOKEN_PRIVILEGES tkp;

    // Open the process token for the current process
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        // std::cout << "[EnableDebugPrivilege] OpenProcessToken failed. Error: " << GetLastError() << std::endl;
        return false;
    }

    // Get the LUID for SeDebugPrivilege
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tkp.Privileges[0].Luid)) {
        // std::cout << "[EnableDebugPrivilege] LookupPrivilegeValue failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    tkp.PrivilegeCount = 1;  // One privilege to set
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    // Adjust the token privileges to enable SeDebugPrivilege
    if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
        // std::cout << "[EnableDebugPrivilege] AdjustTokenPrivileges failed. Error: " << GetLastError() << std::endl;
        CloseHandle(hToken);
        return false;
    }

    DWORD error = GetLastError();
    if (error == ERROR_NOT_ALL_ASSIGNED) {
        // std::cout << "[EnableDebugPrivilege] The token does not have the specified privilege. Error: " << error << std::endl;
        CloseHandle(hToken);
        return false;
    } else if (error != ERROR_SUCCESS) {
        // std::cout << "[EnableDebugPrivilege] AdjustTokenPrivileges returned error: " << error << std::endl;
        CloseHandle(hToken);
        return false;
    }

    // std::cout << "[EnableDebugPrivilege] SeDebugPrivilege enabled successfully." << std::endl;
    CloseHandle(hToken);
    return true;
}
