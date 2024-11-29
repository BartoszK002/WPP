#pragma once

// Windows headers in correct order
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <objidl.h>     // For IStream
#include <gdiplus.h>
#include <psapi.h>
#include <tlhelp32.h>
#include <winternl.h>

// STL headers
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <shared_mutex>
#include <filesystem>
#include <iostream>

// Link required libraries
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

namespace process_manager {
    std::wstring ConvertToWideString(const std::string& str);
    std::string ConvertToString(const std::wstring& wstr);
} 