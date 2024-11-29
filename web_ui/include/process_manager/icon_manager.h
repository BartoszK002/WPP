#pragma once
#include "base.h"
#include <shellapi.h>
#include <commctrl.h>
#include <commoncontrols.h>

#pragma comment(lib, "comctl32.lib")

namespace process_manager {
    class IconManager {
    public:
        static std::string GetProcessIconBase64(DWORD pid);
        
    private:
        static std::vector<uint8_t> ExtractIconFromExe(const std::wstring& exePath);
        static std::string Base64Encode(const std::vector<uint8_t>& data);
        static Gdiplus::Bitmap* IconToBitmapPARGB32(HICON hIcon);
        static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid);
        static std::vector<uint8_t> CreatePlaceholderIcon();
        
        static std::unordered_map<std::wstring, std::string> iconCache;
        static std::shared_mutex cacheMutex;
    };
} 