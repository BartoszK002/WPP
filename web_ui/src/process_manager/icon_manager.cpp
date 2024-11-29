#include "process_manager/icon_manager.h"
#include <shellapi.h>
#include <commctrl.h>
#include <commoncontrols.h>
#include <psapi.h>

#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "comctl32.lib")

namespace process_manager {

// Initialize static members
std::unordered_map<std::wstring, std::string> IconManager::iconCache;
std::shared_mutex IconManager::cacheMutex;

std::string IconManager::GetProcessIconBase64(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
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
        std::vector<uint8_t> placeholderData = CreatePlaceholderIcon();
        if (!placeholderData.empty()) {
            std::string base64Data = Base64Encode(placeholderData);
            return "data:image/png;base64," + base64Data;
        }
        return "";
    }
    CloseHandle(hProcess);

    // Check cache
    std::wstring exePathStr(exePath);
    {
        std::shared_lock<std::shared_mutex> lock(cacheMutex);
        auto it = iconCache.find(exePathStr);
        if (it != iconCache.end()) {
            return it->second;
        }
    }

    // Extract icon
    std::vector<uint8_t> iconData = ExtractIconFromExe(exePath);
    if (iconData.empty()) {
        std::vector<uint8_t> placeholderData = CreatePlaceholderIcon();
        if (!placeholderData.empty()) {
            std::string base64Data = Base64Encode(placeholderData);
            std::string fullDataUrl = "data:image/png;base64," + base64Data;
            
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
        std::vector<uint8_t> placeholderData = CreatePlaceholderIcon();
        if (!placeholderData.empty()) {
            std::string base64Data = Base64Encode(placeholderData);
            return "data:image/png;base64," + base64Data;
        }
        return "";
    }

    std::string fullDataUrl = "data:image/png;base64," + base64Data;

    // Cache the result
    {
        std::unique_lock<std::shared_mutex> lock(cacheMutex);
        iconCache[exePathStr] = fullDataUrl;
    }

    return fullDataUrl;
}

std::vector<uint8_t> IconManager::ExtractIconFromExe(const std::wstring& exePath) {
    std::vector<uint8_t> result;

    // Initialize GDI+
    Gdiplus::GdiplusStartupInput gdiplusStartupInput;
    ULONG_PTR gdiplusToken;
    if (Gdiplus::GdiplusStartup(&gdiplusToken, &gdiplusStartupInput, NULL) != Gdiplus::Ok) {
        return result;
    }

    // Get icon index
    SHFILEINFOW sfi = { 0 };
    if (!SHGetFileInfoW(
        exePath.c_str(),
        FILE_ATTRIBUTE_NORMAL,
        &sfi,
        sizeof(sfi),
        SHGFI_SYSICONINDEX | SHGFI_USEFILEATTRIBUTES
    )) {
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Initialize common controls
    INITCOMMONCONTROLSEX icex;
    icex.dwSize = sizeof(icex);
    icex.dwICC = ICC_LISTVIEW_CLASSES;
    InitCommonControlsEx(&icex);

    // Get image list
    IImageList* pImageList = NULL;
    HRESULT hr = SHGetImageList(SHIL_EXTRALARGE, IID_IImageList, (void**)&pImageList);
    
    if (FAILED(hr)) {
        hr = SHGetImageList(SHIL_LARGE, IID_IImageList, (void**)&pImageList);
        if (FAILED(hr)) {
            Gdiplus::GdiplusShutdown(gdiplusToken);
            return result;
        }
    }

    // Get icon
    HICON hIcon = NULL;
    hr = pImageList->GetIcon(sfi.iIcon, ILD_TRANSPARENT, &hIcon);
    if (FAILED(hr) || hIcon == NULL) {
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Convert to bitmap
    Gdiplus::Bitmap* bitmap = IconToBitmapPARGB32(hIcon);
    if (!bitmap) {
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Create stream for PNG
    IStream* istream = nullptr;
    if (CreateStreamOnHGlobal(NULL, TRUE, &istream) != S_OK) {
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Get PNG encoder
    CLSID pngClsid;
    if (GetEncoderClsid(L"image/png", &pngClsid) == -1) {
        istream->Release();
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Configure PNG encoding
    Gdiplus::EncoderParameters encoderParams;
    encoderParams.Count = 1;
    encoderParams.Parameter[0].Guid = Gdiplus::EncoderQuality;
    encoderParams.Parameter[0].Type = Gdiplus::EncoderParameterValueTypeLong;
    encoderParams.Parameter[0].NumberOfValues = 1;
    ULONG quality = 100;
    encoderParams.Parameter[0].Value = &quality;

    // Save to PNG
    if (bitmap->Save(istream, &pngClsid, &encoderParams) != Gdiplus::Ok) {
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
        istream->Release();
        delete bitmap;
        DestroyIcon(hIcon);
        pImageList->Release();
        Gdiplus::GdiplusShutdown(gdiplusToken);
        return result;
    }

    // Read PNG data
    result.resize(statstg.cbSize.LowPart);
    LARGE_INTEGER liZero = {};
    if (istream->Seek(liZero, STREAM_SEEK_SET, NULL) != S_OK) {
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
        result.clear();
    }

    // Cleanup
    istream->Release();
    delete bitmap;
    DestroyIcon(hIcon);
    pImageList->Release();
    Gdiplus::GdiplusShutdown(gdiplusToken);

    return result;
}

Gdiplus::Bitmap* IconManager::IconToBitmapPARGB32(HICON hIcon) {
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

    Gdiplus::Bitmap* bitmap = new Gdiplus::Bitmap(width, height, PixelFormat32bppPARGB);
    if (!bitmap) {
        DeleteObject(iconInfo.hbmColor);
        DeleteObject(iconInfo.hbmMask);
        return nullptr;
    }

    Gdiplus::Graphics* graphics = Gdiplus::Graphics::FromImage(bitmap);
    if (!graphics) {
        delete bitmap;
        DeleteObject(iconInfo.hbmColor);
        DeleteObject(iconInfo.hbmMask);
        return nullptr;
    }

    graphics->SetInterpolationMode(Gdiplus::InterpolationModeHighQualityBicubic);
    graphics->SetSmoothingMode(Gdiplus::SmoothingModeHighQuality);
    graphics->SetPixelOffsetMode(Gdiplus::PixelOffsetModeHighQuality);
    graphics->Clear(Gdiplus::Color::Transparent);

    HDC hdc = graphics->GetHDC();
    if (hdc) {
        DrawIconEx(hdc, 0, 0, hIcon, width, height, 0, NULL, DI_NORMAL);
        graphics->ReleaseHDC(hdc);
    }

    delete graphics;
    DeleteObject(iconInfo.hbmColor);
    DeleteObject(iconInfo.hbmMask);

    return bitmap;
}

int IconManager::GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num = 0;
    UINT size = 0;

    if (Gdiplus::GetImageEncodersSize(&num, &size) != Gdiplus::Ok) {
        return -1;
    }

    if (size == 0) {
        return -1;
    }

    Gdiplus::ImageCodecInfo* pImageCodecInfo = (Gdiplus::ImageCodecInfo*)(malloc(size));
    if (pImageCodecInfo == NULL) {
        return -1;
    }

    if (Gdiplus::GetImageEncoders(num, size, pImageCodecInfo) != Gdiplus::Ok) {
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

    free(pImageCodecInfo);
    return -1;
}

std::string IconManager::Base64Encode(const std::vector<uint8_t>& data) {
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

std::vector<uint8_t> IconManager::CreatePlaceholderIcon() {
    // Predefined placeholder icon as base64 string
    const char* base64Icon = "iVBORw0KGgoAAAANSUhEUgAAADAAAAAwCAYAAABXAvmHAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAM5SURBVGhD7ZnZTlNhEMd7JS2FQlteRMBXUmSTClpRkU1AFFwTHoBHMF4CshRkRxZFNr2WxBfgZszMt/CdbzjJJCex1JxJfqEBMuf3/2fODSQS8cQTTzxlnVuNjVDo6oDeYk9F0dZyB5qbGiGBH/wfXjdKpdKVX7H4hP/LlQYFuLi4qEjiAOXm/w0wPT0NU1NTAfB7/u+NrfyBhg+/oOH9TyL/DjmD/FvkFPJvkBPIvdZMHkNu4hiyE0eQfYX8gJHF32yv9PmhAaSQNIkb6TMrnfekc4509qXhELLjh2yvlMgBgk2f2qZJnsSPPHEljNS/+K4Y+8b2SokeAMVJVgtP6vMw0k7L9eNaWEsTowdQN3rA9koJDSC9QX4eQWm/aSWtxUf2Fc/32V7p80MDSMldKe02rcVReuSAMNJ1w3tEZmiX7ZUSOYArbcVty6rpeqdpI103pMSJwa9sr5TIAWzTVtxrmdiDzPCubRuFiYEdqEX6t9leKaEBpDdoX8SAtD6NYd2wJ23p34HaZ9tQ27fF9kqfHxpASqBp56aVtBbXwtg0CRNbJF7zdBNq+jbZXinRA5ibNm17TV8lTaD4kw3F4w22V0rkAJkhLexLW3HddN+mattKr5N4uncd0r1rbK+U0ADSG3SlM0Zat4zC2LRt25NOP0JWIV1cZXulzw8NIMU9jxpqGsV1y/o8uPQaSVc//GLx90qJHsC8iAFpbHod0oiRLqqmXenqBytQ3bMCqZ5ltldK5ABMGoWtNG9aSS8rupch1V2C1P0S2yslNID0Bm3LJK1aTheVbNoIO9IpK71kSRYW2V4poQGkuC8i4UprcRLWTVvxArIIyXsLkLxXxgDsPKy0xkgb4a5L6WTnAiQ756GqY57tlRI9AJN2mibpJSVtxEl6Aao6Piva5wh/r5TQANJ34FK4dCkcaFrTOa/bdsTbkFm40TrL9koJDSDFNM2kzXkYad20K03cnSH8vVKiBwhIO8Kh0krYx98rJXKAwU9nwdNASHgu2HLrDFQ5jbsMfDxhe6VEDlBu4gDlhgIUutrh/Jz/ee+6g85tLbch0dx0kz5gmkoCi0d3/19m8cQTTzz/dv4ClooDMBDzMO4AAAAASUVORK5CYII=";

    std::vector<uint8_t> decodedData;
    
    try {
        const char* base64Data = strstr(base64Icon, ",");
        if (base64Data) {
            base64Data++;
        } else {
            base64Data = base64Icon;
        }

        size_t inputLength = strlen(base64Data);
        
        std::string cleanBase64;
        for (size_t i = 0; i < inputLength; i++) {
            if (!isspace(base64Data[i])) {
                cleanBase64 += base64Data[i];
            }
        }

        size_t decodedLength = (cleanBase64.length() * 3) / 4;
        if (cleanBase64[cleanBase64.length() - 1] == '=') decodedLength--;
        if (cleanBase64[cleanBase64.length() - 2] == '=') decodedLength--;

        decodedData.resize(decodedLength);

        static const unsigned char lookup[] = {
            62,  255, 62,  255, 63,  52,  53, 54, 55, 56, 57, 58, 59, 60, 61, 255,
            255, 255, 255, 255, 255, 255, 0,  1,  2,  3,  4,  5,  6,  7,  8,  9,
            10,  11,  12,  13,  14,  15,  16, 17, 18, 19, 20, 21, 22, 23, 24, 25,
            255, 255, 255, 255, 63,  255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35,
            36,  37,  38,  39,  40,  41,  42, 43, 44, 45, 46, 47, 48, 49, 50, 51
        };

        size_t j = 0;
        unsigned int accumulator = 0;
        int bits = 0;
        
        for (char c : cleanBase64) {
            if (c == '=') break;

            accumulator = (accumulator << 6) | lookup[c - 43];
            bits += 6;

            if (bits >= 8) {
                bits -= 8;
                decodedData[j++] = (accumulator >> bits) & 0xFF;
            }
        }
    }
    catch (const std::exception& e) {
        decodedData.clear();
    }

    return decodedData;
}

} // namespace process_manager 