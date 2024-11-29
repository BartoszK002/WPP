#define CPPHTTPLIB_OPENSSL_SUPPORT
#include <httplib.h>
#include "process_manager.h"
#include <filesystem>
#include <nlohmann/json.hpp>
#include <Windows.h>
#include <sstream>
#include <iomanip>
#include <lmcons.h>
#include <codecvt>
#include <locale>

using json = nlohmann::json;

std::string ws2s(const std::wstring& wstr) {
    std::string str;
    for (wchar_t wc : wstr) {
        str += static_cast<char>(wc);
    }
    return str;
}

std::string GetWindowsVersion() {
    OSVERSIONINFOEXW osInfo;
    ZeroMemory(&osInfo, sizeof(OSVERSIONINFOEXW));
    osInfo.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEXW);

    typedef NTSTATUS(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    if (ntdll) {
        auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
        if (RtlGetVersion) {
            RtlGetVersion((PRTL_OSVERSIONINFOW)&osInfo);
        }
    }

    std::ostringstream oss;
    if (osInfo.dwMajorVersion == 10 && osInfo.dwBuildNumber >= 22000) {
        oss << "Windows 11";
    } else {
        oss << "Windows " << osInfo.dwMajorVersion;
    }

    // Get edition information
    DWORD bufferSize = 0;
    GetProductInfo(osInfo.dwMajorVersion, osInfo.dwMinorVersion, 
                  osInfo.wServicePackMajor, osInfo.wServicePackMinor, &bufferSize);

    wchar_t buffer[256];
    DWORD size = sizeof(buffer);
    if (RegGetValueW(HKEY_LOCAL_MACHINE, 
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"DisplayVersion",
                     RRF_RT_REG_SZ,
                     nullptr,
                     buffer,
                     &size) == ERROR_SUCCESS) {
        oss << " Version " << ws2s(buffer);
    }

    oss << " (Build " << osInfo.dwBuildNumber;
    
    // Get UBR (Update Build Revision)
    DWORD ubr = 0;
    size = sizeof(ubr);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"UBR",
                     RRF_RT_REG_DWORD,
                     nullptr,
                     &ubr,
                     &size) == ERROR_SUCCESS) {
        oss << "." << ubr;
    }
    oss << ")";

    // Get edition (Pro, Home, etc.)
    size = sizeof(buffer);
    if (RegGetValueW(HKEY_LOCAL_MACHINE,
                     L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                     L"EditionID",
                     RRF_RT_REG_SZ,
                     nullptr,
                     buffer,
                     &size) == ERROR_SUCCESS) {
        oss << " " << ws2s(buffer);
    }

    return oss.str();
}

std::string GetComputerName() {
    wchar_t buffer[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(buffer)/sizeof(buffer[0]);
    if (GetComputerNameW(buffer, &size)) {
        return ws2s(buffer);
    }
    return "Unknown";
}

std::string GetUsername() {
    wchar_t buffer[UNLEN + 1];
    DWORD size = sizeof(buffer)/sizeof(buffer[0]);
    if (GetUserNameW(buffer, &size)) {
        return ws2s(buffer);
    }
    return "Unknown";
}

const char* HTML_HEAD = R"html(
<!DOCTYPE html>
<html>
<head>
    <title>Windows Process Protector</title>
    <link rel="stylesheet" href="/static/css/styles.css">
    <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet">
</head>
)html";

const char* HTML_BODY = R"html(
<body>
    <div class="container">
        <h1>Windows Process Protector</h1>

        <div class="system-info">
            <h2><i class="material-icons">computer</i>System Information</h2>
            <div class="system-info-grid">
                <div class="system-info-item">
                    <span class="system-info-label">Computer Name</span>
                    <span class="system-info-value" id="computerName">Loading...</span>
                </div>
                <div class="system-info-item">
                    <span class="system-info-label">Username</span>
                    <span class="system-info-value" id="username">Loading...</span>
                </div>
                <div class="system-info-item">
                    <span class="system-info-label">OS Version</span>
                    <span class="system-info-value" id="osVersion">Loading...</span>
                </div>
            </div>
        </div>

        <div class="control-layout">
            <div class="top-controls">
                <div class="control-panel filter-panel">
                    <h3><i class="material-icons">filter_list</i>Process Filters</h3>
                    <div class="filter-controls">
                        <div class="filter-group">
                            <label>Architecture:</label>
                            <select id="archFilter">
                                <option value="all">All</option>
                                <option value="x64">x64</option>
                                <option value="x86">x86</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label>Status:</label>
                            <select id="protectionFilter">
                                <option value="all">All</option>
                                <option value="protected">Protected</option>
                                <option value="unprotected">Unprotected</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label>Type:</label>
                            <select id="systemFilter">
                                <option value="all">All Processes</option>
                                <option value="user">User Processes</option>
                                <option value="system">System Processes</option>
                            </select>
                        </div>
                        <div class="filter-group">
                            <label>Window:</label>
                            <select id="windowFilter">
                                <option value="all">All Processes</option>
                                <option value="visible">With Window</option>
                                <option value="hidden">Without Window</option>
                            </select>
                        </div>
                    </div>
                </div>

                <div class="control-panel refresh-panel">
                    <h3><i class="material-icons">refresh</i>Refresh Settings</h3>
                    <div class="refresh-controls">
                        <div class="refresh-group">
                            <label>
                                <input type="checkbox" id="autoRefresh" checked>
                                Auto-refresh
                            </label>
                            <select id="refreshInterval">
                                <option value="1000">1 second</option>
                                <option value="2000">2 seconds</option>
                                <option value="5000" selected>5 seconds</option>
                                <option value="10000">10 seconds</option>
                            </select>
                        </div>
                    </div>
                </div>
            </div>

            <div class="search-row">
                <div class="control-panel search-panel">
                    <h3><i class="material-icons">search</i>Process Search</h3>
                    <div class="search-controls">
                        <div class="search-container">
                            <input type="text" id="searchInput" placeholder="Search processes..." />
                            <button type="button" class="search-clear" id="searchClear" aria-label="Clear search">
                                <i class="material-icons">close</i>
                            </button>
                        </div>
                        <div class="help-text">Search by process name or PID (updates in real-time)</div>
                    </div>
                </div>
            </div>
        </div>

        <table>
            <thead>
                <tr>
                    <th data-column="name">Process Name</th>
                    <th data-column="pid">PID</th>
                    <th data-column="arch">Architecture</th>
                    <th data-column="protection">Protection Status</th>
                    <th>Actions</th>
                </tr>
            </thead>
            <tbody id="processTable">
            </tbody>
        </table>
    </div>
    <script src="/static/js/main.js"></script>
</body>
</html>
)html";

void SendHTML(httplib::Response& res) {
    std::stringstream ss;
    ss << HTML_HEAD << HTML_BODY;
    
    res.set_content(ss.str(), "text/html");
}

int main() {
    httplib::Server svr;
    process_manager::ProcessManager pm;

    // Enable debug privilege
    if (!process_manager::SystemInfo::EnableDebugPrivilege()) {
        std::cout << "Warning: Failed to enable debug privilege. Some process information may be limited." << std::endl;
    } else {
        std::cout << "Successfully enabled debug privilege." << std::endl;
    }

    // Get the executable directory
    char exePath[MAX_PATH];
    GetModuleFileNameA(NULL, exePath, MAX_PATH);
    std::string exeDir = std::filesystem::path(exePath).parent_path().string();
    std::string staticPath = exeDir + "/static";

    // Create static directories if they don't exist
    std::filesystem::create_directories(staticPath + "/css");
    std::filesystem::create_directories(staticPath + "/js");

    // Serve static files
    svr.set_mount_point("/static", staticPath.c_str());

    // Main page
    svr.Get("/", [](const httplib::Request& req, httplib::Response& res) {
        SendHTML(res);
    });

    // Get system info
    svr.Get("/api/system-info", [](const httplib::Request& req, httplib::Response& res) {
        json info;
        info["osVersion"] = GetWindowsVersion();
        info["computerName"] = GetComputerName();
        info["username"] = GetUsername();
        res.set_content(info.dump(), "application/json");
    });

    // Get processes
    svr.Get("/api/processes", [&pm](const httplib::Request& req, httplib::Response& res) {
        auto processes = pm.GetRunningProcesses();
        json j = json::array();
        
        for (const auto& proc : processes) {
            json process;
            process["name"] = proc.name;
            process["pid"] = proc.pid;
            process["icon"] = proc.iconBase64;
            process["is64Bit"] = proc.is64Bit;
            process["isProtected"] = proc.isProtected;
            process["isSystemProcess"] = process_manager::ProcessInfoManager::IsWindowsSystemProcess(
                std::wstring(proc.name.begin(), proc.name.end()), 
                proc.pid
            );
            process["hasVisibleWindow"] = proc.hasVisibleWindow;
            j.push_back(process);
        }
        
        res.set_content(j.dump(), "application/json");
    });

    // Get process details
    svr.Get(R"(/api/process/(\d+))", [&pm](const httplib::Request& req, httplib::Response& res) {
        auto pid = std::stoi(req.matches[1].str());
        auto procInfo = pm.GetProcessDetails(pid);
        
        // Format PID in hex
        std::stringstream hexPid;
        hexPid << "0x" << std::uppercase << std::hex << std::setfill('0') << std::setw(4) << procInfo.pid;
        
        json result = {
            {"pid", procInfo.pid},
            {"pidHex", hexPid.str()},
            {"name", procInfo.name},
            {"isProtected", procInfo.isProtected},
            {"iconBase64", procInfo.iconBase64},
            {"is64Bit", procInfo.is64Bit},
            {"status", procInfo.status},
            {"username", procInfo.username},
            {"cpuUsage", procInfo.cpuUsage},
            {"workingSetPrivate", procInfo.workingSetPrivate},
            {"imagePath", procInfo.imagePath},
            {"commandLine", procInfo.commandLine},
            {"description", procInfo.description}
        };
        res.set_content(result.dump(), "application/json");
    });

    // Protect process
    svr.Post("/api/protect", [&pm](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        std::string errorMsg;
        
        if (pm.InjectProtectionDLL(pid, errorMsg)) {
            // Check if the process is actually protected
            if (process_manager::ProcessInfoManager::IsProcessProtected(pid)) {
                json response;
                response["success"] = true;
                response["message"] = "Process protected successfully";
                std::cout << "Success response: " << response.dump(2) << std::endl;
                res.set_content(response.dump(), "application/json");
            } else {
                json response;
                response["success"] = false;
                response["error"] = "DLL injection succeeded but protection features failed to initialize";
                response["error_code"] = GetLastError();
                response["error_details"] = [&]() -> std::string {
                    char* lpMsgBuf;
                    DWORD dw = GetLastError();
                    FormatMessageA(
                        FORMAT_MESSAGE_ALLOCATE_BUFFER |
                        FORMAT_MESSAGE_FROM_SYSTEM |
                        FORMAT_MESSAGE_IGNORE_INSERTS,
                        NULL,
                        dw,
                        MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                        (LPSTR)&lpMsgBuf,
                        0, NULL);
                    std::string msg(lpMsgBuf);
                    LocalFree(lpMsgBuf);
                    return msg;
                }();
                std::cout << "Error response (protection failed): " << response.dump(2) << std::endl;
                res.set_content(response.dump(), "application/json");
                res.status = 400;
            }
        } else {
            json response;
            response["success"] = false;
            response["error"] = errorMsg;
            response["error_code"] = GetLastError();
            response["error_details"] = [&]() -> std::string {
                char* lpMsgBuf;
                DWORD dw = GetLastError();
                FormatMessageA(
                    FORMAT_MESSAGE_ALLOCATE_BUFFER |
                    FORMAT_MESSAGE_FROM_SYSTEM |
                    FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL,
                    dw,
                    MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
                    (LPSTR)&lpMsgBuf,
                    0, NULL);
                std::string msg(lpMsgBuf);
                LocalFree(lpMsgBuf);
                return msg;
            }();
            std::cout << "Error response (injection failed): " << response.dump(2) << std::endl;
            res.set_content(response.dump(), "application/json");
            res.status = 400;
        }
    });

    // Add these endpoints
    svr.Post("/api/process/terminate", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
        if (hProcess == NULL) {
            json response = {
                {"success", false},
                {"error", "Failed to open process"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        if (TerminateProcess(hProcess, 1)) {
            json response = {{"success", true}};
            res.set_content(response.dump(), "application/json");
        } else {
            json response = {
                {"success", false},
                {"error", "Failed to terminate process"}
            };
            res.set_content(response.dump(), "application/json");
        }
        CloseHandle(hProcess);
    });

    svr.Post("/api/process/suspend", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        bool success = process_manager::ProcessInfoManager::SuspendProcess(pid);
        
        json response = {
            {"success", success},
            {"error", success ? "" : "Failed to suspend process"}
        };
        res.set_content(response.dump(), "application/json");
    });

    svr.Post("/api/process/resume", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        bool success = process_manager::ProcessInfoManager::ResumeProcess(pid);
        
        json response = {
            {"success", success},
            {"error", success ? "" : "Failed to resume process"}
        };
        res.set_content(response.dump(), "application/json");
    });

    // Get process modules
    svr.Get(R"(/api/process/(\d+)/modules)", [](const httplib::Request& req, httplib::Response& res) {
        auto pid = std::stoi(req.matches[1].str());
        auto modules = process_manager::ProcessInfoManager::GetProcessModules(pid);
        
        json j = json::array();
        for (const auto& mod : modules) {
            json module = {
                {"name", mod.name},
                {"path", mod.path},
                {"description", mod.description},
                {"baseAddress", [&mod]() {
                    std::stringstream ss;
                    ss << "0x" << std::uppercase << std::hex << mod.baseAddress;
                    return ss.str();
                }()},
                {"size", mod.size}
            };
            j.push_back(module);
        }
        
        res.set_content(j.dump(), "application/json");
    });

    // Unprotect process
    svr.Post("/api/unprotect", [](const httplib::Request& req, httplib::Response& res) {
        auto j = json::parse(req.body);
        auto pid = j["pid"].get<DWORD>();
        
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) {
            json response = {
                {"success", false},
                {"error", "Failed to open process"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Find the protection DLL
        HMODULE hMods[1024];
        DWORD cbNeeded;
        bool found = false;
        HMODULE protectionDll = NULL;
        
        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            for (DWORD i = 0; i < (cbNeeded / sizeof(HMODULE)); i++) {
                wchar_t szModName[MAX_PATH];
                if (GetModuleFileNameExW(hProcess, hMods[i], szModName, sizeof(szModName) / sizeof(wchar_t))) {
                    std::wstring moduleName = szModName;
                    if (moduleName.find(L"protection_dll.dll") != std::wstring::npos) {
                        protectionDll = hMods[i];
                        found = true;
                        break;
                    }
                }
            }
        }
        
        CloseHandle(hProcess);
        
        if (!found) {
            json response = {
                {"success", false},
                {"error", "Process is not protected"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        // Unload the DLL
        HANDLE hUnloadProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | 
            PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        
        if (!hUnloadProcess) {
            json response = {
                {"success", false},
                {"error", "Failed to open process for unprotection"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        LPVOID pFreeLibrary = (LPVOID)GetProcAddress(GetModuleHandleW(L"kernel32.dll"), "FreeLibrary");
        HANDLE hThread = CreateRemoteThread(hUnloadProcess, NULL, 0, 
            (LPTHREAD_START_ROUTINE)pFreeLibrary, protectionDll, 0, NULL);
        
        if (!hThread) {
            CloseHandle(hUnloadProcess);
            json response = {
                {"success", false},
                {"error", "Failed to create unload thread"}
            };
            res.set_content(response.dump(), "application/json");
            return;
        }
        
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
        CloseHandle(hUnloadProcess);
        
        json response = {{"success", true}};
        res.set_content(response.dump(), "application/json");
    });

    std::cout << "Server started on http://localhost:8080" << std::endl;
    svr.listen("localhost", 8080);
    
    return 0;
}
