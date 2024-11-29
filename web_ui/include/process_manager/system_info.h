#pragma once
#include "base.h"

namespace process_manager {
    class SystemInfo {
    public:
        static bool IsProcess64Bit(HANDLE process);
        static bool EnableDebugPrivilege();
    };
} 