// Add these globals to track our hooks
std::vector<HOOK_INFO> g_hooks;
bool g_isProtected = false;

// Add cleanup function
void CleanupProtection() {
    if (!g_isProtected) return;

    // Unhook all functions
    for (const auto& hook : g_hooks) {
        if (hook.originalBytes && hook.hookAddress) {
            DWORD oldProtect;
            if (VirtualProtect(hook.hookAddress, hook.originalSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                memcpy(hook.hookAddress, hook.originalBytes, hook.originalSize);
                VirtualProtect(hook.hookAddress, hook.originalSize, oldProtect, &oldProtect);
            }
        }
    }

    g_hooks.clear();
    g_isProtected = false;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
        case DLL_PROCESS_ATTACH:
            // ... existing initialization code ...
            g_isProtected = true;
            break;

        case DLL_PROCESS_DETACH:
            CleanupProtection();
            break;
    }
    return TRUE;
} 