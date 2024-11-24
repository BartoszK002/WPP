#pragma once

namespace Protection {
    bool Initialize();
    void Cleanup();
    bool HookMemoryAllocation();
    bool PreventRemoteThreads();
    bool StripHandles();
}
