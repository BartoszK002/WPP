#pragma once

namespace Protection {
    // Strip handles from other processes that point to our process
    bool StripProcessHandles();
    
    // Monitor handle creation attempts
    bool MonitorHandleCreation();
}
