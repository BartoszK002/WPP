add_library(protection_dll SHARED
    src/dllmain.cpp
    src/protection.cpp
    src/handle_monitor.cpp
    include/protection.h
    include/handle_monitor.h
)

target_include_directories(protection_dll PRIVATE 
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Set Windows-specific properties
set_target_properties(protection_dll PROPERTIES
    WINDOWS_EXPORT_ALL_SYMBOLS TRUE
)
