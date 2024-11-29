cmake_minimum_required(VERSION 3.10)

# Enable manifest generation
if(MSVC)
    cmake_policy(SET CMP0169 NEW)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
endif()

# Add source files
set(PROCESS_MANAGER_SOURCES
    src/process_manager/base.cpp
    src/process_manager/icon_manager.cpp
    src/process_manager/process_info.cpp
    src/process_manager/process_manager.cpp
    src/process_manager/system_info.cpp
)

set(PROCESS_MANAGER_HEADERS
    include/process_manager.h
    include/process_manager/base.h
    include/process_manager/icon_manager.h
    include/process_manager/process_info.h
    include/process_manager/system_info.h
    include/process_manager/windows_api.h
)

add_executable(web_ui
    ${PROCESS_MANAGER_SOURCES}
    ${PROCESS_MANAGER_HEADERS}
    src/main.cpp
    src/lodepng.cpp
)

if(MSVC)
    # Add manifest requirements directly
    set_target_properties(web_ui PROPERTIES
        LINK_FLAGS "/MANIFESTUAC:\"level='requireAdministrator' uiAccess='false'\" /MANIFEST:EMBED"
    )
endif()

# Add cpp-httplib (header-only)
include(FetchContent)
FetchContent_Declare(
    httplib
    GIT_REPOSITORY https://github.com/yhirose/cpp-httplib
    GIT_TAG v0.14.1
)
FetchContent_MakeAvailable(httplib)

# Add nlohmann/json (header-only)
FetchContent_Declare(
    json
    GIT_REPOSITORY https://github.com/nlohmann/json.git
    GIT_TAG v3.11.3
)
FetchContent_MakeAvailable(json)

target_include_directories(web_ui
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${CMAKE_CURRENT_BINARY_DIR}/_deps/json-src/include
)

# Link required libraries
target_link_libraries(web_ui
    PRIVATE
        gdiplus
        psapi
        ntdll
        comctl32
        httplib::httplib
        nlohmann_json::nlohmann_json
        version
)

# Add compile definitions
target_compile_definitions(web_ui
    PRIVATE
        UNICODE
        _UNICODE
)

# Copy static files to build directory
add_custom_command(TARGET web_ui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/src/static
        $<TARGET_FILE_DIR:web_ui>/static
)
