cmake_minimum_required(VERSION 3.10)

# Enable manifest generation
if(MSVC)
    cmake_policy(SET CMP0169 NEW)
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} /MANIFEST:NO")
endif()

add_executable(web_ui
    src/main.cpp
    src/process_manager.cpp
    src/lodepng.cpp
    include/process_manager.h
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
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.hpp
    DOWNLOAD_NO_EXTRACT TRUE
    DOWNLOAD_DIR ${CMAKE_CURRENT_BINARY_DIR}/include/nlohmann
)
FetchContent_MakeAvailable(json)

target_link_libraries(web_ui PRIVATE httplib::httplib)
target_include_directories(web_ui 
    PRIVATE 
        ${CMAKE_CURRENT_SOURCE_DIR}/include
        ${CMAKE_CURRENT_BINARY_DIR}/include  # For nlohmann/json.hpp
)

# Copy static files to build directory
add_custom_command(TARGET web_ui POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_CURRENT_SOURCE_DIR}/src/static
        $<TARGET_FILE_DIR:web_ui>/static
)
