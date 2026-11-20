cmake_minimum_required(VERSION 3.16)
project(demo VERSION 1.4.0 LANGUAGES CXX)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake")

option(ENABLE_GPU "Build the GPU tools" OFF)
option(ENABLE_TLS "Build with TLS" ON)
set(FMT_VERSION 11.1.2)

find_package(PkgConfig REQUIRED)
find_package(Threads REQUIRED)
find_package(ZLIB 1.2.11 REQUIRED)
find_package(Boost 1.74 EXACT REQUIRED COMPONENTS system)
find_package(Snappy)
find_package(YAMLCPP REQUIRED)
find_package(Python3 COMPONENTS Interpreter)

if(ENABLE_TLS)
    find_package(OpenSSL 3.0...<4 REQUIRED)
else()
    find_package(WolfSSL REQUIRED)
endif()

if(SNAPPY_FOUND)
    pkg_check_modules(LZ4 REQUIRED liblz4>=1.9)
endif()

if(WIN32)
    find_package(WinSock REQUIRED)
elseif(ENABLE_GPU)
    find_package(Vulkan REQUIRED)
endif()

include(FetchContent)
FetchContent_Declare(fmt
    GIT_REPOSITORY https://github.com/fmtlib/fmt.git
    GIT_TAG ${FMT_VERSION})
FetchContent_Declare(tinyxml
    URL https://example.com/tinyxml-2.6.2.tar.gz
    URL_HASH SHA256=15BDFDCEC58A7DA30ADC87AC2A078E4417DBE5392F3AFB719F9BA6D062645593)
FetchContent_Declare(unpinned
    GIT_REPOSITORY https://gitlab.com/group/sub/unpinned.git
    GIT_TAG ${SET_ON_THE_COMMAND_LINE})

add_subdirectory(src)
add_subdirectory(third_party/vendored)
if(ENABLE_GPU)
    add_subdirectory(tools/gpu)
endif()
add_subdirectory(tests)
