cmake_minimum_required(VERSION 3.18)
project(nexus_vm LANGUAGES CXX C)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Capstone for ARM64 disassembly
include(FetchContent)
FetchContent_Declare(
    capstone
    GIT_REPOSITORY https://github.com/capstone-engine/capstone.git
    GIT_TAG 5.0.1
)
set(CAPSTONE_BUILD_SHARED OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(CAPSTONE_BUILD_CSTOOL OFF CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(capstone)

add_subdirectory(src)
