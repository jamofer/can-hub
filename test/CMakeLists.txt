cmake_minimum_required(VERSION 3.16)
project(can_hub_tests C CXX)

# ROOT_SRC_DIR is the absolute path to src/ in the main project.
get_filename_component(ROOT_SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src" ABSOLUTE)
set(ROOT_SRC_DIR "${ROOT_SRC_DIR}" CACHE PATH "Path to project src/")

set(CMAKE_C_STANDARD 11)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_compile_options(-Wall -Wextra -Wno-unused-parameter)

get_filename_component(ROOT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/.." ABSOLUTE)
set(CAN_HUB_ROOT_DIR "${ROOT_DIR}")
include(${ROOT_DIR}/cmake/picotls.cmake)
include(${ROOT_DIR}/cmake/monocypher.cmake)

include(FetchContent)
FetchContent_Declare(sqlite3
    URL https://sqlite.org/2026/sqlite-amalgamation-3530200.zip
    URL_HASH SHA256=8a310d0a16c7a90cacd4c884e70faa51c902afed2a89f63aaa0126ab83558a32
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(sqlite3)
add_library(sqlite3 STATIC ${sqlite3_SOURCE_DIR}/sqlite3.c)
target_include_directories(sqlite3 PUBLIC ${sqlite3_SOURCE_DIR})
target_compile_definitions(sqlite3 PRIVATE SQLITE_OMIT_LOAD_EXTENSION SQLITE_THREADSAFE=0)

add_subdirectory(mocks)
add_subdirectory(unit)
