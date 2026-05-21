cmake_minimum_required(VERSION 3.16)
project(iot_mincosig_demo LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_path(SODIUM_INCLUDE_DIR sodium.h)
find_library(SODIUM_LIBRARY NAMES sodium libsodium)

if(NOT SODIUM_INCLUDE_DIR OR NOT SODIUM_LIBRARY)
    message(FATAL_ERROR "libsodium not found. Install libsodium-dev on Ubuntu or libsodium:x64-windows via vcpkg on Windows.")
endif()

add_library(iotproto
    src/common.cpp
    src/mincosig.cpp
    src/net.cpp
    src/protocol.cpp
)
target_include_directories(iotproto PUBLIC include ${SODIUM_INCLUDE_DIR})
target_link_libraries(iotproto PUBLIC ${SODIUM_LIBRARY})

if(WIN32)
    target_link_libraries(iotproto PUBLIC ws2_32)
endif()

foreach(app provision_tool ta_server device_client)
    add_executable(${app} src/${app}.cpp)
    target_link_libraries(${app} PRIVATE iotproto)
endforeach()
