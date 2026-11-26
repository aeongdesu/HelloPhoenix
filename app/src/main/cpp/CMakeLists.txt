cmake_minimum_required(VERSION 3.22.1)
project(hellophoenix LANGUAGES CXX)

add_library(hellophoenix SHARED phoenix_native.cpp)

target_compile_options(hellophoenix PRIVATE
    -std=c++20
    -O2
    -ffunction-sections
    -fdata-sections
    -fvisibility=hidden
    -fno-exceptions
    -fno-rtti
    -Wall
    -Wextra
)

target_link_options(hellophoenix PRIVATE
    -Wl,--gc-sections
    -Wl,-z,max-page-size=16384
)

find_library(LOG_LIB log)
target_link_libraries(hellophoenix PRIVATE ${LOG_LIB})
