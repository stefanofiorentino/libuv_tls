cmake_minimum_required(VERSION 3.15)
project(libuv_tls C)

set(CMAKE_C_STANDARD 11)

add_executable(libuv_tls main.c)
target_link_libraries(libuv_tls uv ssl crypto)