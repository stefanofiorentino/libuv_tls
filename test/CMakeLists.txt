include_directories(${CMAKE_SOURCE_DIR}/../deps/libuv/include)
add_executable(libuv_tls main.cpp)
target_link_libraries(libuv_tls crypto ssl uv)

add_executable(libuv_echo_server echo-server.cpp)
target_link_libraries(libuv_echo_server uv)