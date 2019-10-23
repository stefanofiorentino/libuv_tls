cmake_minimum_required(VERSION 3.2)

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_BINARY_DIR)
    message(FATAL_ERROR "Prevented in-tree built. Please create a build directory outside of the source code and call cmake from there. Thank you.")
endif()

project(libuv_tls VERSION 1.28.0)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(PROJECT_AUTHOR "Stefano Fiorentino")
set(PROJECT_AUTHOR_EMAIL "stefano.fiore84@gmail.com")

message("*")
message("* ${PROJECT_NAME} v${PROJECT_VERSION} (${CMAKE_BUILD_TYPE})")
message("* Copyright (c) 2019 ${PROJECT_AUTHOR} <${PROJECT_AUTHOR_EMAIL}>")
message("*")

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT MSVC)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -DDEBUG")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Os -DRELEASE")
endif()

set(PROJECT_CMAKE_IN ${libuv_tls_SOURCE_DIR}/cmake/in)
set(PROJECT_DEPS_DIR ${libuv_tls_SOURCE_DIR}/deps)
set(PROJECT_SRC_DIR ${libuv_tls_SOURCE_DIR})

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY bin)

set(THREADS_PREFER_PTHREAD_FLAG ON)

include(FindThreads)

if(BUILD_TESTING)
    set(BUILD_TESTING OFF)

    set(GOOGLETEST_DEPS_DIR ${PROJECT_DEPS_DIR}/googletest)
    set(LIBUV_DEPS_DIR ${PROJECT_DEPS_DIR}/libuv)

    configure_file(${PROJECT_CMAKE_IN}/deps.in ${PROJECT_DEPS_DIR}/CMakeLists.txt)
    execute_process(COMMAND ${CMAKE_COMMAND} -G "${CMAKE_GENERATOR}" . WORKING_DIRECTORY ${PROJECT_DEPS_DIR})
    execute_process(COMMAND ${CMAKE_COMMAND} --build . WORKING_DIRECTORY ${PROJECT_DEPS_DIR})

    # gtest, gtest_main, gmock and gmock_main targets are available from now on
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    add_subdirectory(${GOOGLETEST_DEPS_DIR})

    # uv and uv_a targets are available from now on
    add_subdirectory(${LIBUV_DEPS_DIR})
    include_directories(${LIBUV_DEPS_DIR}/include)

    set(BUILD_TESTING ON)
    enable_testing()

    add_subdirectory(test)
endif()
