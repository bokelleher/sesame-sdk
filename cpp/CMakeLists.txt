cmake_minimum_required(VERSION 3.16)
project(sesame_cpp LANGUAGES CXX VERSION 0.1.0)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)  # POSIX strptime/timegm
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

find_package(OpenSSL REQUIRED)

add_library(sesame
  src/crypto_openssl.cpp
  src/tier1.cpp
  src/tier3.cpp
  src/message.cpp
  src/protocol.cpp
)
add_library(sesame::sesame ALIAS sesame)
target_include_directories(sesame PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>)
target_link_libraries(sesame PUBLIC OpenSSL::Crypto)
# Strict on our own code (the vendored test-only json header is not built here).
target_compile_options(sesame PRIVATE -Wall -Wextra -Wpedantic -Werror)

option(SESAME_BUILD_TESTS "Build tests" ON)
option(SESAME_BUILD_EXAMPLES "Build examples" ON)

set(SESAME_VECTORS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../test-vectors"
    CACHE PATH "Directory holding the golden conformance vectors")

if(SESAME_BUILD_TESTS)
  enable_testing()
  foreach(t conformance unit)
    add_executable(${t} tests/${t}.cpp)
    target_include_directories(${t} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/third_party)
    target_link_libraries(${t} PRIVATE sesame OpenSSL::Crypto)
    target_compile_options(${t} PRIVATE -Wall -Wextra)
    target_compile_definitions(${t} PRIVATE SESAME_VECTORS_DIR="${SESAME_VECTORS_DIR}")
    add_test(NAME ${t} COMMAND ${t})
  endforeach()
endif()

if(SESAME_BUILD_EXAMPLES)
  add_executable(sign_request examples/sign_request.cpp)
  target_link_libraries(sign_request PRIVATE sesame OpenSSL::Crypto)
  target_compile_options(sign_request PRIVATE -Wall -Wextra)
endif()
