cmake_minimum_required(VERSION 3.1.1)
project(libmumble)

list(APPEND CMAKE_C_FLAGS " -std=c99 -g -Wall -pedantic ${CMAKE_C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
add_definitions(-DOPT_TLS_GNUTLS -D_POSIX_C_SOURCE=200112L)

INCLUDE(FindPkgConfig)
find_package(PkgConfig REQUIRED)
find_package(Boost COMPONENTS system unit_test_framework program_options filesystem REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Protobuf REQUIRED)

pkg_check_modules(LOG4CPP "log4cpp")
pkg_check_modules(OPUS "opus")


INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})
include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${PROTOBUF_INCLUDE_DIRS})
include_directories(${OPUS_INCLUDE_DIRS})

include_directories(${CMAKE_CURRENT_BINARY_DIR})
include_directories(${LOG4CPP_INCLUDE_DIRS})
include_directories(include)

set(MUMLIB_PUBLIC_HEADERS include/mumlib.hpp include/mumlib/VarInt.hpp)

set(MUMLIB_PRIVATE_HEADERS
        include/mumlib/Callback.hpp
        include/mumlib/CryptState.hpp
        include/mumlib/Transport.hpp
        include/mumlib/Audio.hpp
        include/mumlib/enums.hpp
)

set(MUMLIB_SRC
        src/mumlib.cpp
        src/Callback.cpp
        src/CryptState.cpp
        src/VarInt.cpp
        src/Transport.cpp
        src/Audio.cpp
)

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS Mumble.proto)

add_library(mumlib SHARED ${MUMLIB_SRC} ${MUMLIB_PUBLIC_HEADERS} ${MUMLIB_PRIVATE_HEADERS} ${PROTO_SRCS} ${PROTO_HDRS})
target_link_libraries(mumlib ${PROTOBUF_LIBRARIES})
target_link_libraries(mumlib ${Boost_LIBRARIES})
target_link_libraries(mumlib ${OPENSSL_LIBRARIES})
target_link_libraries(mumlib ${LOG4CPP_LIBRARIES})
target_link_libraries(mumlib ${OPUS_LIBRARIES})


add_executable(mumlib_example mumlib_example.cpp)
target_link_libraries(mumlib_example mumlib)
