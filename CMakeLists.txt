cmake_minimum_required(VERSION 2.8.0)
project(mumlib)

if (MSYS)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -DLOG4CPP_FIX_ERROR_COLLISION=1 -D__USE_W32_SOCKETS")
  add_definitions(-DOPT_TLS_OPENSSL)
elseif (NOT APPLE)
  add_definitions(-DOPT_TLS_OPENSSL -D_POSIX_C_SOURCE=200112L)
elseif()
  LINK_DIRECTORIES(/opt/local/lib) # Include the default MacPorts library directory
endif()

INCLUDE(FindPkgConfig)
find_package(PkgConfig REQUIRED)
#find_package(Boost COMPONENTS system REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(Protobuf REQUIRED)

pkg_check_modules(LOG4CPP "log4cpp")
pkg_check_modules(OPUS "opus")

#INCLUDE_DIRECTORIES(${Boost_INCLUDE_DIR})

include_directories(${OPENSSL_INCLUDE_DIR})
include_directories(${PROTOBUF_INCLUDE_DIRS})
include_directories(${OPUS_INCLUDE_DIRS})
include_directories(~/boost_1_72_0)
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

set(SPEEX_LIBRARIES
        speexdsp
        )

PROTOBUF_GENERATE_CPP(PROTO_SRCS PROTO_HDRS Mumble.proto)

add_library(mumlib STATIC ${MUMLIB_SRC} ${MUMLIB_PUBLIC_HEADERS} ${MUMLIB_PRIVATE_HEADERS} ${PROTO_SRCS} ${PROTO_HDRS})

if (MSYS)
target_link_libraries(mumlib
        ${SPEEX_LIBRARIES}
        ${PROTOBUF_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${LOG4CPP_LIBRARIES}
        ${OPUS_LIBRARIES} ws2_32)
else ()
target_link_libraries(mumlib
        ${SPEEX_LIBRARIES}
        ${PROTOBUF_LIBRARIES}
        ${OPENSSL_LIBRARIES}
        ${LOG4CPP_LIBRARIES}
        ${OPUS_LIBRARIES})
endif ()

set_target_properties(mumlib PROPERTIES PUBLIC_HEADER "${MUMLIB_PUBLIC_HEADERS}")

add_executable(mumlib_example mumlib_example.cpp)

if (MSYS)
target_link_libraries(mumlib_example mumlib ws2_32)
else ()
target_link_libraries(mumlib_example mumlib)
endif ()

install(TARGETS DESTINATION mumlib LIBRARY DESTINATION lib PUBLIC_HEADER DESTINATION include/mumlib)
