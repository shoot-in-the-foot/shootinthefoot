cmake_minimum_required(VERSION 2.8)

project(SITF)

execute_process(COMMAND git rev-parse HEAD OUTPUT_VARIABLE "GIT_SHA1" OUTPUT_STRIP_TRAILING_WHITESPACE)
set(ENV{GIT_SHA1} ${GIT_SHA1})
message(STATUS "git revision: " ${GIT_SHA1})

add_definitions(-DGIT_REVISION="${GIT_SHA1}")

file(GLOB OSDEP_HDR
    "osdep/*.h"
    "osdep/radiotap/*.h")

file(GLOB OSDEP_SRC
    "osdep/*.c"
    "osdep/radiotap/*.c")

file(GLOB SITF_HDR
    "src/*.h")

file(GLOB SITF_SRC
    "src/*.cpp")

include_directories(SYSTEM "osdep")

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_C_STANDARD 11)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -pedantic")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -Weffc++")

add_library(osdep STATIC ${OSDEP_HDR} ${OSDEP_SRC})
add_executable(${PROJECT_NAME} ${SITF_HDR} ${SITF_SRC})
target_link_libraries(${PROJECT_NAME} osdep)

