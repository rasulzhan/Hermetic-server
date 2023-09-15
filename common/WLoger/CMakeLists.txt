cmake_minimum_required(VERSION 3.0.0)

project(Wloger VERSION 0.1.0)

set(CMAKE_BUILD_TYPE Release)

set(CMAKE_CXX_FLAGS_RELEASE "-O2")

set(SRC
	Source/Wloger.cpp 
	Include/WLoger.h
)

message("CMAKE_BINARY_DIR : " ${CMAKE_BINARY_DIR})

set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY $<1:${CMAKE_SOURCE_DIR}/build>)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY $<1:${CMAKE_SOURCE_DIR}/build>)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY $<1:${CMAKE_SOURCE_DIR}/build>)


set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})

add_library(Wloger SHARED ${SRC} )
add_library(libWloger STATIC ${SRC} )


add_executable(test ${SRC} "test//test.cpp")

