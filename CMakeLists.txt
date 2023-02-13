cmake_minimum_required(VERSION 3.14.0)
project(socket_proxy VERSION 0.0.2 DESCRIPTION "socket proxy library" LANGUAGES CXX)

include("${CMAKE_SOURCE_DIR}/third_party/libev.cmake")

find_package(Threads REQUIRED)
add_subdirectory("third_party/protocols/")

file(GLOB_RECURSE CPP_FILES ${${PROJECT_NAME}_SOURCE_DIR}/source/*.cpp)
file(GLOB_RECURSE H_FILES ${${PROJECT_NAME}_SOURCE_DIR}/include/*.h)

add_library(${PROJECT_NAME} ${CPP_FILES} ${H_FILES})
add_library(jkl::${PROJECT_NAME} ALIAS ${PROJECT_NAME})
add_library(socket_proxy::${PROJECT_NAME} ALIAS ${PROJECT_NAME})


target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_compile_options(${PROJECT_NAME} PRIVATE  -Wall -Wextra -Wpedantic  -Wno-vla -Wno-unused-local-typedefs)

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>)

#sanitizer
if(ASAN)
  list(APPEND uv_defines __ASAN__=1)
  if(CMAKE_C_COMPILER_ID MATCHES "AppleClang|GNU|Clang")
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fno-omit-frame-pointer -fsanitize=address")
    set (CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=address")
    set (CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -fno-omit-frame-pointer -fsanitize=address")
  elseif(MSVC)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} /fsanitize=address")
  else()
    message(SEND_ERROR "AddressSanitizer support requires clang, gcc, or msvc. Try again with -DCMAKE_C_COMPILER.")
  endif()
endif()

#app
option(WITH_APP "Build application" OFF)
if(WITH_APP)
    add_subdirectory(app)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC jkl::protocols Threads::Threads ev::ev)

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/cmake/utils.cmake")
    include("${CMAKE_CURRENT_LIST_DIR}/cmake/utils.cmake")
    package_create()
endif()
