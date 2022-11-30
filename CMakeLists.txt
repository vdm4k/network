cmake_minimum_required(VERSION 3.1.0)
project(socket_proxy VERSION 0.0.2 DESCRIPTION "socket proxy library" LANGUAGES CXX)

if(UNIX AND NOT APPLE)
    set(COMMON_OS_SPECIFIC_OPTIONS "-g3;-ggdb3")
endif()

set(COMMON_OPTIONS ${COMMON_OS_SPECIFIC_OPTIONS})
set(DEBUG_OPTIONS "${COMMON_OPTIONS}")
set(RELEASE_OPTIONS "-DNDEBUG;${COMMON_OPTIONS}")


find_package(Threads REQUIRED)
add_subdirectory("third_party/protocols/")

file(GLOB_RECURSE CPP_FILES ${${PROJECT_NAME}_SOURCE_DIR}/source/*.cpp)
file(GLOB_RECURSE H_FILES ${${PROJECT_NAME}_SOURCE_DIR}/include/*.h)

add_library(${PROJECT_NAME} STATIC ${CPP_FILES} ${H_FILES})
add_library(jkl::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_link_libraries(${PROJECT_NAME} PUBLIC jkl::protocols)

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_compile_options(${PROJECT_NAME} PRIVATE "-Wall;-Wextra"
    PUBLIC "$<$<CONFIG:DEBUG>:${DEBUG_OPTIONS}>"
    PUBLIC "$<$<CONFIG:RELEASE>:${RELEASE_OPTIONS}>")

target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>)

#sanitizer
if(NOT DEFINED SANITIZER)
    option(SANITIZER "Sanitizer" OFF)
endif()

if(SANITIZER)
    target_compile_options(${PROJECT_NAME}
        PRIVATE $<$<CONFIG:Debug>:-fsanitize=address>
        PRIVATE $<$<CONFIG:Release>:-fsanitize=address>
        PRIVATE $<$<CONFIG:ReleaseWithDebugInfo>:-fsanitize=address>)
endif()

#test
option(WITH_TESTS "Build tests" OFF)
if(WITH_TESTS)
    add_subdirectory(test)
endif()

#app
option(WITH_APP "Build application" OFF)
if(WITH_APP)
    add_subdirectory(app)
endif()

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/cmake/utils.cmake")
    include("${CMAKE_CURRENT_LIST_DIR}/cmake/utils.cmake")
    package_create()
endif()
