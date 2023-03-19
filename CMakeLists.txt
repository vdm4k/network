cmake_minimum_required(VERSION 3.14.0)
project(network VERSION 0.0.2 DESCRIPTION "network library" LANGUAGES CXX)

# core cpp files
set(H_FILES
    include/network/stream_settings.h
    include/network/libev/libev.h
    include/network/stream_factory.h
    include/network/stream.h
    include/network/linux/stream_factory.h
    include/network/linux/tcp/settings.h
    include/network/linux/tcp/stream.h
    include/network/linux/tcp/listen
    include/network/linux/tcp/listen/settings.h
    include/network/linux/tcp/listen/statistic.h
    include/network/linux/tcp/listen/stream.h
    include/network/linux/tcp/send/settings.h
    include/network/linux/tcp/send/statistic.h
    include/network/linux/tcp/send/stream.h
    include/network/stream_statistic.h
)

# core cpp files
set(CPP_FILES
    source/network/libev/libev.cpp
    source/network/linux/tcp/stream.cpp
    source/network/linux/tcp/listen/stream.cpp
    source/network/linux/tcp/send/stream.cpp
    source/network/linux/stream_factory.cpp
)

# SSL
option(WITH_SSL       "Builds with ssl" OFF)
if(WITH_SSL)
    add_definitions(-DWITH_SSL)
    find_package(OpenSSL REQUIRED)

    set(H_FILES ${H_FILES}
        include/network/linux/ssl/listen/settings.h
        include/network/linux/ssl/listen/statistic.h
        include/network/linux/ssl/listen/stream.h
        include/network/linux/ssl/send/settings.h
        include/network/linux/ssl/send/statistic.h
        include/network/linux/ssl/send/stream.h
        include/network/linux/ssl/common.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/linux/ssl/listen/stream.cpp
        source/network/linux/ssl/send/stream.cpp
        source/network/linux/ssl/common.cpp
    )

    set(ADDITIONAL_DEPS
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif()


include("${CMAKE_SOURCE_DIR}/third_party/libev.cmake")
find_package(Threads REQUIRED)
add_subdirectory("third_party/protocols/")

add_library(${PROJECT_NAME} ${CPP_FILES} ${H_FILES})
add_library(bro::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_compile_options(${PROJECT_NAME} PRIVATE  -Wall -Wextra -Wpedantic -Wno-vla -Wno-unused-local-typedefs)

# TODO: maybe we need to add only not secure (without SSL)
target_include_directories(${PROJECT_NAME} PUBLIC
    $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>)

#sanitizer
if(NOT DEFINED WITH_SANITIZER)
    option(SANITIZER "Enable address sanitizer" OFF)
endif()

if(WITH_SANITIZER)
    target_compile_options(${PROJECT_NAME} INTERFACE -fsanitize=address -fPIC)
    target_link_options(${PROJECT_NAME} INTERFACE -fsanitize=address)
endif()

#app
option(WITH_APP "Build application" OFF)
if(WITH_APP)
    add_subdirectory(app)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC network_protocols Threads::Threads ev::ev ${ADDITIONAL_DEPS})

if(EXISTS "${CMAKE_CURRENT_LIST_DIR}/cmake/utils.cmake")
    include("${CMAKE_CURRENT_LIST_DIR}/cmake/utils.cmake")
    package_create()
endif()
