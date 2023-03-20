cmake_minimum_required(VERSION 3.14.0)
project(network VERSION 0.0.2 DESCRIPTION "network library")

# core cpp files
set(H_FILES
    include/stream/stream.h
    include/stream/factory.h
    include/stream/settings.h
    include/stream/statistic.h
    include/network/libev/libev.h
    include/network/stream_factory.h
    include/network/tcp/settings.h
    include/network/tcp/stream.h
    include/network/tcp/listen
    include/network/tcp/listen/settings.h
    include/network/tcp/listen/statistic.h
    include/network/tcp/listen/stream.h
    include/network/tcp/send/settings.h
    include/network/tcp/send/statistic.h
    include/network/tcp/send/stream.h
)

# core cpp files
set(CPP_FILES
    source/network/libev/libev.cpp
    source/network/tcp/stream.cpp
    source/network/tcp/listen/stream.cpp
    source/network/tcp/send/stream.cpp
    source/network/stream_factory.cpp
)


# SSL
option(WITH_SCTP       "Builds with ssl" OFF)
if(WITH_SCTP)

    #TODO: need to fix it ( maybe )
    include(CheckIncludeFile)
    set (CMAKE_REQUIRED_INCLUDES "/usr/include")
    CHECK_INCLUDE_FILE(linux/sctp.h  HAVE_NETINET_SCTP_H)

    add_definitions(-DWITH_SCTP)
    set(H_FILES ${H_FILES}
        include/network/sctp/settings.h
        include/network/sctp/stream.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/sctp/stream.cpp
    )

endif()

# SSL
option(WITH_SSL       "Builds with ssl" OFF)
if(WITH_SSL)
    add_definitions(-DWITH_SSL)
    find_package(OpenSSL REQUIRED)

    set(H_FILES ${H_FILES}
        include/network/tcp/ssl/listen/settings.h
        include/network/tcp/ssl/listen/statistic.h
        include/network/tcp/ssl/listen/stream.h
        include/network/tcp/ssl/send/settings.h
        include/network/tcp/ssl/send/statistic.h
        include/network/tcp/ssl/send/stream.h
        include/network/tcp/ssl/common.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/tcp/ssl/listen/stream.cpp
        source/network/tcp/ssl/send/stream.cpp
        source/network/tcp/ssl/common.cpp
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
    option(WITH_SANITIZER "Enable address sanitizer" OFF)
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
