cmake_minimum_required(VERSION 3.14.0)
project(network VERSION 0.0.2 DESCRIPTION "network library")

# core cpp files
set(H_FILES
    include/stream/stream.h
    include/stream/factory.h
    include/stream/settings.h
    include/stream/statistic.h
    include/network/libev/libev.h
    include/network/stream.h
    include/network/stream_factory.h
    include/network/common.h
    include/network/settings.h
    include/network/tcp/stream.h
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
    source/network/stream.cpp
    source/network/common.cpp
)

# SSL
if(WITH_SCTP_SSL OR WITH_SSL)
    if(OPENSSL_DIR)
         set(OPENSSL_ROOT_DIR ${OPENSSL_DIR})
         set(OPENSSL_INCLUDE_DIR ${OPENSSL_ROOT_DIR}/include)
         set(OPENSSL_LIB_DIR "${OPENSSL_ROOT_DIR}/lib64")
         set(OPENSSL_CRYPTO_LIBRARY "${OPENSSL_LIB_DIR}/libcrypto.so")
         set(OPENSSL_SSL_LIBRARY "${OPENSSL_LIB_DIR}/libssl.so")
    endif()

    find_package(OpenSSL REQUIRED)

    set(ADDITIONAL_DEPS
        ${ADDITIONAL_DEPS}
        OpenSSL::SSL
        OpenSSL::Crypto
    )
endif() # WITH_SCTP_SSL OR WITH_SSL

# SSL
option(WITH_SSL       "Builds with ssl" OFF)
if(WITH_SSL)
    add_definitions(-DWITH_SSL)    

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
endif() #WITH_SSL


# SCTP
option(WITH_SCTP       "Builds with ssl" OFF)
if(WITH_SCTP)

    add_definitions(-DWITH_SCTP)

    #TODO: need to fix it ( maybe )
    include(CheckIncludeFile)
    CHECK_INCLUDE_FILE(netinet/sctp.h  HAVE_NETINET_SCTP_H)
    if(NOT HAVE_NETINET_SCTP_H)
        message(FATAL_ERROR "please install libsctp-dev library to build with sctp support")
    endif()

    add_definitions(-DWITH_SCTP)
    set(H_FILES ${H_FILES}
        include/network/sctp/settings.h
        include/network/sctp/stream.h
        include/network/sctp/listen/settings.h
        include/network/sctp/listen/statistic.h
        include/network/sctp/listen/stream.h
        include/network/sctp/send/settings.h
        include/network/sctp/send/statistic.h
        include/network/sctp/send/stream.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/sctp/stream.cpp
        source/network/sctp/listen/stream.cpp
        source/network/sctp/send/stream.cpp
    )

    set(ADDITIONAL_DEPS
        ${ADDITIONAL_DEPS}
        sctp
    )

endif() #SCTP

# WITH_SCTP_SSL
option(WITH_SCTP_SSL       "Builds with ssl" OFF)
if(WITH_SCTP_SSL)
    add_definitions(-DWITH_SCTP_SSL)

    include(CheckSymbolExists)
    # Check for macro SEEK_SET
    list(APPEND CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
    check_symbol_exists(BIO_new_dgram_sctp "openssl/bio.h" HAVE_SUPPORT_FROM_OPENSSL_LIBRARY)
    if(NOT HAVE_SUPPORT_FROM_OPENSSL_LIBRARY)
        message(STATUS "Can't find BIO_new_dgram_sctp needed for sctp-dtls.
                        Probably cmake can't find right version or you
                        need build openssl with SCTP support.
                        You can do something like that -
                        git clone git://git.openssl.org/openssl.git
                        ./config sctp --prefix=$HOME/my-openssl/ && make -j8 && make -j8 install")
    endif()

    message(STATUS "don't forget to enable sudo sysctl -w net.sctp.auth_enable=1")

    set(H_FILES ${H_FILES}
        include/network/sctp/ssl/listen/settings.h
        include/network/sctp/ssl/listen/statistic.h
        include/network/sctp/ssl/listen/stream.h
        include/network/sctp/ssl/send/settings.h
        include/network/sctp/ssl/send/statistic.h
        include/network/sctp/ssl/send/stream.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/sctp/ssl/listen/stream.cpp
        source/network/sctp/ssl/send/stream.cpp
    )

endif() # WITH_SCTP_SSL

include("${CMAKE_SOURCE_DIR}/third_party/libev.cmake")
find_package(Threads REQUIRED)
add_subdirectory("third_party/protocols/")

add_library(${PROJECT_NAME} ${CPP_FILES} ${H_FILES})
add_library(bro::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_compile_options(${PROJECT_NAME} PRIVATE  -Wall -Wextra -Wpedantic -Wno-vla -Wno-unused-local-typedefs)

# TODO: maybe we need to add only not secure (without SSL)
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC
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
