cmake_minimum_required(VERSION 3.14.0)
project(network VERSION 0.9.0 DESCRIPTION "network library")

# core h files
set(H_FILES
    include/stream/stream.h
    include/stream/factory.h
    include/stream/settings.h
    include/stream/statistic.h
    include/network/stream/stream.h
    include/network/stream/factory.h
    include/network/stream/settings.h
    include/network/stream/send/settings.h
    include/network/stream/send/statistic.h
    include/network/stream/send/stream.h
    include/network/stream/listen/settings.h
    include/network/stream/listen/statistic.h
    include/network/stream/listen/stream.h

    include/network/tcp/listen/settings.h
    include/network/tcp/listen/statistic.h
    include/network/tcp/listen/stream.h
    include/network/tcp/send/settings.h
    include/network/tcp/send/statistic.h
    include/network/tcp/send/stream.h    
    include/network/udp/send/settings.h
    include/network/udp/send/statistic.h
    include/network/udp/send/stream.h
    include/network/common/buffer.h
    include/network/platforms/system.h
)

# core cpp files
set(CPP_FILES
    source/network/tcp/listen/stream.cpp
    source/network/tcp/send/stream.cpp
    source/network/udp/send/stream.cpp
    source/network/stream/send/stream.cpp
    source/network/stream/listen/stream.cpp
    source/network/stream/factory.cpp
    source/network/stream/stream.cpp
    source/network/platforms/system.cpp
)

if(WITH_SCTP_SSL OR WITH_TCP_SSL OR WITH_DTLS)
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
    set(H_FILES ${H_FILES}
        include/network/common/ssl.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/common/ssl.cpp
    )

endif() # WITH_SCTP_SSL OR WITH_TCP_SSL OR WITH_DTLS

option(WITH_TCP_SSL       "Builds with tcp-ssl" OFF)
if(WITH_TCP_SSL)
    add_definitions(-DWITH_TCP_SSL)

    set(H_FILES ${H_FILES}
        include/network/tcp/ssl/listen/settings.h
        include/network/tcp/ssl/listen/statistic.h
        include/network/tcp/ssl/listen/stream.h
        include/network/tcp/ssl/send/settings.h
        include/network/tcp/ssl/send/statistic.h
        include/network/tcp/ssl/send/stream.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/tcp/ssl/listen/stream.cpp
        source/network/tcp/ssl/send/stream.cpp
    )
endif() #WITH_TCP_SSL

option(WITH_UDP_SSL       "Builds with udp-ssl" OFF)
if(WITH_UDP_SSL)
    add_definitions(-DWITH_UDP_SSL)

    include(CheckSymbolExists)
    # Check for macro SEEK_SET
    list(APPEND CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
    check_symbol_exists(BIO_new_dgram "openssl/bio.h" HAVE_SUPPORT_FROM_OPENSSL_LIBRARY)
    if(NOT HAVE_SUPPORT_FROM_OPENSSL_LIBRARY)
        message(FATAL_ERROR "Can't find BIO_new_dgram needed for dtls.
                             Probably cmake can't find right version or you
                             need to build openssl with DTLS support")
    endif()

    set(H_FILES ${H_FILES}
        include/network/udp/ssl/listen/settings.h
        include/network/udp/ssl/listen/statistic.h
        include/network/udp/ssl/listen/stream.h
        include/network/udp/ssl/send/settings.h
        include/network/udp/ssl/send/statistic.h
        include/network/udp/ssl/send/stream.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/udp/ssl/listen/stream.cpp
        source/network/udp/ssl/send/stream.cpp
    )
endif() #WITH_UDP_SSL

option(WITH_SCTP       "Builds with sctp" OFF)
if(WITH_SCTP)

    add_definitions(-DWITH_SCTP)

    list(APPEND CMAKE_REQUIRED_LIBRARIES sctp)
    include(CheckSymbolExists)
    check_symbol_exists(sctp_send "netinet/sctp.h" HAVE_SCTP_LIBRARY)
    if(NOT HAVE_SCTP_LIBRARY)
        message(FATAL_ERROR "You need to install libsctp")
    endif()

    add_definitions(-DWITH_SCTP)
    set(H_FILES ${H_FILES}
        include/network/sctp/settings.h
        include/network/sctp/listen/settings.h
        include/network/sctp/listen/statistic.h
        include/network/sctp/listen/stream.h
        include/network/sctp/send/settings.h
        include/network/sctp/send/statistic.h
        include/network/sctp/send/stream.h
    )

    set(CPP_FILES ${CPP_FILES}
        source/network/sctp/listen/stream.cpp
        source/network/sctp/send/stream.cpp
    )

    set(ADDITIONAL_DEPS
        ${ADDITIONAL_DEPS}
        sctp
    )

endif() #SCTP

option(WITH_SCTP_SSL       "Builds with sctp-ssl" OFF)
if(WITH_SCTP_SSL)
    add_definitions(-DWITH_SCTP_SSL)

    include(CheckSymbolExists)
    # Check for macro SEEK_SET
    list(APPEND CMAKE_REQUIRED_LIBRARIES OpenSSL::SSL OpenSSL::Crypto)
    check_symbol_exists(BIO_new_dgram_sctp "openssl/bio.h" HAVE_SUPPORT_FROM_OPENSSL_LIBRARY)
    if(NOT HAVE_SUPPORT_FROM_OPENSSL_LIBRARY)
        message(FATAL_ERROR "Can't find BIO_new_dgram_sctp needed for sctp-dtls.
                             Probably cmake can't find right version or you
                             need to build openssl with DTLS/SCTP support.
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

include("${PROJECT_SOURCE_DIR}/third_party/libev_wrapper.cmake")
include("${PROJECT_SOURCE_DIR}/third_party/network_protocols.cmake")
find_package(Threads REQUIRED)

add_library(${PROJECT_NAME} ${CPP_FILES} ${H_FILES})
add_library(bro::${PROJECT_NAME} ALIAS ${PROJECT_NAME})

target_compile_features(${PROJECT_NAME} PUBLIC cxx_std_17)
target_compile_options(${PROJECT_NAME} PRIVATE -Wall -Wextra -Wpedantic -Wno-vla -Wno-unused-local-typedefs -fPIC)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# TODO: maybe we need to add only not secure (without SSL)
target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC
    $<BUILD_INTERFACE:${${PROJECT_NAME}_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include/${PROJECT_NAME}>)

#sanitizer
option(WITH_SANITIZER "Enable address sanitizer" OFF)

if(WITH_SANITIZER)
    target_compile_options(${PROJECT_NAME} INTERFACE -fsanitize=address -fPIC)
    target_link_options(${PROJECT_NAME} INTERFACE -fsanitize=address)
endif()

#examples
option(WITH_EXAMPLES "Build examples" OFF)
if(WITH_EXAMPLES)
    add_subdirectory(examples)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC bro::network_protocols Threads::Threads bro::libev_wrapper ${ADDITIONAL_DEPS} )
