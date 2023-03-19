cmake_minimum_required(VERSION 3.3.2)
project(ssl_client)

add_executable(${PROJECT_NAME} main.cpp )

find_package(OpenSSL)

#sanitizer
if(NOT DEFINED SANITIZER)
    option(SANITIZER "Enable address sanitizer" OFF)
endif()

if(SANITIZER)
    target_compile_options(${PROJECT_NAME} INTERFACE -fsanitize=address -fPIC)
    target_link_options(${PROJECT_NAME} INTERFACE -fsanitize=address)
endif()

target_link_libraries(${PROJECT_NAME} PUBLIC Threads::Threads network CLI11::CLI11)


