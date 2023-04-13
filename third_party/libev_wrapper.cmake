cmake_minimum_required(VERSION 3.14.0)
include(FetchContent)
FetchContent_Declare(
  libev_wrapper
  GIT_REPOSITORY https://github.com/vdm4k/libev_wrapper
)

FetchContent_MakeAvailable(libev_wrapper)
