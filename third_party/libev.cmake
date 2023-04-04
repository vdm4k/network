cmake_minimum_required(VERSION 3.14.0)
include(FetchContent)
FetchContent_Declare(
  libev
  GIT_REPOSITORY https://github.com/vdm4k/libev-cmake
)

FetchContent_MakeAvailable(libev)
