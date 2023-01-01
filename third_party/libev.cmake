cmake_minimum_required(VERSION 3.14.0)
include(FetchContent)
FetchContent_Declare(
  libev
  GIT_REPOSITORY https://github.com/mksdev/libev-cmake.git
)

FetchContent_MakeAvailable(libev)
