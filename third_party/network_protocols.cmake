cmake_minimum_required(VERSION 3.14.0)
include(FetchContent)
FetchContent_Declare(
  network_protocols
  GIT_REPOSITORY https://github.com/vdm4k/network_protocols
)

FetchContent_MakeAvailable(network_protocols)
