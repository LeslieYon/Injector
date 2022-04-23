cmake_minimum_required(VERSION 3.21)
project(Injector)

set(CMAKE_CXX_STANDARD 14)
add_definitions(-DUNICODE)
add_executable(Injector WIN32 Local.h Local.cpp Remote.h Remote.cpp PETools/PETools.cpp PETools/PETools.h)
