# CMakeList.txt : CMake project for crypt, include source and define
# project specific logic here.
#
cmake_minimum_required (VERSION 3.8)

SET (SRC_LIST crypt.cpp des.c getopt.c md5.c)

# Add source to this project's executable.
add_executable (crypt ${SRC_LIST})

# TODO: Add tests and install targets if needed.
