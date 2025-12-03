cmake_minimum_required(VERSION 3.10)

project(schc-demo-app C)

set(AHOI_SERIAL_LIB "ahoi-serial-lib::ahoi-serial-lib")
find_package(ahoi-serial-lib REQUIRED)

add_subdirectory(src)