cmake_minimum_required(VERSION 3.10)

project(schc-demo-app C)

include(config.cmake)

set(AHOI_SERIAL_LIB "ahoi-serial-lib::ahoi-serial-lib")
set(ZLOG_LIB "zlog::zlog")
find_package(ahoi-serial-lib REQUIRED)
find_package(zlog REQUIRED)

add_subdirectory(src)