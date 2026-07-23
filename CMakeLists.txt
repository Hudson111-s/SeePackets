cmake_minimum_required(VERSION 3.15)
project(SeePackets 
    VERSION 1.0.0
    DESCRIPTION "Packet sniffer in C"
    LANGUAGES C
)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

add_executable(SeePackets 
    main.c
    src/utils.c
    src/ip.c
    src/arp.c
    src/ethernet.c
    src/transport.c
)

target_compile_definitions(SeePackets PRIVATE 
    _GNU_SOURCE
)

target_compile_options(SeePackets PRIVATE
    -Wall
    -Wextra
    -Werror
)

target_include_directories(SeePackets PRIVATE
    include
)
