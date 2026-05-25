cmake_minimum_required(VERSION 3.15)
project(SeePackets C)

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

target_include_directories(SeePackets PRIVATE
    include
)
