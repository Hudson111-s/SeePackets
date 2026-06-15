#pragma once 

#include <stdint.h>
#include <stddef.h>

int parse_ipv4(uint8_t *buffer, size_t size);
int parse_ipv6(uint8_t *buffer, size_t size);
