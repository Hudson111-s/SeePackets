#pragma once

#include <stdint.h>

int parse_tcp(uint8_t *buffer, size_t size);
int parse_udp(uint8_t *buffer, size_t size);
int parse_icmp(uint8_t *buffer, size_t size);
