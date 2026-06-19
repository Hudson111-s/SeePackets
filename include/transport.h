#pragma once

#include <stdint.h>
#include <stddef.h>

#include "utils.h"

int parse_tcp(uint8_t *buffer, size_t size, see_config *conf);
int parse_udp(uint8_t *buffer, size_t size, see_config *conf);
int parse_icmp(uint8_t *buffer, size_t size, see_config *conf);
int parse_icmp6(uint8_t *buffer, size_t size, see_config *conf);
