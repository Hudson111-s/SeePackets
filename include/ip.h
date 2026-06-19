#pragma once 

#include <stdint.h>
#include <stddef.h>

#include "utils.h"

int parse_ipv4(uint8_t *buffer, size_t size, see_config *conf);
int parse_ipv6(uint8_t *buffer, size_t size, see_config *conf);
