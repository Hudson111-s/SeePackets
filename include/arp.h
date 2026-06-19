#pragma once

#include <stdint.h>
#include <stddef.h>

#include "utils.h"

int parse_arp(uint8_t *buffer, size_t size, see_config *conf);
