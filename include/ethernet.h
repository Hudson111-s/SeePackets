#pragma once

#include <stdint.h>
#include <stddef.h>

#include "utils.h"

#define ETH_FRAME_SIZE 65536 // Max eth frame size

int parse_ethernet(uint8_t *buffer, size_t size, see_config *conf);
