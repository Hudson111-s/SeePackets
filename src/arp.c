#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/if_ether.h>

#include "arp.h"
#include "utils.h"

int parse_arp(uint8_t *buffer, size_t size) {
    if (sizeof(struct ether_arp) > size) return -1;

    struct ether_arp* arp = (struct ether_arp *)buffer;

    print_ether_arp(arp);
    return 0;
}
