#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/if_ether.h>

#include "arp.h"

int parse_arp(uint8_t *buffer, size_t size) {
    if (sizeof(struct ether_arp) > size) return -1;

    struct ether_arp* arp = (struct ether_arp *)buffer;
    (void)arp; // Placeholder

    printf("--- (ARP) ---\n"); // Placeholder
    return 0;
}
