#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <net/if_arp.h>

#include "arp.h"

int parse_arp(uint8_t *buffer, size_t size) {
    if (sizeof(struct arphdr) > size) return -1;

    struct arphdr* arp = (struct arphdr *)buffer;
    (void)arp; // Placeholder

    printf("--- (ARP) ---\n"); // Placeholder
    return 0;
}
