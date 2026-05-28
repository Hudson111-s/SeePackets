#include <stdio.h>
#include <stdint.h>
#include <linux/if_arp.h>

#include "arp.h"

int parse_arp(uint8_t *buffer, size_t size) {
    if (sizeof(struct arphdr) > size) return -1;

    struct arphdr*arp = (struct arphdr *)buffer;

    printf("--- (ARP) ---\n");
    return 0;
}
