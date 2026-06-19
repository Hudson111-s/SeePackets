#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/if_ether.h>

#include "arp.h"
#include "utils.h"

int parse_arp(uint8_t *buffer, size_t size, see_config *conf) {
    if (sizeof(struct ether_arp) > size) return -1;

    struct ether_arp* arp = (struct ether_arp *)buffer;

    if (conf->addr_set) {
        if (memcmp(arp->arp_spa, &conf->addr, sizeof(struct in_addr)) != 0 &&
        memcmp(arp->arp_tpa, &conf->addr, sizeof(struct in_addr)) != 0) {
            return 0;
        }
    }

    print_ether_arp(arp, conf);
    return 0;
}
