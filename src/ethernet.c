#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "ethernet.h"
#include "ip.h"
#include "arp.h"

int parse_ethernet(uint8_t *buffer, size_t size) {
    if (sizeof(struct ethhdr) > size) return -1;

    struct ethhdr *eth = (struct ethhdr *)buffer;
    size_t ethhdr_size = sizeof(struct ethhdr);

    size -= ethhdr_size;
    buffer += ethhdr_size;
    
    switch (ntohs(eth->h_proto)) {
        case ETH_P_IP: parse_ipv4(buffer, size); break;
        case ETH_P_IPV6: parse_ipv6(buffer, size); break;
        case ETH_P_ARP: parse_arp(buffer, size); break;
    }

    return 0;
}
