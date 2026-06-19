#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "ethernet.h"
#include "ip.h"
#include "arp.h"
#include "utils.h"

int parse_ethernet(uint8_t *buffer, size_t size, see_config *conf) {
    if (sizeof(struct ethhdr) > size) return -1;

    struct ethhdr *eth = (struct ethhdr *)buffer;
    size_t ethhdr_size = sizeof(struct ethhdr);

    size -= ethhdr_size;
    buffer += ethhdr_size;
    
    switch (ntohs(eth->h_proto)) {
        case ETH_P_IP: 
            if (conf->ip_mode == IPMODE_V6_ONLY) {
                return 0;
            }

            parse_ipv4(buffer, size, conf); 
            break;
        case ETH_P_IPV6:
            if (conf->ip_mode == IPMODE_V4_ONLY) {
                return 0;
            }

            parse_ipv6(buffer, size, conf); 
            break;
        case ETH_P_ARP:
            if (!(conf->proto_mask & PROTO_ARP) || conf->ip_mode == IPMODE_V6_ONLY) {
                return 0;
            }

            parse_arp(buffer, size, conf); 
            break;
    }

    return 0;
}
