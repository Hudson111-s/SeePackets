#include <stdio.h>
#include <stdint.h>
#include <linux/ip.h>
#include <arpa/inet.h>

#include "ip.h"
#include "transport.h"

int parse_ipv4(uint8_t *buffer, size_t size) {
    if (sizeof(struct iphdr) > size) return -1;

    struct iphdr *ip = (struct iphdr *)buffer;
    size_t iphdr_size = ip->ihl * 4;
    if (iphdr_size > size) return -1;

    size -= iphdr_size;
    buffer += iphdr_size;

    switch (ip->protocol) {
        case IPPROTO_TCP: parse_tcp(buffer, size); break;
        case IPPROTO_UDP: parse_udp(buffer, size); break;
        case IPPROTO_ICMP: parse_icmp(buffer, size); break;
    }

    return 0;
}

int parse_ipv6(uint8_t *buffer, size_t size) {
    printf("This is ipv6\n"); // Placeholder
    return 0;
}