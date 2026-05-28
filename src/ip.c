#include <stdio.h>
#include <stdint.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <arpa/inet.h>

#include "ip.h"
#include "transport.h"

int parse_ipv4(uint8_t *buffer, size_t size) {
    if (sizeof(struct iphdr) > size) return -1;

    struct iphdr *ip = (struct iphdr *)buffer;
    size_t iphdr_size = ip->ihl * 4;
    uint16_t total_len = ntohs(ip->tot_len);
    if (iphdr_size > size) return -1;
    if (total_len < iphdr_size || total_len > size) return -1;

    size = total_len - iphdr_size;
    buffer += iphdr_size;

    printf("--- (IPv4) ---\n");
    switch (ip->protocol) {
        case IPPROTO_TCP: parse_tcp(buffer, size); break;
        case IPPROTO_UDP: parse_udp(buffer, size); break;
        case IPPROTO_ICMP: parse_icmp(buffer, size); break;
        default: printf("Unsupported protocol: 0x%04X\n", ip->protocol);
    }

    return 0;
}

int parse_ipv6(uint8_t *buffer, size_t size) {
    if (sizeof(struct ipv6hdr) > size) return -1;

    struct ipv6hdr *ip6 = (struct ipv6hdr *)buffer;
    // Add header to payload_len.
    uint16_t payload_len = ntohs(ip6->payload_len) + sizeof(struct ipv6hdr);
    if (payload_len > size) return -1;

    size_t offset = sizeof(struct ipv6hdr);
    uint8_t next_header = ip6->nexthdr;

    while(1) {
        if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP || 
            next_header == IPPROTO_ICMPV6) break; // Check if header is transport

        if (offset + sizeof(struct ipv6_opt_hdr) > size) return -1;
        struct ipv6_opt_hdr *exthdr = (struct ipv6_opt_hdr *)(buffer + offset);

        size_t exthdr_size = (exthdr->hdrlen + 1) * 8;
        if (offset + exthdr_size > size) return -1;

        offset += exthdr_size;
        next_header = exthdr->nexthdr;
    }
    
    size = payload_len - offset;
    buffer += offset;

    printf("--- (IPv6) ---\n");
    switch (next_header) {
        case IPPROTO_TCP: parse_tcp(buffer, size); break;
        case IPPROTO_UDP: parse_udp(buffer, size); break;
        case IPPROTO_ICMPV6: parse_icmp6(buffer, size); break;
        default: printf("Unsupported protocol: 0x%04X\n", next_header);
    }

    return 0;
}