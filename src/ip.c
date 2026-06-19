#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "ip.h"
#include "transport.h"
#include "utils.h"

int parse_ipv4(uint8_t *buffer, size_t size, see_config *conf) {
    if (sizeof(struct iphdr) > size) return -1;

    struct iphdr *ip = (struct iphdr *)buffer;
    size_t iphdr_size = ip->ihl * 4;
    uint16_t total_len = ntohs(ip->tot_len);
    if (iphdr_size > size) return -1;
    if (total_len < iphdr_size || total_len > size) return -1;

    // Check ipv4 filter.
    if (conf->addr_set && (ip->saddr != conf->addr.s_addr && ip->daddr != conf->addr.s_addr)) {
        return 0;
    }

    size = total_len - iphdr_size;
    buffer += iphdr_size;

    switch (ip->protocol) {
        case IPPROTO_TCP: 
            if (!(conf->proto_mask & PROTO_TCP)) return 0;
            if (parse_tcp(buffer, size, conf) == -1) return 0; 
            print_iphdr(ip, conf);

            struct tcphdr *tcp = (struct tcphdr *)buffer;
            size_t tcphdr_size = tcp->doff * 4;
            size -= tcphdr_size;
            buffer += tcphdr_size;

            print_tcphdr(tcp, conf);
            print_payload(buffer, size, conf);
            break;
        case IPPROTO_UDP: 
            if (!(conf->proto_mask & PROTO_UDP)) return 0;
            if (parse_udp(buffer, size, conf) == -1) return 0;
            print_iphdr(ip, conf);

            struct udphdr *udp = (struct udphdr *)buffer;
            size_t udphdr_size = sizeof(struct udphdr);
            size -= udphdr_size;
            buffer += udphdr_size;

            print_udphdr(udp, conf);
            print_payload(buffer, size, conf);
            break;
        case IPPROTO_ICMP:
            if (!(conf->proto_mask & PROTO_ICMP)) return 0;

            print_iphdr(ip, conf);
            parse_icmp(buffer, size, conf); 
            break;
    }

    return 0;
}

int parse_ipv6(uint8_t *buffer, size_t size, see_config *conf) {
    if (sizeof(struct ip6_hdr) > size) return -1;

    struct ip6_hdr *ip6 = (struct ip6_hdr *)buffer;
    // Add header to payload.
    uint16_t total_len = ntohs(ip6->ip6_plen) + sizeof(struct ip6_hdr);
    if (total_len > size) return -1;

        // Check ipv6 filter.
        if (conf->addr6_set &&
            (memcmp(&ip6->ip6_src, &conf->addr6, sizeof(struct in6_addr)) != 0 ||
            memcmp(&ip6->ip6_dst, &conf->addr6, sizeof(struct in6_addr)) != 0)) {
                return 0;
            }
            
    size_t offset = sizeof(struct ip6_hdr);
    uint8_t next_header = ip6->ip6_nxt;

    while(1) {
        if (next_header == IPPROTO_TCP || next_header == IPPROTO_UDP || 
            next_header == IPPROTO_ICMPV6) break; // Check if header is transport

        if (offset + sizeof(struct ip6_ext) > size) return -1;
        struct ip6_ext *exthdr = (struct ip6_ext *)(buffer + offset);

        size_t exthdr_size = (exthdr->ip6e_len + 1) * 8;
        if (offset + exthdr_size > size) return -1;

        offset += exthdr_size;
        next_header = exthdr->ip6e_nxt;
    }
    
    size = total_len - offset;
    buffer += offset;

    switch (next_header) {
        case IPPROTO_TCP: 
            if (!(conf->proto_mask & PROTO_TCP)) return 0;
            if (parse_tcp(buffer, size, conf) == -1) return 0; 
            print_ip6_hdr(ip6, conf);

            struct tcphdr *tcp = (struct tcphdr *)buffer;
            size_t tcphdr_size = tcp->doff * 4;
            size -= tcphdr_size;
            buffer += tcphdr_size;

            print_tcphdr(tcp, conf);
            print_payload(buffer, size, conf);
            break;
        case IPPROTO_UDP: 
            if (!(conf->proto_mask & PROTO_UDP)) return 0;
            if (parse_udp(buffer, size, conf) == -1) return 0;
            print_ip6_hdr(ip6, conf);

            struct udphdr *udp = (struct udphdr *)buffer;
            size_t udphdr_size = sizeof(struct udphdr);
            size -= udphdr_size;
            buffer += udphdr_size;

            print_udphdr(udp, conf);
            print_payload(buffer, size, conf);
            break;
        case IPPROTO_ICMPV6: 
            if (!(conf->proto_mask & PROTO_ICMP)) return 0;

            print_ip6_hdr(ip6, conf);
            parse_icmp6(buffer, size, conf); 
            break;
    }

    return 0;
}