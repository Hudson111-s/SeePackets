#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <arpa/inet.h>

#include "transport.h"
#include "utils.h"

int parse_tcp(uint8_t *buffer, size_t size) {
    if (sizeof(struct tcphdr) > size) return -1;

    struct tcphdr *tcp = (struct tcphdr *)buffer;
    size_t tcphdr_size = tcp->doff * 4;
    if (tcphdr_size > size) return -1;

    size -= tcphdr_size;
    buffer += tcphdr_size;

    print_tcphdr(tcp);
    print_payload(buffer, size);
    return 0;
}

int parse_udp(uint8_t *buffer, size_t size) {
    if (sizeof(struct udphdr) > size) return -1;

    struct udphdr *udp = (struct udphdr *)buffer;
    size_t udphdr_size = sizeof(struct udphdr);

    size -= udphdr_size;
    buffer += udphdr_size;

    print_udphdr(udp);
    print_payload(buffer, size);
    return 0;
}

int parse_icmp(uint8_t *buffer, size_t size) {
    if (sizeof(struct icmphdr) > size) return -1;

    struct icmphdr *icmp = (struct icmphdr *)buffer;
    size_t icmphdr_size = sizeof(struct icmphdr);

    size -= icmphdr_size;
    buffer += icmphdr_size;

    print_icmphdr(icmp);
    print_payload(buffer, size);
    return 0;
}

int parse_icmp6(uint8_t *buffer, size_t size) {
    if (sizeof(struct icmp6_hdr) > size) return -1;

    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
    size_t icmp6hdr_size = sizeof(struct icmp6_hdr);

    size -= icmp6hdr_size;
    buffer += icmp6hdr_size;

    print_icmp6_hdr(icmp6);
    print_payload(buffer, size);
    return 0;
}
