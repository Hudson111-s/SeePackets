#include <stdio.h>
#include <stdint.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
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

    print_payload(buffer, size);
    return 0;
}

int parse_udp(uint8_t *buffer, size_t size) {
    if (sizeof(struct udphdr) > size) return -1;

    struct udphdr *udp = (struct udphdr *)buffer;
    size_t udphdr_size = sizeof(struct udphdr);

    size -= udphdr_size;
    buffer += udphdr_size;

    print_payload(buffer, size);
    return 0;
}

int parse_icmp(uint8_t *buffer, size_t size) {
    if (sizeof(struct icmphdr) > size) return -1;

    struct icmphdr *icmp = (struct icmphdr *)buffer;
    size_t icmphdr_size = sizeof(struct icmphdr);

    size -= icmphdr_size;
    buffer += icmphdr_size;

    print_payload(buffer, size);
    return 0;
}
