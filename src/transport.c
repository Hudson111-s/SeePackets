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

int parse_tcp(uint8_t *buffer, size_t size, see_config *conf) {
    if (sizeof(struct tcphdr) > size) return -1;

    struct tcphdr *tcp = (struct tcphdr *)buffer;
    size_t tcphdr_size = tcp->doff * 4;
    if (tcphdr_size > size) return -1;

    if (conf->port_set && (ntohs(tcp->source) != conf->port && ntohs(tcp->dest) != conf->port)) {
        return -1;
    }

    size -= tcphdr_size;
    buffer += tcphdr_size;

    // Filtering by port causes the ip header to still print
    // even if the port is invalid, therefore printing will 
    // be moved into the parse_ipv4/6, for now.

    // print_tcphdr(tcp, conf);
    // print_payload(buffer, size, conf);
    return 0;
}

int parse_udp(uint8_t *buffer, size_t size, see_config *conf) {
    if (sizeof(struct udphdr) > size) return -1;

    struct udphdr *udp = (struct udphdr *)buffer;
    size_t udphdr_size = sizeof(struct udphdr);

    if (conf->port_set && (ntohs(udp->source) != conf->port && ntohs(udp->dest) != conf->port)) {
        return -1;
    }

    size -= udphdr_size;
    buffer += udphdr_size;

    // Filtering by port causes the ip header to still print
    // even if the port is invalid, therefore printing will 
    // be moved into the parse_ipv4/6, for now.

    // print_udphdr(udp, conf);
    // print_payload(buffer, size, conf);
    return 0;
}

int parse_icmp(uint8_t *buffer, size_t size, see_config *conf) {
    if (sizeof(struct icmphdr) > size) return -1;

    struct icmphdr *icmp = (struct icmphdr *)buffer;
    size_t icmphdr_size = sizeof(struct icmphdr);

    size -= icmphdr_size;
    buffer += icmphdr_size;

    print_icmphdr(icmp, conf);
    print_payload(buffer, size, conf);
    return 0;
}

int parse_icmp6(uint8_t *buffer, size_t size, see_config *conf) {
    if (sizeof(struct icmp6_hdr) > size) return -1;

    struct icmp6_hdr *icmp6 = (struct icmp6_hdr *)buffer;
    size_t icmp6hdr_size = sizeof(struct icmp6_hdr);

    size -= icmp6hdr_size;
    buffer += icmp6hdr_size;

    print_icmp6_hdr(icmp6, conf);
    print_payload(buffer, size, conf);
    return 0;
}
