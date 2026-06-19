#pragma once

#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <net/if.h>

// Proto mask.
#define PROTO_TCP   (1 << 0)
#define PROTO_UDP   (1 << 1)
#define PROTO_ICMP  (1 << 2)
#define PROTO_ARP   (1 << 3)
#define PROTO_ALL   (PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ARP)

typedef enum {
    IPMODE_ANY = 0,
    IPMODE_V4_ONLY,
    IPMODE_V6_ONLY
} ip_mode_t;

typedef struct see_config {
    FILE *out;

    char iface[IFNAMSIZ];
    bool iface_set;

    struct in_addr addr;
    bool addr_set;

    struct in6_addr addr6;
    bool addr6_set;
    
    ip_mode_t ip_mode;
    bool ip_mode_set;

    // 4 byte so can expand flags later.
    uint32_t proto_mask; 
    
    uint16_t port;
    bool port_set;
} see_config;

void print_payload(const uint8_t *data, size_t data_size, see_config *conf);
void print_iphdr(struct iphdr *ip, see_config *conf);
void print_ip6_hdr(struct ip6_hdr* ip6, see_config *conf);
void print_tcphdr(struct tcphdr *tcp, see_config *conf);
void print_udphdr(struct udphdr *udp, see_config *conf);
void print_icmphdr(struct icmphdr *icmp, see_config *conf);
void print_icmp6_hdr(struct icmp6_hdr *icmp6, see_config *conf);
void print_ether_arp(struct ether_arp *arp, see_config *conf);

int parse_args(int argc, char *argv[], see_config *conf);

