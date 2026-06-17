#pragma once

#include <stdint.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>

void print_payload(const uint8_t *data, size_t data_size);
void print_tcphdr(struct tcphdr *tcp);
void print_udphdr(struct udphdr *udp);
void print_icmphdr(struct icmphdr *icmp);
void print_icmp6_hdr(struct icmp6_hdr *icmp6);
void print_ether_arp(struct ether_arp *arp);
