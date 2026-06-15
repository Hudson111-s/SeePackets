#pragma once

#include <stdint.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

void print_payload(const uint8_t *data, size_t data_size);
void print_tcphdr(struct tcphdr *tcp);
void print_udphdr(struct udphdr *udp);
