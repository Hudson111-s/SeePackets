#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "utils.h"

void print_payload(const uint8_t *data, size_t data_size) {
    if (data_size == 0) {
        printf("No payload.\n");
        return;
    } 

    printf("--- Payload size (%ld) ---\n", data_size);
    for (int i = 0; i < data_size; i += 16) {
        printf("%04X ", i);

        // Print hex.
        for (int j = 0; j < 16; j++) {
            if (i + j < data_size) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        } 

        printf(" | ");

        // Print byte/char if readable.
        for (int j = 0; j < 16; j++) {
            if (i + j < data_size) {
                char byte = data[i + j];
                printf("%c", isprint(byte) ? byte : '.');
            }
        }

        printf("\n");
    }
}

void print_tcphdr(struct tcphdr *tcp) {
    printf("--- (TCP) ---\n");
    printf("Seq=%u Ack=%u Win=%u\n", 
        ntohl(tcp->seq), 
        ntohl(tcp->ack_seq), 
        ntohs(tcp->window));

    printf("Flags: ");
    if (tcp->syn) printf("SYN ");
    if (tcp->ack) printf("ACK ");
    if (tcp->fin) printf("FIN ");
    if (tcp->rst) printf("RST ");
    if (tcp->psh) printf("PSH ");
    if (tcp->urg) printf("URG ");
    printf("\n");
}

void print_udphdr(struct udphdr *udp) {
    printf("--- (UDP) ---\n");
    printf("Src=%u Dst=%u Len=%u\n", 
        ntohs(udp->source), 
        ntohs(udp->dest), 
        ntohs(udp->len));
}
