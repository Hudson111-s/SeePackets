#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "utils.h"

void print_payload(const uint8_t *data, size_t data_size) {
    if (data_size == 0) {
        printf("No payload.\n\n");
        return;
    } 

    printf("--- Payload size (%ld) ---\n", data_size);
    for (size_t i = 0; i < data_size; i += 16) {
        printf("%04X ", (int)i);

        // Print hex.
        for (size_t j = 0; j < 16; j++) {
            if (i + j < data_size) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   ");
            }
        } 

        printf(" | ");

        // Print byte/char if readable.
        for (size_t j = 0; j < 16; j++) {
            if (i + j < data_size) {
                char byte = data[i + j];
                printf("%c", isprint(byte) ? byte : '.');
            }
        }

        printf("\n");
    }
    printf("\n");
}

void print_tcphdr(struct tcphdr *tcp) {
    printf("  --- (TCP) ---\n");
    printf("\tSeq=%u Ack=%u Win=%u\n", 
        ntohl(tcp->seq), 
        ntohl(tcp->ack_seq), 
        ntohs(tcp->window));

    printf("\tFlags: ");
    if (tcp->syn) printf("SYN ");
    if (tcp->ack) printf("ACK ");
    if (tcp->fin) printf("FIN ");
    if (tcp->rst) printf("RST ");
    if (tcp->psh) printf("PSH ");
    if (tcp->urg) printf("URG ");
    printf("\n");
}

void print_udphdr(struct udphdr *udp) {
    printf("  --- (UDP) ---\n");
    printf("\tSrc=%u Dst=%u Len=%u\n", 
        ntohs(udp->source), 
        ntohs(udp->dest), 
        ntohs(udp->len));
}

void print_icmphdr(struct icmphdr *icmp) {
    printf("  --- (ICMP) ---\n");
    printf("\tType: %u\n", icmp->type);
    printf("\tCode: %u\n", icmp->code);
    printf("\tChecksum: 0x%04x\n", ntohs(icmp->checksum));

    switch (icmp->type) {
        case ICMP_ECHO:
            printf("\tEcho Request\n");
            break;
        case ICMP_ECHOREPLY:
            printf("\tEcho Reply\n");
            break;
        default:
            printf("\tOther ICMP type\n");
            break;
    }
}

void print_icmp6_hdr(struct icmp6_hdr *icmp6) {
    printf("  --- (ICMPv6) ---\n");
    printf("\tType: %u\n", icmp6->icmp6_type);
    printf("\tCode: %u\n", icmp6->icmp6_code);
    printf("\tChecksum: 0x%04x\n", ntohs(icmp6->icmp6_cksum));

    switch (icmp6->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
            printf("\tEcho Request\n");
            break;
        case ICMP6_ECHO_REPLY:
            printf("\tEcho Reply\n");
            break;
        default:
            printf("\tOther ICMP type\n");
            break;
    }
}

void print_ether_arp(struct ether_arp *arp) {
    printf("--- (ARP) ---\n");
    printf("  Hardware type: %u\n", ntohs(arp->ea_hdr.ar_hrd));
    printf("  Protocol type: 0x%04x\n", ntohs(arp->ea_hdr.ar_pro));
    printf("  Opcode: %u\n", ntohs(arp->ea_hdr.ar_op));

    printf("  Sender MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
        arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

    printf("  Sender IP: %s\n", inet_ntoa(*(struct in_addr *)arp->arp_spa));

    printf("  Target MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
        arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
        arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);

    printf("  Target IP: %s\n\n", inet_ntoa(*(struct in_addr *)arp->arp_tpa));
}
