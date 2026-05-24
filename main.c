#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>

#include <arpa/inet.h>
#include <sys/socket.h>

#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <net/ethernet.h>
#include <net/if.h>

void print_payload(const uint8_t *data, int data_size) {
    if (data_size <= 0) {
        printf("No payload data.\n");
        return;
    }

    printf("--- Payload Data (%d bytes) ---\n", data_size);
    for (int i = 0; i < data_size; i += 16) {
        printf("%04X  ", i);

        // Print the Hex values.
        for (int j = 0; j < 16; j++) {
            if (i + j < data_size) {
                printf("%02X ", data[i + j]);
            } else {
                printf("   "); // Pad spaces if not data
            }
        }
        printf(" | ");

        //Print the ASCII.
        for (int j = 0; j < 16; j++) {
            if (i + j < data_size) {
                uint8_t byte = data[i + j];
                // Only print if readable, else print a dot
                printf("%c", isprint(byte) ? byte : '.');
            }
        }
        printf("\n");
    }
    printf("-------------------------------\n");
}

int main(int argc, char **arcv) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    const char *iface = "eth0";

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));

    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = if_nametoindex(iface);
    if (sll.sll_ifindex == 0) {
        perror("if_nametoindex");
        return 1;
    }

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        return 1;
    }

    printf("Listening on %s\n", iface);

    uint8_t buffer[65536]; // Max eth frame size

    while (1) {
        int size = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (size < 0) {
            perror("recvfrom");
            break;
        }

        struct ethhdr *frame = (struct ethhdr *)buffer;
        printf("ETH proto: 0x%04x\n", ntohs(frame->h_proto));
        
        if (ntohs(frame->h_proto) != ETH_P_IP) continue; // Only ipv4 for now
        
        // Add checks before moving pointer.
        struct iphdr *ip = (struct iphdr *)((uint8_t *)frame + sizeof(struct ethhdr));
        
        char src_ip[INET_ADDRSTRLEN];
        char dst_ip[INET_ADDRSTRLEN];

        inet_ntop(AF_INET, &ip->saddr, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &ip->daddr, dst_ip, sizeof(dst_ip));

        printf("SRC: %s, DST: %s\n", src_ip, dst_ip);

        uint8_t *transport = (uint8_t *)ip + ip->ihl * 4;

        int curr_doff = 14 + (ip->ihl * 4);
 
        switch (ip->protocol) {
            case IPPROTO_TCP: {
                struct tcphdr *tcp = (struct tcphdr *)transport;
                printf("TCP SRC PORT: %u\n", ntohs(tcp->source));

                uint8_t *data = (uint8_t *)tcp + (tcp->doff * 4);
                int data_size = size - (curr_doff + (tcp->doff * 4));

                print_payload(data, data_size);
                break;
            }
            case IPPROTO_UDP: {
                struct udphdr *udp = (struct udphdr *)transport;
                printf("UDP SRC PORT: %u\n", ntohs(udp->source));

                uint8_t *data = (uint8_t *)udp + 8;
                int data_size = size - (curr_doff + 8);
                
                print_payload(data, data_size);
                break;
            }
            case IPPROTO_ICMP: {
                struct icmphdr *icmp = (struct icmphdr *)transport;

                uint8_t *data = (uint8_t *)icmp + 8;
                int data_size = size - (curr_doff + 8);
                
                print_payload(data, data_size);
                break;
            }
        }
        
    }

    return 0;
}