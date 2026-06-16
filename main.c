#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#include "ethernet.h"

int main(int argc, char **argv) {
    (void)argc;
    (void)argv;

    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return 1;
    }

    const char *iface = "eth0";

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(iface);
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
        ssize_t size = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (size < 0) {
            perror("recvfrom");
            break;
        }

        parse_ethernet(buffer, size);
    }

    return 0;
}