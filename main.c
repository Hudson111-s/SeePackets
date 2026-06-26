#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <net/if.h>

#include "ethernet.h"
#include "utils.h"

int main(int argc, char *argv[]) {
    see_config *conf = &(see_config){
        .out          = stdout,
        .iface        = "eth0",
        .proto_mask   = 0,
        .ip_mode      = IPMODE_ANY
    };

    int err = 0;
    int sock = -1;
    
    if (parse_args(argc, argv, conf) == -1) {        
        err = 1;    
        goto cleanup;
    }

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        err = 1;
        goto cleanup;
    }

    const char *iface = conf->iface;

    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));

    sll.sll_family = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = if_nametoindex(iface);
    if (sll.sll_ifindex == 0) {
        perror("if_nametoindex");
        err = 1;
        goto cleanup;
    }

    if (bind(sock, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("bind");
        err = 1;
        goto cleanup;
    }

    fprintf(conf->out, "Listening on %s\n", iface);
    uint8_t buffer[ETH_FRAME_SIZE];

    while (1) {
        ssize_t size = recvfrom(sock, buffer, sizeof(buffer), 0, NULL, NULL);
        if (size < 0) {
            perror("recvfrom");
            break;
        }

        parse_ethernet(buffer, size, conf);
    }

    cleanup:
        if (sock >= 0) close(sock);
        if (conf->out != stdout) fclose(conf->out);

        return err;
}