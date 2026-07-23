#include <stdio.h>
#include <ctype.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdlib.h>
#include <getopt.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include "utils.h"

static void print_usage(const char *prog) {
    fprintf(stderr,
        "Usage: %s [options]\n"
        "Options:\n"
        "  -i, --iface <iface>      Network interface (default: eth0)\n"
        "  -4, --ip <addr>          IPv4 address filter\n"
        "  -6, --ip6 <addr>         IPv6 address filter\n"
        "  -p, --port <port>        Port filter (for udp and tcp only)\n"
        "  -P, --proto <proto>      Protocol (tcp,udp,icmp,arp)\n"
        "  -f, --file <path>        Output file\n"
        "  --ipv4-only              Only filter for ipv4\n"
        "  --ipv6-only              Only filter for ipv6\n"
        "  -h, --help               Display usage\n",
        prog
    );
}

int parse_args(int argc, char *argv[], see_config *conf) {
    int opt;

    static struct option long_opts[] = {
        {"iface",     required_argument, 0, 'i'},
        {"ip",        required_argument, 0, '4'},
        {"ip6",       required_argument, 0, '6'},
        {"port",      required_argument, 0, 'p'},
        {"proto",     required_argument, 0, 'P'},
        {"file",      required_argument, 0, 'f'},
        {"ipv4-only", no_argument,       0, 1001},
        {"ipv6-only", no_argument,       0, 1002},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "i:4:6:p:P:f:h", long_opts, NULL)) != -1) {
        switch (opt) {
            case 'i':
                strncpy(conf->iface, optarg, sizeof(conf->iface) - 1);
                conf->iface_set = true;
                break;
            case '4':
                if (inet_pton(AF_INET, optarg, &conf->addr) != 1) {
                    fprintf(stderr, "Invalid IPv4 address: %s\n", optarg);
                    return -1;
                }

                conf->addr_set = true;
                break;
            case '6':
                if (inet_pton(AF_INET6, optarg, &conf->addr6) != 1) {
                    fprintf(stderr, "Invalid IPv6 address: %s\n", optarg);
                    return -1;
                }

                conf->addr6_set = true;
                break;
            case 'p':
                conf->port = (uint16_t)atoi(optarg);
                if (conf->port == 0) {
                    fprintf(stderr, "Invalid port\n");
                    return -1;
                }

                conf->port_set = true;
                break;
            case 'P':
                char *token = strtok(optarg, ",");

                while (token) {
                    if (!strcmp(token, "tcp"))
                        conf->proto_mask |= PROTO_TCP;
                    else if (!strcmp(token, "udp"))
                        conf->proto_mask |= PROTO_UDP;
                    else if (!strcmp(token, "icmp"))
                        conf->proto_mask |= PROTO_ICMP;
                    else if (!strcmp(token, "arp"))
                        conf->proto_mask |= PROTO_ARP;
                    else {
                        fprintf(stderr, "Unknown protocol: %s\n", token);
                        return -1;
                    }

                    token = strtok(NULL, ",");
                }

                break;
            case 'f':
                conf->out = fopen(optarg, "w");
                if (!conf->out) {
                    perror("fopen");
                    return -1;
                }

                break;
            case 1001:
                if (conf->ip_mode_set) {
                    fprintf(stderr, "IP mode already set\n");
                    return -1;
                }

                conf->ip_mode = IPMODE_V4_ONLY;
                conf->ip_mode_set = true;
                break;
            case 1002:
                if (conf->ip_mode_set) {
                    fprintf(stderr, "IP mode already set\n");
                    return -1;
                }

                conf->ip_mode = IPMODE_V6_ONLY;
                conf->ip_mode_set = true;
                break;
            case 'h':
                print_usage(argv[0]);
                return -1;
            default:
                print_usage(argv[0]);
                return -1;
        }
    }

    // Default to all protos.
    if (!conf->proto_mask) {
        conf->proto_mask = PROTO_ALL;
    }

    return 0;
}

void print_payload(const uint8_t *data, size_t data_size, see_config *conf) {
    if (data_size == 0) {
        fprintf(conf->out, "No payload.\n\n");
        return;
    } 

    fprintf(conf->out, "--- Payload size (%zu) ---\n", data_size);
    for (size_t i = 0; i < data_size; i += 16) {
        fprintf(conf->out, "%04X ", (int)i);

        // Print hex.
        for (size_t j = 0; j < 16; j++) {
            if (i + j < data_size) {
                fprintf(conf->out, "%02X ", data[i + j]);
            } else {
                fprintf(conf->out, "   ");
            }
        } 

        fprintf(conf->out, " | ");

        // Print byte/char if readable.
        for (size_t j = 0; j < 16; j++) {
            if (i + j < data_size) {
                char byte = data[i + j];
                fprintf(conf->out, "%c", isprint(byte) ? byte : '.');
            }
        }

        fprintf(conf->out, "\n");
    }
    
    fprintf(conf->out, "\n");
    fflush(conf->out);
}

void print_iphdr(struct iphdr *ip, see_config *conf) {
    char src[INET_ADDRSTRLEN];
    char dst[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, &ip->saddr, src, sizeof(src));
    inet_ntop(AF_INET, &ip->daddr, dst, sizeof(dst));

    uint16_t frag = ntohs(ip->frag_off);
    int df = (frag & IP_DF) != 0;
    int mf = (frag & IP_MF) != 0;

    fprintf(conf->out, 
        "---(IPv4)---\n"
        "%s -> %s ttl=%u", 
        src, dst, ip->ttl 
    );

    if (df || mf) {
        fprintf(conf->out, " Flags=");
        if (df) fputc('D', conf->out);
        if (mf) fputc('M', conf->out);
    }

    fprintf(conf->out, "\n");
    fflush(conf->out);
}

void print_ip6_hdr(struct ip6_hdr* ip6, see_config *conf) {
    char src[INET6_ADDRSTRLEN];
    char dst[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, &ip6->ip6_src, src, sizeof(src));
    inet_ntop(AF_INET6, &ip6->ip6_dst, dst, sizeof(dst));

    fprintf(conf->out,
        "---(IPv6)---\n"
        "%s -> %s Hop=%u\n", src, dst, ip6->ip6_hlim
    );
}

void print_tcphdr(struct tcphdr *tcp, see_config *conf) {
    fprintf(conf->out, 
        "  --- (TCP) ---\n"
        "\tSeq=%u\n"
        "\tAck=%u\n"
        "\tWin=%u\n"
        "\tSrc=%u\n"
        "\tDec=%u\n",
        ntohl(tcp->seq), ntohl(tcp->ack_seq), ntohs(tcp->window),
        ntohs(tcp->source), ntohs(tcp->dest)
    );

    fprintf(conf->out, "\tFlags=");
    if (tcp->syn) fprintf(conf->out, "SYN ");
    if (tcp->ack) fprintf(conf->out, "ACK ");
    if (tcp->fin) fprintf(conf->out, "FIN ");
    if (tcp->rst) fprintf(conf->out, "RST ");
    if (tcp->psh) fprintf(conf->out, "PSH ");
    if (tcp->urg) fprintf(conf->out, "URG ");
    
    fprintf(conf->out, "\n");
    fflush(conf->out);
}

void print_udphdr(struct udphdr *udp, see_config *conf) {
    fprintf(conf->out, 
        "  --- (UDP) ---\n"
        "\tSrc=%u\n" 
        "\tDst=%u\n"
        "\tLen=%u\n", 
        ntohs(udp->source), ntohs(udp->dest), ntohs(udp->len)
    );

    fflush(conf->out);
}

void print_icmphdr(struct icmphdr *icmp, see_config *conf) {
    fprintf(conf->out, 
        "  --- (ICMP) ---\n"
        "\tType=%u\n"
        "\tCode=%u\n"
        "\tChecksum=0x%04x\n", 
        icmp->type, icmp->code, ntohs(icmp->checksum)
    );

    switch (icmp->type) {
        case ICMP_ECHO:
            fprintf(conf->out, "\tEcho Request\n");
            break;
        case ICMP_ECHOREPLY:
            fprintf(conf->out, "\tEcho Reply\n");
            break;
        default:
            fprintf(conf->out, "\tOther ICMP type\n");
            break;
    }

    fflush(conf->out);
}

void print_icmp6_hdr(struct icmp6_hdr *icmp6, see_config *conf) {
    fprintf(conf->out, 
        "  --- (ICMPv6) ---\n"
        "\tType=%u\n" 
        "\tCode=%u\n"
        "\tChecksum=0x%04x\n", 
        icmp6->icmp6_type, icmp6->icmp6_code, ntohs(icmp6->icmp6_cksum)
    );

    switch (icmp6->icmp6_type) {
        case ICMP6_ECHO_REQUEST:
            fprintf(conf->out, "\tEcho Request\n");
            break;
        case ICMP6_ECHO_REPLY:
            fprintf(conf->out, "\tEcho Reply\n");
            break;
        default:
            fprintf(conf->out, "\tOther ICMP type\n");
            break;
    }

    fflush(conf->out);
}

void print_ether_arp(struct ether_arp *arp, see_config *conf) {
    char spa[INET_ADDRSTRLEN];
    char tpa[INET_ADDRSTRLEN];

    inet_ntop(AF_INET, arp->arp_spa, spa, sizeof(spa));
    inet_ntop(AF_INET, arp->arp_tpa, tpa, sizeof(tpa));

    fprintf(conf->out, 
        "--- (ARP) ---\n"
        "Hardware type=%u\n"
        "Protocol type=0x%04x\n"
        "Opcode=%u\n", 
        ntohs(arp->ea_hdr.ar_hrd), ntohs(arp->ea_hdr.ar_pro), ntohs(arp->ea_hdr.ar_op)
    );

    fprintf(conf->out,
        "Sender MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
        arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
        arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

    fprintf(conf->out, "Sender IP=%s\n", spa);

    fprintf(conf->out,
        "Target MAC=%02x:%02x:%02x:%02x:%02x:%02x\n",
        arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
        arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);

    fprintf(conf->out, "Target IP=%s\n\n", tpa);
    fflush(conf->out);
}
