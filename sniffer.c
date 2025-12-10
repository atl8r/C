#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <errno.h>

#define BUFFER_SIZE 65536
#define ETH_HDR_SIZE 14
#define IP_MIN_HDR_SIZE 20
#define TCP_MIN_HDR_SIZE 20
#define UDP_HDR_SIZE 8

static int sock = -1;
static int promisc_enabled = 0;
static int ifindex = 0;

void print_mac(const unsigned char *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_payload(const unsigned char *data, size_t len) {
    if (len == 0) return;
    printf("Payload (%zu Bytes): ", len);
    size_t max_print = (len < 32) ? len : 32;
    for (size_t i = 0; i < max_print; ++i) {
        printf("%02x ", data[i]);
    }
    if (len > 32) printf("...");
    printf("\n");
}

void cleanup_and_exit(int sig) {
    (void)sig;  // unused
    if (promisc_enabled && ifindex > 0) {
        struct packet_mreq mreq = {0};
        mreq.mr_ifindex = ifindex;
        mreq.mr_type = PACKET_MR_PROMISC;
        setsockopt(sock, SOL_PACKET, PACKET_DROP_MEMBERSHIP, &mreq, sizeof(mreq));
    }
    if (sock >= 0) close(sock);
    printf("\nSniffer sauber beendet.\n");
    exit(EXIT_SUCCESS);
}

int set_promisc(int sockfd, int idx, int enable) {
    struct packet_mreq mreq = {0};
    mreq.mr_ifindex = idx;
    mreq.mr_type = PACKET_MR_PROMISC;
    int opt = enable ? PACKET_ADD_MEMBERSHIP : PACKET_DROP_MEMBERSHIP;
    if (setsockopt(sockfd, SOL_PACKET, opt, &mreq, sizeof(mreq)) < 0) {
        perror("setsockopt promisc");
        return -1;
    }
    return 0;
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface> (z.B. eth0)\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *iface = argv[1];

    // Signal-Handler für sauberes Beenden
    struct sigaction sa = {0};
    sa.sa_handler = cleanup_and_exit;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sock < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    // Interface-Index
    struct ifreq ifr = {0};
    if (snprintf(ifr.ifr_name, IFNAMSIZ, "%s", iface) >= IFNAMSIZ) {
        fprintf(stderr, "Interface-Name zu lang\n");
        goto cleanup;
    }
    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ioctl SIOCGIFINDEX");
        goto cleanup;
    }
    ifindex = ifr.ifr_ifindex;

    // Bind
    struct sockaddr_ll sll = {0};
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = ifindex;
    sll.sll_protocol = htons(ETH_P_ALL);
    if (bind(sock, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
        perror("bind");
        goto cleanup;
    }

    // Promiscuous-Modus
    if (set_promisc(sock, ifindex, 1) == 0) {
        promisc_enabled = 1;
    }

    printf("Sniffer läuft auf %s (Strg+C zum sauberen Beenden)...\n\n", iface);

    unsigned char buffer[BUFFER_SIZE];

    while (1) {
        ssize_t len = recvfrom(sock, buffer, BUFFER_SIZE, 0, NULL, NULL);
        if (len < 0) {
            if (errno == EINTR) continue;
            perror("recvfrom");
            continue;
        }
        if (len < ETH_HDR_SIZE) {
            printf("Zu kleines Paket (%zd Bytes) ignoriert\n\n", len);
            continue;
        }

        struct ether_header *eth = (struct ether_header *)buffer;

        printf("=== Ethernet Frame ===\n");
        printf("Dest MAC: "); print_mac(eth->ether_dhost); printf("\n");
        printf("Src  MAC: "); print_mac(eth->ether_shost); printf("\n");
        printf("Type    : 0x%04x ", ntohs(eth->ether_type));
        if (ntohs(eth->ether_type) == ETHERTYPE_IP) printf("(IPv4)\n");
        else if (ntohs(eth->ether_type) == ETHERTYPE_IPV6) printf("(IPv6)\n");
        else if (ntohs(eth->ether_type) == ETHERTYPE_ARP) printf("(ARP)\n");
        else printf("(Anderes)\n");

        if (ntohs(eth->ether_type) != ETHERTYPE_IP) {
            printf("\n");
            continue;
        }

        if (len < ETH_HDR_SIZE + IP_MIN_HDR_SIZE) {
            printf("Unvollständiger IP-Header\n\n");
            continue;
        }

        struct iphdr *ip = (struct iphdr *)(buffer + ETH_HDR_SIZE);
        unsigned int ip_hdr_len = ip->ihl * 4;
        if (ip_hdr_len < IP_MIN_HDR_SIZE || ip_hdr_len > len - ETH_HDR_SIZE) {
            printf("Ungültige IP-Header-Länge (%u)\n\n", ip_hdr_len);
            continue;
        }

        printf("--- IPv4 Header ---\n");
        printf("Version      : %d\n", ip->version);
        printf("Header Len   : %u Bytes\n", ip_hdr_len);
        printf("Total Len    : %d Bytes\n", ntohs(ip->tot_len));
        printf("TTL          : %d\n", ip->ttl);
        printf("Protocol     : %d ", ip->protocol);
        switch (ip->protocol) {
            case IPPROTO_ICMP: printf("(ICMP)\n"); break;
            case IPPROTO_TCP:  printf("(TCP)\n");  break;
            case IPPROTO_UDP:  printf("(UDP)\n");  break;
            default:           printf("(Anderes)\n");
        }
        struct in_addr src, dst;
        src.s_addr = ip->saddr;
        dst.s_addr = ip->daddr;
        printf("Source IP    : %s\n", inet_ntoa(src));
        printf("Dest   IP    : %s\n", inet_ntoa(dst));

        unsigned char *transport = buffer + ETH_HDR_SIZE + ip_hdr_len;
        size_t transport_len = len - ETH_HDR_SIZE - ip_hdr_len;

        if (ip->protocol == IPPROTO_TCP) {
            if (transport_len < TCP_MIN_HDR_SIZE) {
                printf("Unvollständiger TCP-Header\n");
            } else {
                struct tcphdr *tcp = (struct tcphdr *)transport;
                unsigned int tcp_hdr_len = tcp->doff * 4;
                if (tcp_hdr_len < TCP_MIN_HDR_SIZE || tcp_hdr_len > transport_len) {
                    printf("Ungültige TCP-Header-Länge (%u)\n", tcp_hdr_len);
                } else {
                    printf("--- TCP Header ---\n");
                    printf("Source Port  : %d\n", ntohs(tcp->source));
                    printf("Dest   Port  : %d\n", ntohs(tcp->dest));
                    printf("Sequence     : %u\n", ntohl(tcp->seq));
                    printf("Ack          : %u\n", ntohl(tcp->ack_seq));
                    printf("Flags        : ");
                    if (tcp->urg) printf("URG ");
                    if (tcp->ack) printf("ACK ");
                    if (tcp->psh) printf("PSH ");
                    if (tcp->rst) printf("RST ");
                    if (tcp->syn) printf("SYN ");
                    if (tcp->fin) printf("FIN ");
                    printf("\n");

                    size_t payload_len = transport_len - tcp_hdr_len;
                    print_payload(transport + tcp_hdr_len, payload_len);
                }
            }
        } else if (ip->protocol == IPPROTO_UDP) {
            if (transport_len >= UDP_HDR_SIZE) {
                struct udphdr *udp = (struct udphdr *)transport;
                printf("--- UDP Header ---\n");
                printf("Source Port  : %d\n", ntohs(udp->source));
                printf("Dest   Port  : %d\n", ntohs(udp->dest));
                printf("Length       : %d\n", ntohs(udp->len));

                size_t payload_len = transport_len - UDP_HDR_SIZE;
                print_payload(transport + UDP_HDR_SIZE, payload_len);
            } else {
                printf("Unvollständiger UDP-Header\n");
            }
        } else if (ip->protocol == IPPROTO_ICMP) {
            if (transport_len >= sizeof(struct icmphdr)) {
                struct icmphdr *icmp = (struct icmphdr *)transport;
                printf("--- ICMP Header ---\n");
                printf("Type         : %d\n", icmp->type);
                printf("Code         : %d\n", icmp->code);
            }
        }

        printf("\n");
    }

cleanup:
    cleanup_and_exit(0);
    return EXIT_FAILURE;  // unreachable
}
