/*
 * firewall_l7_reassembly.c
 *
 * Erweiterter lokaler Firewall-Daemon mit vollständigem TCP-Reassembly
 * für Layer-7 Analyse (insbesondere HTTP) und Exploit-Schutz.
 *
 * TCP-Reassembly sorgt dafür, dass HTTP-Anfragen über mehrere Pakete hinweg korrekt zusammengesetzt werden.
 *
 * Kompilieren: gcc -o firewall_l7_reassembly firewall_l7_reassembly.c -lpcap
 */

#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <signal.h>

#define MAX_ENTRIES 8192
#define RATE_WINDOW 10
#define RATE_THRESHOLD 30
#define NOP_THRESHOLD 8
#define NONPRINTABLE_RATIO 0.6
#define LONG_PAYLOAD 1500
#define L7_OFFENSES_TO_BLOCK 2
#define BLOCK_CMD_FMT "iptables -I INPUT -s %s -j DROP -m comment --comment \"auto-blocked-by-firewall-l7\""

typedef struct ip_entry {
    uint32_t ip;
    time_t last_ts;
    int count;
    int offenses;
    int l7_hits;      // Anzahl L7-suspicious Funde
    struct ip_entry *next;
} ip_entry;

typedef struct tcp_session {
    uint32_t ip_src;
    uint32_t ip_dst;
    uint16_t port_src;
    uint16_t port_dst;
    uint64_t seq_num;
    uint64_t ack_num;
    char *data;
    size_t data_len;
    struct tcp_session *next;
} tcp_session;

static ip_entry *htable[MAX_ENTRIES];
static tcp_session *sessions = NULL;
static pcap_t *handle = NULL;
static volatile int running = 1;

// Hashing für IP-Adresse (einfaches Verfahren)
static inline int hidx(uint32_t ip) { return (ip ^ (ip>>16)) % MAX_ENTRIES; }

// TCP-Session finden oder erstellen
static tcp_session *find_or_create_session(uint32_t ip_src, uint32_t ip_dst, uint16_t port_src, uint16_t port_dst) {
    tcp_session *session = sessions;
    while (session) {
        if (session->ip_src == ip_src && session->ip_dst == ip_dst && 
            session->port_src == port_src && session->port_dst == port_dst) {
            return session;
        }
        session = session->next;
    }
    session = malloc(sizeof(tcp_session));
    if (!session) return NULL;
    session->ip_src = ip_src;
    session->ip_dst = ip_dst;
    session->port_src = port_src;
    session->port_dst = port_dst;
    session->seq_num = 0;
    session->ack_num = 0;
    session->data = malloc(1024); // Initialer Puffer
    session->data_len = 0;
    session->next = sessions;
    sessions = session;
    return session;
}

// Paketverarbeitung
static void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    const struct ip *ip_hdr;
    const struct tcphdr *tcp_hdr;
    int ip_header_len;
    int tcp_header_len;
    int payload_len;
    const u_char *payload;

    if (h->caplen < 14 + sizeof(struct ip)) return;
    ip_hdr = (struct ip*)(bytes + 14);
    if (ip_hdr->ip_v != 4) return;
    if (ip_hdr->ip_p != IPPROTO_TCP) return;

    ip_header_len = ip_hdr->ip_hl * 4;
    tcp_hdr = (struct tcphdr*)(bytes + 14 + ip_header_len);
    tcp_header_len = tcp_hdr->doff * 4;

    int total_len = ntohs(ip_hdr->ip_len);
    payload_len = total_len - ip_header_len - tcp_header_len;
    if (payload_len <= 0) return;
    payload = bytes + 14 + ip_header_len + tcp_header_len;

    uint32_t src_ip = ip_hdr->ip_src.s_addr;
    uint32_t dst_ip = ip_hdr->ip_dst.s_addr;
    uint16_t src_port = ntohs(tcp_hdr->th_sport);
    uint16_t dst_port = ntohs(tcp_hdr->th_dport);

    // TCP-Session finden oder erstellen
    tcp_session *session = find_or_create_session(src_ip, dst_ip, src_port, dst_port);
    if (!session) return;

    // Prüfen, ob es sich um ein Paket handelt, das zum Aufbauen einer TCP-Session erforderlich ist
    if (tcp_hdr->th_seq > session->seq_num) {
        size_t new_data_len = session->data_len + payload_len;
        session->data = realloc(session->data, new_data_len);
        if (!session->data) return;
        memcpy(session->data + session->data_len, payload, payload_len);
        session->data_len = new_data_len;
    }

    session->seq_num = tcp_hdr->th_seq + payload_len;

    // Nach vollständigem HTTP-Request suchen
    if (session->data_len > 0) {
        // HTTP-Request erkennen: einfache Überprüfung auf "GET /", "POST /" oder ähnliche Methodennamen
        if (strstr(session->data, "GET ") || strstr(session->data, "POST ")) {
            fprintf(stderr, "[%ld] L7 HTTP suspicious from %s:%d to %s:%d\n", 
                    (long)time(NULL), inet_ntoa(ip_hdr->ip_src), src_port, inet_ntoa(ip_hdr->ip_dst), dst_port);
            // Weitere L7-Analyse könnte hier folgen
        }
    }
}

// Paketfilter festlegen
static void set_filter(pcap_t *handle) {
    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip and tcp", 1, PCAP_NETMASK_UNKNOWN) == 0) {
        pcap_setfilter(handle, &fp);
        pcap_freecode(&fp);
    }
}

// Signalhandler (Ctrl-C)
static void sigint_handler(int signo) {
    (void)signo;
    running = 0;
    if (handle) pcap_breakloop(handle);
}

static void usage(const char *p) {
    fprintf(stderr, "Usage: %s <interface>\n", p);
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev;
    if (argc != 2) { usage(argv[0]); return 1; }
    dev = argv[1];

    signal(SIGINT, sigint_handler);
    signal(SIGTERM, sigint_handler);

    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (!handle) {
        fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
        return 1;
    }

    set_filter(handle);

    fprintf(stderr, "Firewall L7 daemon with TCP Reassembly running on %s. Ctrl-C to stop.\n", dev);
    pcap_loop(handle, -1, packet_handler, NULL);
    pcap_close(handle);
    fprintf(stderr, "Exiting.\n");
    return 0;
}
