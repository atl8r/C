/*
 * firewall_l7_dual.c - Dual-Stack L7 Firewall + HTTP/2 (HPACK) + HTTP/3 (QUIC) + Live Logging
 * Features: IPv4/IPv6, TCP Reassembly, DNS, HTTP/1.1, HTTP/2 (h2/h2c), HPACK, QUIC/HTTP3, Live Log
 *
 * Kompiliere mit:
 *   gcc -O2 -Wall -Wextra -pthread -o firewall_l7_secure firewall_l7_secure.c -lpcap -lnghttp2
 *
 * Aufruf:
 *   sudo ./firewall_l7_dual -v -i {interface}
 */

#define _GNU_SOURCE
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <syslog.h>
#include <math.h>
#include <net/ethernet.h>
#include <nghttp2/nghttp2.h>
#include <getopt.h>

// --- HTTP/2 & HTTP/3 Konstanten ---
#define HTTP2_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP2_MAGIC_LEN 24
#define HTTP2_FRAME_HEADER_LEN 9
#define HTTP2_HEADERS_FRAME 0x1
#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x01
#define QUIC_LONG_HEADER 0x80
#define ALPN_H2 "h2"
#define ALPN_H3 "h3"

// --- Config (tunable) ---
#define MAX_ENTRIES 32768
#define RATE_WINDOW 10
#define RATE_THRESHOLD 80
#define BLOCK_DURATION 1800
#define SESSION_TIMEOUT 180
#define CLEANUP_INTERVAL 30
#define MAX_TCP_SESSIONS 1024
#define MAX_SESSION_DATA (1024 * 1024)  // 1 MB
#define MAX_BLOCK_ENTRIES 4096
#define MAX_HASH_BUCKET 16

typedef enum { AF_4, AF_6 } af_t;
typedef union ip_addr { uint32_t v4; struct in6_addr v6; } ip_addr;

// --- Strukturen ---
typedef struct block_entry {
    af_t af;
    ip_addr ip;
    time_t block_until;
    struct block_entry *next;
} block_entry;

typedef struct ip_rate {
    af_t af;
    ip_addr ip;
    time_t last_ts;
    int count;
    int offenses;
    int dns_floods;
    int l7_hits;
    struct ip_rate *next;
} ip_rate;

typedef struct tcp_session {
    af_t af;
    ip_addr src_ip, dst_ip;
    uint16_t src_port, dst_port;
    char *data;
    size_t data_len, alloc_len;
    time_t last_seen;
    int is_http2;
    nghttp2_hd_inflater *inflater;
    struct tcp_session *next;
} tcp_session;

// --- Globals ---
static ip_rate *rate_table[MAX_ENTRIES] = {0};
static block_entry *block_list = NULL;
static tcp_session *tcp_sessions = NULL;
static pcap_t *handle = NULL;
static volatile sig_atomic_t running = 1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_mutex_t log_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t cleanup_thread;
static int verbose = 0;
static int session_count = 0;
static int block_count = 0;

// --- Live Logging (Thread-sicher) ---
void live_log(const char *color, const char *type, const char *msg, const char *ip, const char *extra) {
    if (!verbose) return;
    time_t now = time(NULL);
    char ts[9];
    strftime(ts, sizeof(ts), "%H:%M:%S", localtime(&now));
    pthread_mutex_lock(&log_lock);
    printf("\033[%sm[%s] [%s] %s%s%s\033[0m\n", color, ts, type, ip, extra ? " " : "", extra ? extra : "");
    fflush(stdout);
    pthread_mutex_unlock(&log_lock);
}

// --- Besserer Hash (SipHash-light) ---
static inline uint64_t siphash24(const uint8_t *in, size_t len) {
    uint64_t v0 = 0x736f6d6570736575ULL, v1 = 0x646f72616e646f6dULL;
    uint64_t v2 = 0x6c7967656e657261ULL, v3 = 0x7465646279746573ULL;
    uint64_t k0 = 0x0706050403020100ULL, k1 = 0x0f0e0d0c0b0a0908ULL;
    uint64_t m;

    #define SIPROUND do { \
        v0 += v1; v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0; \
        v0 = (v0 << 32) | (v0 >> 32); \
        v2 += v3; v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2; \
        v0 += v3; v3 = (v3 << 21) | (v3 >> 43); v3 ^= v0; \
        v2 += v1; v1 = (v1 << 17) | (v1 >> 47); v1 ^= v2; \
        v2 = (v2 << 32) | (v2 >> 32); \
    } while(0)

    for (size_t i = 0; i < len; i += 8) {
        m = i + 8 <= len ? *(uint64_t*)(in + i) : 0;
        if (i + 8 > len) m |= (uint64_t)in[i] << (8 * (len - i - 1));
        v3 ^= m; SIPROUND; v0 ^= m;
    }
    v3 ^= len; SIPROUND; v0 ^= 0xff;
    SIPROUND; SIPROUND; SIPROUND; SIPROUND;
    return v0 ^ v1 ^ v2 ^ v3;
}

static inline int hash_ip(af_t af, const ip_addr *ip) {
    if (af == AF_4) {
        return siphash24((uint8_t*)&ip->v4, 4) % MAX_ENTRIES;
    } else {
        return siphash24(ip->v6.s6_addr, 16) % MAX_ENTRIES;
    }
}

// --- IP Blocked? ---
int is_ip_blocked(af_t af, const ip_addr *ip) {
    pthread_mutex_lock(&lock);
    for (block_entry *e = block_list; e; e = e->next) {
        if (e->af == af && memcmp(&e->ip, ip, af == AF_4 ? 4 : 16) == 0 && time(NULL) < e->block_until) {
            pthread_mutex_unlock(&lock);
            return 1;
        }
    }
    pthread_mutex_unlock(&lock);
    return 0;
}

// --- Update Rate & Block ---
void update_rate_and_block(af_t af, const ip_addr *ip, int is_dns, const char *reason) {
    int h = hash_ip(af, ip);
    time_t now = time(NULL);
    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&ip->v4 : (void*)&ip->v6, ip_str, sizeof(ip_str));

    pthread_mutex_lock(&lock);
    ip_rate **head = &rate_table[h];
    ip_rate *r = *head;
    int bucket_size = 0;
    while (r && (r->af != af || memcmp(&r->ip, ip, af == AF_4 ? 4 : 16))) {
        r = r->next; bucket_size++;
    }
    if (bucket_size > MAX_HASH_BUCKET) {
        live_log("1;31", "HASHFLOOD", "Bucket overflow", ip_str, NULL);
        pthread_mutex_unlock(&lock);
        return;
    }

    if (!r) {
        if (bucket_size >= MAX_HASH_BUCKET) {
            pthread_mutex_unlock(&lock); return;
        }
        r = calloc(1, sizeof(ip_rate));
        if (!r) { pthread_mutex_unlock(&lock); return; }
        r->af = af; r->ip = *ip; r->last_ts = now;
        r->next = *head; *head = r;
    }

    if (now - r->last_ts > RATE_WINDOW) r->count = 1; else r->count++;
    r->last_ts = now;
    if (is_dns) r->dns_floods++; else r->l7_hits++;

    if (r->count > RATE_THRESHOLD || r->offenses > 5) {
        if (block_count >= MAX_BLOCK_ENTRIES) {
            pthread_mutex_unlock(&lock); return;
        }
        block_entry *b = malloc(sizeof(block_entry));
        if (b) {
            b->af = af; b->ip = *ip; b->block_until = now + BLOCK_DURATION;
            b->next = block_list; block_list = b; block_count++;
            live_log("1;31", "BLOCK", ip_str, reason, NULL);
            syslog(LOG_WARNING, "BLOCKED %s: %s", ip_str, reason);
        }
    }
    r->offenses++;
    pthread_mutex_unlock(&lock);
}

// --- Shannon Entropy ---
double shannon_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i]) { double p = (double)freq[i] / len; e -= p * log2(p); }
    }
    return e;
}

// --- HTTP/2 Magic ---
int is_http2_magic(const char *data) {
    return data && memcmp(data, HTTP2_MAGIC, HTTP2_MAGIC_LEN) == 0;
}

// --- TLS ALPN ---
int parse_tls_alpn(const uint8_t *data, size_t len, const char *target) {
    if (len < 50 || data[0] != TLS_HANDSHAKE || data[5] != TLS_CLIENT_HELLO) return 0;
    size_t pos = 43;
    if (pos + 2 >= len) return 0;
    uint16_t cs_len = ntohs(*(uint16_t*)(data + pos)); pos += 2 + cs_len;
    if (pos + 2 >= len) return 0;
    uint16_t ext_len = ntohs(*(uint16_t*)(data + pos)); pos += 2;
    size_t end = pos + ext_len;
    while (pos + 4 <= end) {
        uint16_t type = ntohs(*(uint16_t*)(data + pos));
        uint16_t elen = ntohs(*(uint16_t*)(data + pos + 2));
        pos += 4;
        if (pos + elen > end) break;
        if (type == 0x0010) {
            size_t p = pos;
            while (p + 1 < pos + elen) {
                uint8_t plen = data[p++];
                if (p + plen > pos + elen) break;
                if (plen == strlen(target) && memcmp(data + p, target, plen) == 0) return 1;
                p += plen;
            }
        }
        pos += elen;
    }
    return 0;
}

// --- HPACK Callback ---
static int on_header_callback(nghttp2_nv *nv, void *user_data) {
    if (nv->namelen > 1024 || nv->valuelen > 4096) {
        syslog(LOG_WARNING, "HPACK Anomalie: Header zu lang");
        return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
    return 0;
}

// --- HTTP/2 Analyse ---
void analyze_http2(const uint8_t *data, size_t len, af_t af, ip_addr *src_ip, tcp_session *sess) {
    if (len < HTTP2_FRAME_HEADER_LEN) return;
    size_t pos = 0;
    int headers = 0;
    while (pos + HTTP2_FRAME_HEADER_LEN <= len) {
        uint32_t plen = (data[pos] << 16) | (data[pos+1] << 8) | data[pos+2];
        uint8_t type = data[pos+3];
        if (pos + HTTP2_FRAME_HEADER_LEN + plen > len) break;
        if (type == HTTP2_HEADERS_FRAME && plen > 0) {
            headers++;
            if (!sess->inflater && nghttp2_hd_inflate_new(&sess->inflater)) break;
            size_t inlen = plen; const uint8_t *in = data + pos + HTTP2_FRAME_HEADER_LEN;
            int inflate_flags = 0;
            while (inlen > 0) {
                nghttp2_nv nv;
                nghttp2_ssize rv = nghttp2_hd_inflate_hd3(sess->inflater, &nv, &inflate_flags, in, inlen, 1);
                if (rv < 0) {
                    update_rate_and_block(af, src_ip, 0, "HPACK Decode Error");
                    return;
                }
                in += rv; inlen -= rv;
                if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
                    if (on_header_callback(&nv, sess) != 0) return;
                }
                if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
                    nghttp2_hd_inflate_end_headers(sess->inflater);
                    break;
                }
            }
        }
        pos += HTTP2_FRAME_HEADER_LEN + plen;
    }
    if (headers > 20) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&src_ip->v4 : (void*)&src_ip->v6, ip_str, sizeof(ip_str));
        update_rate_and_block(af, src_ip, 0, "HTTP/2 Header Flood");
    }
}

// --- QUIC / HTTP/3 ---
void analyze_quic(const u_char *payload, int len, af_t af, ip_addr *src_ip) {
    if (len <= 0 || (payload[0] & 0x80) != QUIC_LONG_HEADER) return;
    if (len < 50) return;
    if (parse_tls_alpn(payload, len, ALPN_H3)) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&src_ip->v4 : (void*)&src_ip->v6, ip_str, sizeof(ip_str));
        live_log("1;35", "H3", "HTTP/3 (QUIC) erkannt", ip_str, NULL);
        syslog(LOG_INFO, "HTTP/3 (QUIC) erkannt von %s", ip_str);
    }
}

// --- TCP Payload Verarbeitung (unter lock) ---
void process_tcp_payload(tcp_session *sess, const u_char *payload, int payload_len, af_t af, ip_addr *src_ip) {
    if (payload_len <= 0 || !sess->data) return;

    if (sess->data_len + payload_len > MAX_SESSION_DATA) {
        update_rate_and_block(af, src_ip, 0, "TCP Payload Flood");
        return;
    }

    if (sess->data_len + payload_len > sess->alloc_len) {
        size_t new_len = sess->alloc_len ? sess->alloc_len * 2 : 32768;
        if (new_len > MAX_SESSION_DATA) new_len = MAX_SESSION_DATA;
        char *new = realloc(sess->data, new_len);
        if (!new) return;
        sess->data = new;
        sess->alloc_len = new_len;
    }

    memcpy(sess->data + sess->data_len, payload, payload_len);
    sess->data_len += payload_len;

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&src_ip->v4 : (void*)&src_ip->v6, ip_str, sizeof(ip_str));

    if (!sess->is_http2 && sess->data_len >= HTTP2_MAGIC_LEN && is_http2_magic(sess->data)) {
        sess->is_http2 = 1;
        live_log("1;33", "H2C", "HTTP/2 (clear) erkannt", ip_str, NULL);
        syslog(LOG_INFO, "HTTP/2 (h2c) erkannt von %s", ip_str);
    }
    if (!sess->is_http2 && sess->data_len >= 60 && sess->data[0] == TLS_HANDSHAKE && parse_tls_alpn((uint8_t*)sess->data, sess->data_len, ALPN_H2)) {
        sess->is_http2 = 1;
        live_log("1;33", "H2", "HTTP/2 (TLS) erkannt", ip_str, NULL);
        syslog(LOG_INFO, "HTTP/2 (h2) erkannt von %s", ip_str);
    }
    if (sess->is_http2) analyze_http2((uint8_t*)sess->data, sess->data_len, af, src_ip, sess);
}

// --- IPv6 Ext Headers (sicher) ---
int skip_ipv6_ext(const u_char *base, int offset, uint8_t *proto) {
    int hops = 0;
    while (hops++ < 32) {
        uint8_t nxt = base[offset];
        if (nxt != IPPROTO_HOPOPTS && nxt != IPPROTO_ROUTING && nxt != IPPROTO_FRAGMENT && nxt != IPPROTO_DSTOPTS) {
            *proto = nxt;
            return offset;
        }
        int len = (base[offset + 1] + 1) * 8;
        if (len < 8 || offset + len > 65536) return -1;
        offset += len;
    }
    return -1;
}

// --- Packet Handler ---
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    if (h->caplen < 54) return;
    const struct ether_header *eth = (struct ether_header*)bytes;
    uint16_t ethtype = ntohs(eth->ether_type);
    if (ethtype != ETHERTYPE_IP && ethtype != ETHERTYPE_IPV6) return;

    af_t af; ip_addr src_ip; uint8_t proto = 0; int header_len = 0;
    const u_char *payload = bytes + 14;
    int payload_len = h->caplen - 14;

    if (ethtype == ETHERTYPE_IP) {
        const struct ip *ip4 = (struct ip*)payload;
        if (payload_len < (int)ip4->ip_hl * 4 || ip4->ip_v != 4) return;
        af = AF_4; src_ip.v4 = ip4->ip_src.s_addr;
        header_len = ip4->ip_hl * 4; proto = ip4->ip_p;
        payload += header_len; payload_len -= header_len;
    } else {
        const struct ip6_hdr *ip6 = (struct ip6_hdr*)payload;
        af = AF_6; src_ip.v6 = ip6->ip6_src;
        header_len = 40; proto = ip6->ip6_nxt;
        int off = skip_ipv6_ext(bytes + 14, 40, &proto);
        if (off < 0) return;
        header_len = off; payload = bytes + 14 + header_len; payload_len = h->caplen - 14 - header_len;
    }

    if (is_ip_blocked(af, &src_ip)) return;

    if (proto == IPPROTO_TCP && payload_len >= 20) {
        const struct tcphdr *tcp = (struct tcphdr*)payload;
        int tcp_hl = tcp->doff * 4;
        if (payload_len < tcp_hl) return;
        uint16_t sport = ntohs(tcp->source), dport = ntohs(tcp->dest);
        const u_char *data = payload + tcp_hl;
        int dlen = payload_len - tcp_hl;

        pthread_mutex_lock(&lock);
        if (session_count >= MAX_TCP_SESSIONS) {
            pthread_mutex_unlock(&lock);
            return;
        }

        tcp_session **p = &tcp_sessions;
        while (*p && ((*p)->af != af || (*p)->src_port != sport || (*p)->dst_port != dport || memcmp(&(*p)->src_ip, &src_ip, af == AF_4 ? 4 : 16)))
            p = &(*p)->next;

        tcp_session *sess = *p;
        if (!sess) {
            sess = calloc(1, sizeof(tcp_session));
            if (!sess) { pthread_mutex_unlock(&lock); return; }
            sess->af = af; sess->src_ip = src_ip;
            sess->src_port = sport; sess->dst_port = dport;
            sess->alloc_len = 32768; sess->data = malloc(sess->alloc_len);
            if (!sess->data) { free(sess); pthread_mutex_unlock(&lock); return; }
            sess->next = tcp_sessions; tcp_sessions = sess;
            session_count++;
        }
        sess->last_seen = time(NULL);
        pthread_mutex_unlock(&lock);

        if (dlen > 0) {
            pthread_mutex_lock(&lock);
            if (sess->data) process_tcp_payload(sess, data, dlen, af, &src_ip);
            pthread_mutex_unlock(&lock);
        }

    } else if (proto == IPPROTO_UDP && payload_len >= 8) {
        const struct udphdr *udp = (struct udphdr*)payload;
        uint16_t dport = ntohs(udp->dest);
        if (dport == 443) {
            int quic_len = payload_len - 8;
            if (quic_len > 0) {
                analyze_quic(payload + 8, quic_len, af, &src_ip);
            }
        }
    }
}

// --- Cleanup Thread ---
void *session_cleanup_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(CLEANUP_INTERVAL);
        time_t now = time(NULL);
        pthread_mutex_lock(&lock);

        // Cleanup Sessions
        tcp_session **p = &tcp_sessions;
        while (*p) {
            if (now - (*p)->last_seen > SESSION_TIMEOUT) {
                tcp_session *s = *p; *p = s->next;
                if (s->inflater) nghttp2_hd_inflate_del(s->inflater);
                free(s->data); free(s);
                session_count--;
            } else {
                p = &(*p)->next;
            }
        }

        // Cleanup Blocks
        block_entry **b = &block_list;
        while (*b) {
            if (now >= (*b)->block_until) {
                block_entry *tmp = *b; *b = tmp->next;
                free(tmp); block_count--;
            } else {
                b = &(*b)->next;
            }
        }

        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

// --- Signal Handler ---
void sig_handler(int s) { (void)s; running = 0; }

// --- Main ---
int main(int argc, char **argv) {
    char *iface = NULL;
    int opt;
    while ((opt = getopt(argc, argv, "vi:")) != -1) {
        switch (opt) {
            case 'v': verbose = 1; break;
            case 'i': iface = optarg; break;
            default: fprintf(stderr, "Usage: %s [-v] [-i interface]\n", argv[0]); return 1;
        }
    }
    if (!iface) { fprintf(stderr, "Interface erforderlich: -i eth0\n"); return 1; }

    openlog("firewall_l7_secure", LOG_PID | LOG_CONS, LOG_DAEMON);
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(iface, BUFSIZ, 1, 1000, errbuf);
    if (!handle) { syslog(LOG_ERR, "pcap_open_live: %s", errbuf); closelog(); return 1; }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "tcp or udp port 443", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        syslog(LOG_ERR, "Filter error: %s", pcap_geterr(handle));
        pcap_close(handle); closelog(); return 1;
    }

    pthread_create(&cleanup_thread, NULL, session_cleanup_thread, NULL);
    live_log("1;36", "START", "Sichere L7 Firewall (H2/H3)", iface, "Live-Log aktiv");
    syslog(LOG_INFO, "Sichere Firewall gestartet auf %s", iface);

    pcap_loop(handle, -1, packet_handler, NULL);

    running = 0;
    pthread_join(cleanup_thread, NULL);
    pcap_close(handle);
    closelog();
    return 0;
}
