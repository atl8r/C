/*
 * firewall_l7_dual.c - Dual-Stack L7 Firewall + HTTP/2 Erkennung inkl. HPACK-Decoding
 * IPv4/IPv6, TCP-Reassembly, DNS, HTTP/1.1, HTTP/2 (h2/h2c), HPACK, Exploit-Schutz
 *
 * Erweitert um nghttp2-Bibliothek für HPACK-Decoding.
 * Kompiliert mit: gcc -o firewall_l7_dual firewall_l7_dual.c -lpcap -lpthread -lnghttp2 -lm -lsyslog
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
#include <ctype.h>
#include <signal.h>
#include <pthread.h>
#include <syslog.h>
#include <math.h>
#include <net/ethernet.h>
#include <nghttp2/nghttp2.h>

// --- HTTP/2 Konstanten ---
#define HTTP2_MAGIC "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define HTTP2_MAGIC_LEN 24
#define HTTP2_FRAME_HEADER_LEN 9
#define HTTP2_SETTINGS_FRAME 0x4
#define HTTP2_HEADERS_FRAME 0x1
#define TLS_HANDSHAKE 0x16
#define TLS_CLIENT_HELLO 0x01

// --- Bestehende Defines ---
#define MAX_ENTRIES 32768
#define RATE_WINDOW 10
#define RATE_THRESHOLD 80
#define BLOCK_DURATION 1800
#define DNS_TUNNEL_ENTROPY 3.9
#define DNS_TUNNEL_LABEL_LEN 40
#define CONFIG_FILE "/etc/firewall_l7/config.conf"
#define BLACKLIST_FILE "/etc/firewall_l7/blacklist.txt"
#define SESSION_TIMEOUT 180
#define CLEANUP_INTERVAL 30

typedef enum { AF_4, AF_6 } af_t;
typedef union ip_addr { uint32_t v4; struct in6_addr v6; } ip_addr;

// --- Strukturen ---
typedef struct block_entry { af_t af; ip_addr ip; time_t block_until; struct block_entry *next; } block_entry;
typedef struct ip_rate { af_t af; ip_addr ip; time_t last_ts; int count; int offenses; int dns_floods; int l7_hits; struct ip_rate *next; } ip_rate;

typedef struct tcp_session {
    af_t af;
    ip_addr src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint32_t seq;
    char *data;
    size_t data_len;
    size_t alloc_len;
    time_t last_seen;
    int is_http2;           // HTTP/2 erkannt?
    int http2_frames;       // Anzahl Frames
    int http2_headers;      // Anzahl HEADERS
    nghttp2_hd_inflater *inflater;  // Neu: HPACK Inflater für Decoding
    struct tcp_session *next;
} tcp_session;

// --- Globals ---
static ip_rate *rate_table[MAX_ENTRIES] = {0};
static block_entry *block_list = NULL;
static tcp_session *tcp_sessions = NULL;
static pcap_t *handle = NULL;
static volatile sig_atomic_t running = 1;
static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_t cleanup_thread;

#define BL_SIZE 16384
static char *blacklist[BL_SIZE] = {0};
static int cfg_rate_threshold = RATE_THRESHOLD;
static int cfg_block_duration = BLOCK_DURATION;

// --- Vorwärtsdeklarationen ---
void load_config(void);
void load_blacklist(void);
void *session_cleanup_thread(void *arg);
int is_http2_magic(const char *data);
int parse_tls_client_hello(const uint8_t *data, size_t len);
void analyze_http2(const uint8_t *data, size_t len, af_t af, ip_addr *src_ip, tcp_session *sess);
double shannon_entropy(const uint8_t *data, size_t len);
void process_tcp_payload(tcp_session *sess, const u_char *payload, int payload_len, af_t af, ip_addr *src_ip);
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes);
int skip_ipv6_ext_headers(const u_char *payload, int offset, uint8_t *next_proto);
void sig_handler(int signo);
int is_ip_blocked(af_t af, const ip_addr *ip);
void update_rate(af_t af, const ip_addr *ip, int is_dns);
void analyze_dns(const u_char *dns_payload, int len, af_t af, const ip_addr *src_ip);

// --- Hilfsfunktionen ---
static inline int hash_ip(af_t af, const ip_addr *ip) {
    if (af == AF_4) {
        uint32_t v = ip->v4;
        return (v ^ (v >> 13) ^ (v >> 26)) % MAX_ENTRIES;
    } else {
        uint64_t h = 0;
        for (int i = 0; i < 16; i += 8)
            h ^= *(uint64_t*)(ip->v6.s6_addr + i);
        return h % MAX_ENTRIES;
    }
}

static inline int bl_hash(const char *s) {
    unsigned h = 5381;
    while (*s) h = h * 33 + *s++;
    return h % BL_SIZE;
}

// --- Signal Handler ---
void sig_handler(int signo) {
    (void)signo;
    running = 0;
}

// --- Load Config ---
void load_config(void) {
    // Dummy-Implementierung; erweitern für echte Config-Parsing
    cfg_rate_threshold = RATE_THRESHOLD;
    cfg_block_duration = BLOCK_DURATION;
    syslog(LOG_INFO, "Config geladen: Rate Threshold=%d, Block Duration=%d", cfg_rate_threshold, cfg_block_duration);
}

// --- Load Blacklist ---
void load_blacklist(void) {
    FILE *f = fopen(BLACKLIST_FILE, "r");
    if (!f) {
        syslog(LOG_ERR, "Blacklist-Datei nicht gefunden: %s", BLACKLIST_FILE);
        return;
    }
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;  // Entferne Newline
        int h = bl_hash(line);
        if (!blacklist[h]) {
            blacklist[h] = strdup(line);
        }
    }
    fclose(f);
    syslog(LOG_INFO, "Blacklist geladen");
}

// --- IP Blocked? ---
int is_ip_blocked(af_t af, const ip_addr *ip) {
    pthread_mutex_lock(&lock);
    for (block_entry *e = block_list; e; e = e->next) {
        if (e->af == af && memcmp(&e->ip, ip, af == AF_4 ? 4 : 16) == 0) {
            if (time(NULL) < e->block_until) {
                pthread_mutex_unlock(&lock);
                return 1;
            }
        }
    }
    pthread_mutex_unlock(&lock);
    return 0;
}

// --- Update Rate ---
void update_rate(af_t af, const ip_addr *ip, int is_dns) {
    int h = hash_ip(af, ip);
    time_t now = time(NULL);
    pthread_mutex_lock(&lock);
    ip_rate *r = rate_table[h];
    while (r) {
        if (r->af == af && memcmp(&r->ip, ip, af == AF_4 ? 4 : 16) == 0) {
            if (now - r->last_ts > RATE_WINDOW) {
                r->count = 1;
                r->last_ts = now;
            } else {
                r->count++;
            }
            if (is_dns) r->dns_floods++;
            else r->l7_hits++;
            r->offenses++;
            if (r->count > cfg_rate_threshold || r->offenses > 5) {
                block_entry *b = malloc(sizeof(block_entry));
                if (b) {
                    b->af = af;
                    b->ip = *ip;
                    b->block_until = now + cfg_block_duration;
                    b->next = block_list;
                    block_list = b;
                    char ip_str[INET6_ADDRSTRLEN];
                    inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&ip->v4 : (void*)&ip->v6, ip_str, sizeof(ip_str));
                    syslog(LOG_WARNING, "IP blockiert: %s für %d Sekunden", ip_str, cfg_block_duration);
                }
            }
            pthread_mutex_unlock(&lock);
            return;
        }
        r = r->next;
    }
    // Neuen Entry hinzufügen
    r = malloc(sizeof(ip_rate));
    if (r) {
        r->af = af;
        r->ip = *ip;
        r->last_ts = now;
        r->count = 1;
        r->offenses = is_dns ? 0 : 1;
        r->dns_floods = is_dns ? 1 : 0;
        r->l7_hits = is_dns ? 0 : 1;
        r->next = rate_table[h];
        rate_table[h] = r;
    }
    pthread_mutex_unlock(&lock);
}

// --- DNS Analyse ---
void analyze_dns(const u_char *dns_payload, int len, af_t af, const ip_addr *src_ip) {
    if (len < 12) return;  // DNS Header zu kurz
    // Einfache Entropy-Check für Tunneling
    double e = shannon_entropy(dns_payload, len);
    if (e > DNS_TUNNEL_ENTROPY) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&src_ip->v4 : (void*)&src_ip->v6, ip_str, sizeof(ip_str));
        syslog(LOG_WARNING, "DNS Tunnel verdächtig: Entropy=%.2f von %s", e, ip_str);
        update_rate(af, src_ip, 1);
    }
}

// --- HTTP/2 Erkennung: h2c (clear) ---
int is_http2_magic(const char *data) {
    return (data && memcmp(data, HTTP2_MAGIC, HTTP2_MAGIC_LEN) == 0);
}

// --- HTTP/2 Erkennung: h2 (TLS) via ALPN ---
int parse_tls_client_hello(const uint8_t *data, size_t len) {
    if (len < 6) return 0;
    if (data[0] != TLS_HANDSHAKE || data[5] != TLS_CLIENT_HELLO) return 0;

    size_t pos = 43;  // Skip Header + Version + Random + Session ID
    if (pos >= len) return 0;

    uint16_t cipher_suites_len = ntohs(*(uint16_t*)(data + pos));
    pos += 2 + cipher_suites_len;
    if (pos >= len) return 0;

    uint16_t extensions_len = ntohs(*(uint16_t*)(data + pos));
    pos += 2;
    if (pos + extensions_len > len) return 0;

    size_t end = pos + extensions_len;
    while (pos + 4 <= end) {
        uint16_t type = ntohs(*(uint16_t*)(data + pos));
        uint16_t elen = ntohs(*(uint16_t*)(data + pos + 2));
        pos += 4;
        if (pos + elen > end) break;

        if (type == 0x0010) {  // ALPN extension
            if (elen < 3) break;
            size_t alpn_pos = pos + 3;
            size_t alpn_end = pos + elen;
            while (alpn_pos + 2 < alpn_end) {
                uint8_t plen = data[alpn_pos++];
                if (alpn_pos + plen > alpn_end) break;
                if (plen == 2 && memcmp(data + alpn_pos, "h2", 2) == 0) {
                    return 1;  // ALPN = h2
                }
                alpn_pos += plen;
            }
        }
        pos += elen;
    }
    return 0;
}

// --- HPACK Decoding Callback (für nghttp2) ---
static int on_header_callback(nghttp2_nv *nv, void *user_data) {
    tcp_session *sess = (tcp_session *)user_data;
    // Prüfe dekodierte Headers auf Anomalien
    if (nv->namelen > 1024 || nv->valuelen > 4096) {
        syslog(LOG_WARNING, "HPACK Anomalie: Überlanger Header (%zu:%zu)", nv->namelen, nv->valuelen);
        sess->http2_headers++;  // Zähle als Anomalie
    }
    double e = shannon_entropy(nv->value, nv->valuelen);
    if (e > 4.5) {
        syslog(LOG_WARNING, "HPACK Anomalie: Hohe Entropy in Value (%.2f)", e);
    }
    // Weitere Checks, z.B. Blacklist-Match
    return 0;  // Fortsetzen
}

// --- HTTP/2 Analyse (mit HPACK-Decoding via nghttp2) ---
void analyze_http2(const uint8_t *data, size_t len, af_t af, ip_addr *src_ip, tcp_session *sess) {
    if (len < HTTP2_FRAME_HEADER_LEN) return;

    size_t pos = 0;
    int frames = 0, headers = 0;
    double entropy_sum = 0.0;
    int blocks = 0;

    while (pos + HTTP2_FRAME_HEADER_LEN <= len) {
        uint32_t payload_len = (data[pos] << 16) | (data[pos+1] << 8) | data[pos+2];
        uint8_t type = data[pos+3];
        // uint8_t flags = data[pos+4];
        // uint32_t stream_id = ntohl(*(uint32_t*)(data + pos + 5)) & 0x7FFFFFFF;

        if (pos + HTTP2_FRAME_HEADER_LEN + payload_len > len) break;

        frames++;
        if (type == HTTP2_HEADERS_FRAME && payload_len > 0) {
            headers++;
            const uint8_t *payload = data + pos + HTTP2_FRAME_HEADER_LEN;

            // HPACK Decoding mit nghttp2
            if (!sess->inflater) {
                if (nghttp2_hd_inflate_new(&sess->inflater) != 0) {
                    syslog(LOG_ERR, "nghttp2_hd_inflate_new failed");
                    break;
                }
            }

            int inflate_flags = 0;
            size_t inlen = payload_len;
            const uint8_t *in = payload;
            while (inlen > 0) {
                nghttp2_nv nv;
                nghttp2_ssize rv = nghttp2_hd_inflate_hd3(sess->inflater, &nv, &inflate_flags, in, inlen, 1);  // final=1 für vollständigen Block
                if (rv < 0) {
                    syslog(LOG_WARNING, "HPACK Decode Fehler: %s", nghttp2_strerror((int)rv));
                    break;
                }
                in += rv;
                inlen -= rv;

                if (inflate_flags & NGHTTP2_HD_INFLATE_EMIT) {
                    on_header_callback(&nv, sess);  // Verarbeite dekodierten Header
                }

                if (inflate_flags & NGHTTP2_HD_INFLATE_FINAL) {
                    nghttp2_hd_inflate_end_headers(sess->inflater);
                    break;
                }
            }

            // Entropy auf komprimierter Payload
            if (payload_len > 32) {
                entropy_sum += shannon_entropy(payload, payload_len > 256 ? 256 : payload_len);
                blocks++;
            }
        }

        pos += HTTP2_FRAME_HEADER_LEN + payload_len;
    }

    sess->http2_frames += frames;
    sess->http2_headers += headers;

    if (frames == 0) return;

    char ip_str[INET6_ADDRSTRLEN];
    inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&src_ip->v4 : (void*)&src_ip->v6, ip_str, sizeof(ip_str));

    double avg_entropy = blocks ? entropy_sum / blocks : 0.0;

    if (frames > 50 || headers > 20 || avg_entropy > 4.0 || sess->http2_headers > 10) {  // Erweitert um HPACK-Anomalien
        syslog(LOG_WARNING, "HTTP/2 ANOMALY: %d frames, %d headers, entropy=%.2f von %s", frames, headers, avg_entropy, ip_str);
        update_rate(af, src_ip, 0);
    }
}

// --- Shannon Entropy ---
double shannon_entropy(const uint8_t *data, size_t len) {
    if (len == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < len; i++) freq[data[i]]++;
    double e = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i]) {
            double p = (double)freq[i] / len;
            e -= p * log2(p);
        }
    }
    return e;
}

// --- TCP Session: HTTP/2 Erkennung + Analyse ---
void process_tcp_payload(tcp_session *sess, const u_char *payload, int payload_len, af_t af, ip_addr *src_ip) {
    if (payload_len <= 0 || !sess->data) return;

    if (sess->data_len + payload_len > sess->alloc_len) {
        size_t new_size = sess->alloc_len * 2;
        char *new_data = realloc(sess->data, new_size);
        if (!new_data) {
            syslog(LOG_ERR, "Realloc failed for TCP session");
            return;
        }
        sess->data = new_data;
        sess->alloc_len = new_size;
    }

    memcpy(sess->data + sess->data_len, payload, payload_len);
    sess->data_len += payload_len;

    // --- HTTP/2 Erkennung (nur einmal) ---
    if (!sess->is_http2 && sess->data_len >= HTTP2_MAGIC_LEN) {
        if (is_http2_magic(sess->data)) {
            sess->is_http2 = 1;
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&src_ip->v4 : (void*)&src_ip->v6, ip_str, sizeof(ip_str));
            syslog(LOG_INFO, "HTTP/2 (h2c) erkannt von %s", ip_str);
        }
    }

    if (!sess->is_http2 && sess->data_len >= 60 && sess->data[0] == TLS_HANDSHAKE) {
        if (parse_tls_client_hello((uint8_t*)sess->data, sess->data_len)) {
            sess->is_http2 = 1;
            char ip_str[INET6_ADDRSTRLEN];
            inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&src_ip->v4 : (void*)&src_ip->v6, ip_str, sizeof(ip_str));
            syslog(LOG_INFO, "HTTP/2 (h2/TLS) erkannt via ALPN von %s", ip_str);
        }
    }

    // --- HTTP/2 Analyse mit HPACK ---
    if (sess->is_http2 && sess->data_len >= HTTP2_FRAME_HEADER_LEN) {
        analyze_http2((uint8_t*)sess->data, sess->data_len, af, src_ip, sess);
    }

    // --- HTTP/1.1 Exploit-Erkennung ---
    if (!sess->is_http2 && sess->data_len > 8 &&
        (strncmp(sess->data, "GET ", 4) == 0 || strncmp(sess->data, "POST ", 5) == 0)) {
        char ip_str[INET6_ADDRSTRLEN];
        inet_ntop(af == AF_4 ? AF_INET : AF_INET6, af == AF_4 ? (void*)&src_ip->v4 : (void*)&src_ip->v6, ip_str, sizeof(ip_str));
        syslog(LOG_INFO, "HTTP/1.1 Request von %s", ip_str);

        int nop = 0, nonprint = 0;
        for (size_t i = 0; i < sess->data_len; i++) {
            if (sess->data[i] == 0x90) nop++;
            if (!isprint(sess->data[i]) && !strchr("\r\n\t ", sess->data[i])) nonprint++;
        }
        if (nop > 10 || (double)nonprint / sess->data_len > 0.6 || sess->data_len > 3000) {
            syslog(LOG_WARNING, "L7 Exploit (HTTP/1.1) von %s", ip_str);
            update_rate(af, src_ip, 0);
        }
    }
}

// --- IPv6 Extension Headers überspringen ---
int skip_ipv6_ext_headers(const u_char *payload, int offset, uint8_t *next_proto) {
    while (1) {
        switch (*next_proto) {
            case IPPROTO_HOPOPTS: case IPPROTO_ROUTING: case IPPROTO_FRAGMENT:
            case IPPROTO_DSTOPTS: case IPPROTO_MH:
                *next_proto = payload[offset];
                offset += (payload[offset + 1] + 1) * 8;
                break;
            default:
                return offset;
        }
        if (offset > 1500) return -1;  // Vermeide Endlosschleifen
    }
}

// --- Packet Handler ---
void packet_handler(u_char *user, const struct pcap_pkthdr *h, const u_char *bytes) {
    (void)user;
    if (h->caplen < sizeof(struct ether_header) + 40) return;

    const struct ether_header *eth = (struct ether_header*)bytes;
    uint16_t eth_type = ntohs(eth->ether_type);
    if (eth_type != ETHERTYPE_IP && eth_type != ETHERTYPE_IPV6) return;

    af_t af;
    int header_len = 0;
    uint8_t proto = 0;
    ip_addr src_ip, dst_ip;
    const u_char *payload = NULL;
    int payload_len = 0;

    // --- IPv4 Parsing ---
    if (eth_type == ETHERTYPE_IP) {
        const struct ip *ip4 = (struct ip*)(bytes + sizeof(struct ether_header));
        if (h->caplen < sizeof(struct ether_header) + ip4->ip_hl * 4) return;
        if (ip4->ip_v != 4 || (ip4->ip_off & htons(IP_MF | IP_OFFMASK))) return;

        af = AF_4;
        src_ip.v4 = ip4->ip_src.s_addr;
        dst_ip.v4 = ip4->ip_dst.s_addr;
        header_len = ip4->ip_hl * 4;
        proto = ip4->ip_p;
        payload = bytes + sizeof(struct ether_header) + header_len;
        payload_len = ntohs(ip4->ip_len) - header_len;

    // --- IPv6 Parsing ---
    } else {
        const struct ip6_hdr *ip6 = (struct ip6_hdr*)(bytes + sizeof(struct ether_header));
        af = AF_6;
        src_ip.v6 = ip6->ip6_src;
        dst_ip.v6 = ip6->ip6_dst;
        header_len = 40;
        proto = ip6->ip6_nxt;

        int off = skip_ipv6_ext_headers(bytes + sizeof(struct ether_header) + 40, 40, &proto);
        if (off < 0) return;
        header_len = off;
        payload = bytes + sizeof(struct ether_header) + header_len;
        payload_len = ntohs(ip6->ip6_plen) - (header_len - 40);
    }

    if (is_ip_blocked(af, &src_ip)) return;

    // --- TCP Handling ---
    if (proto == IPPROTO_TCP && payload_len >= 20) {
        const struct tcphdr *tcp = (struct tcphdr*)payload;
        uint16_t sport = ntohs(tcp->source);
        uint16_t dport = ntohs(tcp->dest);
        int tcp_hl = tcp->doff * 4;
        if (payload_len < tcp_hl) return;

        tcp_session *sess = NULL;
        pthread_mutex_lock(&lock);
        for (tcp_session *s = tcp_sessions; s; s = s->next) {
            if (s->af == af && s->src_port == sport && s->dst_port == dport &&
                memcmp(&s->src_ip, &src_ip, af == AF_4 ? 4 : 16) == 0) {
                sess = s; break;
            }
        }

        if (!sess) {
            sess = calloc(1, sizeof(tcp_session));
            if (sess) {
                sess->af = af; sess->src_ip = src_ip; sess->dst_ip = dst_ip;
                sess->src_port = sport; sess->dst_port = dport;
                sess->alloc_len = 32768; sess->data = malloc(sess->alloc_len);
                if (!sess->data) {
                    free(sess);
                    sess = NULL;
                } else {
                    sess->next = tcp_sessions;
                    tcp_sessions = sess;
                }
            }
        }
        pthread_mutex_unlock(&lock);

        if (!sess) return;

        sess->last_seen = time(NULL);
        const u_char *data = payload + tcp_hl;
        int data_len = payload_len - tcp_hl;

        if (data_len > 0) {
            process_tcp_payload(sess, data, data_len, af, &src_ip);
        }

    // --- UDP/DNS Handling ---
    } else if (proto == IPPROTO_UDP && payload_len >= 8) {
        const struct udphdr *udp = (struct udphdr*)payload;
        uint16_t sport = ntohs(udp->source);
        uint16_t dport = ntohs(udp->dest);
        if (sport == 53 || dport == 53) {
            analyze_dns(payload + 8, payload_len - 8, af, &src_ip);
            update_rate(af, &src_ip, 1);
        }
    }
}

// --- Session Cleanup Thread ---
void *session_cleanup_thread(void *arg) {
    (void)arg;
    while (running) {
        sleep(CLEANUP_INTERVAL);
        pthread_mutex_lock(&lock);
        tcp_session *prev = NULL, *next;
        time_t now = time(NULL);
        for (tcp_session *s = tcp_sessions; s; s = next) {
            next = s->next;
            if (now - s->last_seen > SESSION_TIMEOUT) {
                if (prev) prev->next = next;
                else tcp_sessions = next;
                if (s->inflater) nghttp2_hd_inflate_del(s->inflater);  // Neu: Inflater freigeben
                free(s->data);
                free(s);
            } else {
                prev = s;
            }
        }
        pthread_mutex_unlock(&lock);
    }
    return NULL;
}

// --- Main ---
int main(int argc, char **argv) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <interface>\n", argv[0]);
        return 1;
    }

    openlog("firewall_l7", LOG_PID | LOG_CONS, LOG_DAEMON);
    load_config();
    load_blacklist();

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    char errbuf[PCAP_ERRBUF_SIZE];
    handle = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
    if (!handle) {
        syslog(LOG_ERR, "pcap_open_live: %s", errbuf);
        closelog();
        return 1;
    }

    struct bpf_program fp;
    if (pcap_compile(handle, &fp, "ip or ip6", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle, &fp) == -1) {
        syslog(LOG_ERR, "Filter error: %s", pcap_geterr(handle));
        pcap_close(handle);
        closelog();
        return 1;
    }
    pcap_freecode(&fp);

    if (pthread_create(&cleanup_thread, NULL, session_cleanup_thread, NULL) != 0) {
        syslog(LOG_ERR, "Failed to start cleanup thread");
    }

    syslog(LOG_INFO, "L7 Firewall mit HTTP/2-Support und HPACK-Decoding gestartet auf %s", argv[1]);
    printf("Firewall L7 + HTTP/2 + HPACK läuft auf %s – Strg+C zum Beenden\n", argv[1]);

    pcap_loop(handle, -1, packet_handler, NULL);

    running = 0;
    pthread_join(cleanup_thread, NULL);
    pcap_close(handle);
    closelog();
    return 0;
}
