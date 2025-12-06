#include <ncurses.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

// ===================== COLORS =============================
#define PAIR_NORMAL     1
#define PAIR_ACCENT_BG  2
#define PAIR_RED_FG     3
#define PAIR_GREEN_FG   4

// ===================== LOGGING ===========================
#define MAX_LOG_ENTRIES 2048

typedef struct {
    char time[32];
    char method[16];
    int status;
    char domain[128];
    char size[32];
} LogEntry;

LogEntry entries[MAX_LOG_ENTRIES];
int entry_count = 0;
pthread_mutex_t log_mutex = PTHREAD_MUTEX_INITIALIZER;

// ===================== TLS KEY STORE ======================
#define MAX_TLS_SESSIONS 4096
typedef struct {
    unsigned char client_random[32];
    unsigned char master_secret[48];
    int valid;
} TlsKey;

TlsKey tls_keys[MAX_TLS_SESSIONS];
int tls_key_count = 0;
pthread_mutex_t tls_key_mutex = PTHREAD_MUTEX_INITIALIZER;

char sslkeylog_path[512] = {0};

// ===================== LAST PAYLOAD ======================
unsigned char last_payload[65536];
int last_payload_len = 0;
pthread_mutex_t payload_mutex = PTHREAD_MUTEX_INITIALIZER;

// ===================== LOG FUNCTIONS =====================
void add_log_entry(const char *time, const char *method, int status,
                   const char *domain, const char *size)
{
    pthread_mutex_lock(&log_mutex);
    int i = entry_count % MAX_LOG_ENTRIES;
    snprintf(entries[i].time, sizeof(entries[i].time), "%s", time);
    snprintf(entries[i].method, sizeof(entries[i].method), "%s", method);
    entries[i].status = status;
    snprintf(entries[i].domain, sizeof(entries[i].domain), "%s", domain);
    snprintf(entries[i].size, sizeof(entries[i].size), "%s", size);
    entry_count++;
    pthread_mutex_unlock(&log_mutex);
}

// ===================== SSLKEYLOG ==========================
static void load_sslkeylogfile()
{
    const char *path = getenv("SSLKEYLOGFILE");
    if (!path) return;

    snprintf(sslkeylog_path, sizeof(sslkeylog_path), "%s", path);

    FILE *f = fopen(path, "r");
    if (!f) return;

    char line[512];
    pthread_mutex_lock(&tls_key_mutex);

    while (fgets(line, sizeof(line), f)) {
        unsigned char cr[32], ms[48];
        char cr_hex[65], ms_hex[97];
        if (sscanf(line, "CLIENT_RANDOM %64s %96s", cr_hex, ms_hex) == 2) {
            if (strlen(cr_hex) != 64 || strlen(ms_hex) != 96)
                continue;

            for (int i = 0; i < 32; i++)
                sscanf(&cr_hex[i*2], "%2hhx", &cr[i]);
            for (int i = 0; i < 48; i++)
                sscanf(&ms_hex[i*2], "%2hhx", &ms[i]);

            if (tls_key_count < MAX_TLS_SESSIONS) {
                memcpy(tls_keys[tls_key_count].client_random, cr, 32);
                memcpy(tls_keys[tls_key_count].master_secret, ms, 48);
                tls_keys[tls_key_count].valid = 1;
                tls_key_count++;
            }
        }
    }

    pthread_mutex_unlock(&tls_key_mutex);
    fclose(f);
}

// ===================== TLS KEY LOOKUP =====================
static TlsKey *find_tls_key(const unsigned char *client_random)
{
    pthread_mutex_lock(&tls_key_mutex);
    for (int i = 0; i < tls_key_count; i++) {
        if (!tls_keys[i].valid) continue;
        if (memcmp(tls_keys[i].client_random, client_random, 32) == 0) {
            pthread_mutex_unlock(&tls_key_mutex);
            return &tls_keys[i];
        }
    }
    pthread_mutex_unlock(&tls_key_mutex);
    return NULL;
}

// ===================== TLS CLIENTHELLO ====================
static int extract_client_random(const u_char *payload, int len, unsigned char *out32)
{
    if (len < 11 + 32) return 0;
    if (payload[0] != 22) return 0;
    if (payload[5] != 1) return 0;
    memcpy(out32, payload + 11, 32);
    return 1;
}

// ===================== HTTP HELPERS =======================
char *extract_http_method(const u_char *payload) {
    if (!strncmp((char*)payload, "GET", 3)) return "GET";
    if (!strncmp((char*)payload, "POST", 4)) return "POST";
    if (!strncmp((char*)payload, "HEAD", 4)) return "HEAD";
    if (!strncmp((char*)payload, "CONNECT", 7)) return "CONNECT";
    return "OTHER";
}

char *extract_host(const u_char *payload) {
    static char host[128];
    memset(host, 0, sizeof(host));
    const char *p = strstr((char*)payload, "Host: ");
    if (p) sscanf(p, "Host: %127s", host);
    return host[0] ? host : "unknown";
}

// ===================== PACKET TYPE ========================
typedef enum { PKT_HTTP, PKT_TLS, PKT_OTHER } PacketType;
PacketType detect_protocol(const u_char *p, int len) {
    if (len < 1) return PKT_OTHER;
    if (p[0] == 22) return PKT_TLS;
    if (!strncmp((char*)p, "GET ", 4) ||
        !strncmp((char*)p, "POST ", 5) ||
        !strncmp((char*)p, "HEAD ", 5) ||
        !strncmp((char*)p, "HTTP/", 5))
        return PKT_HTTP;
    return PKT_OTHER;
}

// ===================== HTTP DETAILS ======================
void draw_http_details(WINDOW *win, const char *payload) {
    mvwprintw(win, 7, 2, "HTTP Packet:");
    mvwprintw(win, 8, 4, "%.*s", strcspn(payload, "\r\n"), payload);

    int y = 10;
    const char *line = payload;
    while (*line && y < 22) {
        const char *next = strstr(line, "\r\n");
        if (!next) break;
        int len = next - line;
        if (len == 0) break;
        mvwprintw(win, y++, 4, "%.*s", len, line);
        line = next + 2;
    }
}

// ===================== HEXDUMP ===========================
void draw_hexdump(WINDOW *win, int starty, const u_char *data, int len) {
    int row = starty;
    for (int i = 0; i < len; i += 16) {
        mvwprintw(win, row, 2, "%04x  ", i);
        for (int j = 0; j < 16; j++)
            wprintw(win, "%02x ", (i + j < len) ? data[i+j] : 0x00);
        wprintw(win, " |");
        for (int j = 0; j < 16; j++) {
            unsigned char c = (i + j < len) ? data[i+j] : '.';
            wprintw(win, "%c", isprint(c) ? c : '.');
        }
        wprintw(win, "|");
        row++;
    }
}

// ===================== PACKET HANDLER ====================
void packet_handler(u_char *args, const struct pcap_pkthdr *header,
                    const u_char *packet)
{
    const u_char *payload = packet + 54;
    int len = header->len - 54;
    if (len <= 0) return;

    pthread_mutex_lock(&payload_mutex);
    memcpy(last_payload, payload, len);
    last_payload_len = len;
    pthread_mutex_unlock(&payload_mutex);

    char timebuf[32];
    snprintf(timebuf, sizeof(timebuf), "%ld", header->ts.tv_sec);

    unsigned char client_random[32];
    if (extract_client_random(payload, len, client_random)) {
        TlsKey *key = find_tls_key(client_random);
        if (key)
            add_log_entry(timebuf, "TLS", 200, "TLS (SSLKEYLOGFILE key found)", "Encrypted");
        else
            add_log_entry(timebuf, "TLS", 0, "TLS (no key available)", "Encrypted");
        return;
    }

    const char *method = extract_http_method(payload);
    const char *host = extract_host(payload);
    char sizebuf[32];
    snprintf(sizebuf, sizeof(sizebuf), "%d B", header->len);
    add_log_entry(timebuf, method, 0, host, sizebuf);
}

// ===================== PCAP THREAD =======================
void *capture_thread(void *arg) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs, *d;

    if (pcap_findalldevs(&alldevs, errbuf) == -1) return NULL;

    char devname[128] = {0};
    for (d = alldevs; d; d = d->next)
        if (!(d->flags & PCAP_IF_LOOPBACK)) {
            snprintf(devname, sizeof(devname), "%s", d->name);
            break;
        }
    pcap_freealldevs(alldevs);
    if (!devname[0]) return NULL;

    pcap_t *handle = pcap_open_live(devname, 65535, 1, 10, errbuf);
    if (!handle) return NULL;

    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);
    return NULL;
}

// ===================== UI FUNCTIONS ======================
void init_colors() {
    start_color();
    init_pair(PAIR_NORMAL, COLOR_WHITE, COLOR_BLACK);
    init_pair(PAIR_ACCENT_BG, COLOR_BLACK, COLOR_RED);
    init_pair(PAIR_RED_FG, COLOR_RED, COLOR_BLACK);
    init_pair(PAIR_GREEN_FG, COLOR_GREEN, COLOR_BLACK);
    bkgd(COLOR_PAIR(PAIR_NORMAL));
}

void draw_traffic_log(WINDOW *win, int selected) {
    int y, x;
    getmaxyx(win, y, x);

    wattron(win, COLOR_PAIR(PAIR_RED_FG));
    box(win, 0, 0);
    mvwprintw(win, 0, 2, " Live Network Traffic Log ");
    wattroff(win, COLOR_PAIR(PAIR_RED_FG));

    pthread_mutex_lock(&log_mutex);
    int start = (entry_count > y - 3) ? entry_count - (y - 3) : 0;
    int row = 1;

    for (int i = start; i < entry_count && row < y - 1; i++, row++) {
        LogEntry *e = &entries[i % MAX_LOG_ENTRIES];
        if (i == selected)
            wattron(win, COLOR_PAIR(PAIR_ACCENT_BG) | A_BOLD);
        else
            wattron(win, COLOR_PAIR(PAIR_NORMAL));

        mvwprintw(win, row, 1,
                  "%-10s %-7s %-30s %-8s",
                  e->time, e->method, e->domain, e->size);

        if (i == selected)
            wattroff(win, COLOR_PAIR(PAIR_ACCENT_BG) | A_BOLD);
        else
            wattroff(win, COLOR_PAIR(PAIR_NORMAL));
    }
    pthread_mutex_unlock(&log_mutex);
}

void draw_details_panel(WINDOW *win, int selected) {
    int y, x;
    getmaxyx(win, y, x);

    wattron(win, COLOR_PAIR(PAIR_RED_FG));
    box(win, 0, 0);
    mvwprintw(win, 0, 2, " Details ");
    wattroff(win, COLOR_PAIR(PAIR_RED_FG));

    if (entry_count == 0) {
        mvwprintw(win, 2, 2, "Waiting for traffic...");
        return;
    }

    if (selected >= entry_count) selected = entry_count - 1;
    LogEntry *e = &entries[selected % MAX_LOG_ENTRIES];

    mvwprintw(win, 2, 2, "Time:   %s", e->time);
    mvwprintw(win, 3, 2, "Method: %s", e->method);
    mvwprintw(win, 4, 2, "Domain: %s", e->domain);
    mvwprintw(win, 5, 2, "Size:   %s", e->size);

    pthread_mutex_lock(&payload_mutex);
    int len = last_payload_len;
    unsigned char *data = last_payload;
    pthread_mutex_unlock(&payload_mutex);

    if (len <= 0) return;

    PacketType type = detect_protocol(data, len);
    switch (type) {
        case PKT_HTTP: draw_http_details(win, (char*)data); break;
        case PKT_TLS: mvwprintw(win, 7, 2, "TLS Packet (Encrypted)"); break;
        default: mvwprintw(win, 7, 2, "Unknown protocol"); break;
    }

    mvwprintw(win, 22, 2, "Hexdump:");
    draw_hexdump(win, 23, data, len);
}

void draw_control_bar(WINDOW *win) {
    int y, x;
    getmaxyx(win, y, x);
    wattron(win, COLOR_PAIR(PAIR_RED_FG));
    mvwhline(win, 0, 0, ACS_HLINE, x);
    wattroff(win, COLOR_PAIR(PAIR_RED_FG));

    if (sslkeylog_path[0])
        mvwprintw(win, 1, 2, "[↑/↓] Navigate   [Q] Exit   | SSLKEYLOGFILE loaded");
    else
        mvwprintw(win, 1, 2, "[↑/↓] Navigate   [Q] Exit   | No SSLKEYLOGFILE");
}

// ===================== MAIN =============================
int main() {
    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(100);

    init_colors();
    load_sslkeylogfile();

    pthread_t cap_thread;
    pthread_create(&cap_thread, NULL, capture_thread, NULL);
    pthread_detach(cap_thread);

    int selected = 0;
    while (1) {
        int max_y, max_x;
        getmaxyx(stdscr, max_y, max_x);

        int log_h = max_y * 0.5;
        int det_h = max_y * 0.4;
        int ctl_h = max_y - log_h - det_h;

        WINDOW *log_win = newwin(log_h, max_x, 0, 0);
        WINDOW *det_win = newwin(det_h, max_x, log_h, 0);
        WINDOW *ctl_win = newwin(ctl_h, max_x, log_h + det_h, 0);

        int ch = getch();
        if (ch == 'q' || ch == 'Q') break;
        if (ch == KEY_UP && selected > 0) selected--;
        if (ch == KEY_DOWN && selected < entry_count - 1) selected++;

        werase(log_win);
        werase(det_win);
        werase(ctl_win);

        draw_traffic_log(log_win, selected);
        draw_details_panel(det_win, selected);
        draw_control_bar(ctl_win);

        wrefresh(log_win);
        wrefresh(det_win);
        wrefresh(ctl_win);

        delwin(log_win);
        delwin(det_win);
        delwin(ctl_win);
    }

    endwin();
    return 0;
}
