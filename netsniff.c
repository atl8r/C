/*  ===========================
    Stable Network Sniffer UI
    With -o output.txt
    Base64 Payload Logging
    Stable Window Rendering
    ===========================
*/

#include <ncurses.h>
#include <string.h>
#include <stdlib.h>
#include <pthread.h>
#include <pcap.h>
#include <ctype.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <errno.h>
#include <stdint.h>

// ==========================================================
//  CONFIG / COLORS
// ==========================================================
#define PAIR_NORMAL     1
#define PAIR_ACCENT_BG  2
#define PAIR_RED_FG     3
#define PAIR_GREEN_FG   4

// ==========================================================
//  LOGGING
// ==========================================================
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

// Output file support:
static FILE *outfile = NULL;

// ==========================================================
//  TLS KEY STORE
// ==========================================================
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

// ==========================================================
//  LAST PAYLOAD
// ==========================================================
unsigned char last_payload[65536];
int last_payload_len = 0;

pthread_mutex_t payload_mutex = PTHREAD_MUTEX_INITIALIZER;

// ==========================================================
//  BASE64 ENCODE
// ==========================================================
static const char b64chars[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *src, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;) {
        uint32_t a = i < len ? src[i++] : 0;
        uint32_t b = i < len ? src[i++] : 0;
        uint32_t c = i < len ? src[i++] : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        out[j++] = b64chars[(triple >> 18) & 0x3F];
        out[j++] = b64chars[(triple >> 12) & 0x3F];
        out[j++] = b64chars[(triple >> 6) & 0x3F];
        out[j++] = b64chars[(triple >> 0) & 0x3F];
    }

    int mod = len % 3;
    if (mod) {
        out[out_len - 1] = '=';
        if (mod == 1) out[out_len - 2] = '=';
    }

    out[out_len] = 0;
    return out;
}

// ==========================================================
//  LOG FUNCTIONS
// ==========================================================
void append_log_to_file(const char *time, const char *method, int status,
                        const char *domain, const char *size,
                        const unsigned char *payload, int payload_len)
{
    if (!outfile) return;

    char *b64 = base64_encode(payload, payload_len);
    if (!b64) return;

    fprintf(outfile,
            "%s | %s | %d | %s | %s | payload_b64: %s\n",
            time, method, status, domain, size, b64);
    fflush(outfile);
    free(b64);
}

void add_log_entry(const char *time, const char *method, int status,
                   const char *domain, const char *size,
                   const unsigned char *payload, int payload_len)
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

    append_log_to_file(time, method, status, domain, size, payload, payload_len);
}

// ==========================================================
//  SSL KEYLOG
// ==========================================================
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
                sscanf(&cr_hex[i * 2], "%2hhx", &cr[i]);
            for (int i = 0; i < 48; i++)
                sscanf(&ms_hex[i * 2], "%2hhx", &ms[i]);

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

// ==========================================================
//  PACKET HANDLER
// ==========================================================
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

    const char *method = "OTHER";
    const char *domain = "unknown";

    if (!strncmp((char*)payload, "GET", 3)) method = "GET";
    else if (!strncmp((char*)payload, "POST", 4)) method = "POST";

    const char *p = strstr((char*)payload, "Host: ");
    char host[128] = {0};
    if (p) sscanf(p, "Host: %127s", host);

    if (host[0]) domain = host;

    char sizebuf[32];
    snprintf(sizebuf, sizeof(sizebuf), "%d B", header->len);

    add_log_entry(timebuf, method, 0, domain, sizebuf, payload, len);
}

// ==========================================================
//  PCAP THREAD
// ==========================================================
void *capture_thread(void *arg)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t *alldevs, *d;
    if (pcap_findalldevs(&alldevs, errbuf) == -1)
        return NULL;

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

// ==========================================================
//  DRAWING FUNCTIONS (optimized)
// ==========================================================
void draw_traffic_log(WINDOW *win, int selected) {
    werase(win);
    box(win, 0, 0);

    pthread_mutex_lock(&log_mutex);
    int max_y, max_x;
    getmaxyx(win, max_y, max_x);

    int start = (entry_count > max_y - 3) ? entry_count - (max_y - 3) : 0;
    int row = 1;

    for (int i = start; i < entry_count && row < max_y - 1; i++, row++) {
        LogEntry *e = &entries[i % MAX_LOG_ENTRIES];

        if (i == selected)
            wattron(win, COLOR_PAIR(PAIR_ACCENT_BG) | A_BOLD);

        mvwprintw(win, row, 1, "%s %-6s %-25s %s",
                  e->time, e->method, e->domain, e->size);

        if (i == selected)
            wattroff(win, COLOR_PAIR(PAIR_ACCENT_BG) | A_BOLD);
    }
    pthread_mutex_unlock(&log_mutex);

    wrefresh(win);
}

void draw_details(WINDOW *win, int selected) {
    werase(win);
    box(win, 0, 0);

    pthread_mutex_lock(&log_mutex);
    if (entry_count == 0) {
        mvwprintw(win, 2, 2, "Waiting for traffic...");
        pthread_mutex_unlock(&log_mutex);
        wrefresh(win);
        return;
    }
    if (selected >= entry_count) selected = entry_count - 1;

    LogEntry *e = &entries[selected % MAX_LOG_ENTRIES];
    pthread_mutex_unlock(&log_mutex);

    mvwprintw(win, 2, 2, "Time:   %s", e->time);
    mvwprintw(win, 3, 2, "Method: %s", e->method);
    mvwprintw(win, 4, 2, "Domain: %s", e->domain);
    mvwprintw(win, 5, 2, "Size:   %s", e->size);

    pthread_mutex_lock(&payload_mutex);
    int len = last_payload_len;
    unsigned char *data = last_payload;
    pthread_mutex_unlock(&payload_mutex);

    mvwprintw(win, 7, 2, "Raw Payload (%d bytes):", len);
    int row = 9;
    for (int i = 0; i < len && row < 28; i += 16) {
        wmove(win, row++, 2);
        for (int j = 0; j < 16; j++) {
            if (i + j < len) wprintw(win, "%02x ", data[i + j]);
            else wprintw(win, "   ");
        }
    }

    wrefresh(win);
}

void draw_control(WINDOW *win) {
    werase(win);
    mvwprintw(win, 1, 2, "[↑/↓] Navigate  [PgUp/PgDn] Fast Scroll  [Q] Exit");
    if (sslkeylog_path[0])
        mvwprintw(win, 2, 2, "SSLKEYLOGFILE: %s", sslkeylog_path);
    else
        mvwprintw(win, 2, 2, "No SSLKEYLOGFILE loaded");

    wrefresh(win);
}

// ==========================================================
//  MAIN
// ==========================================================
int main(int argc, char **argv)
{
    // --- parse -o file.txt ---
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "-o") && i + 1 < argc) {
            outfile = fopen(argv[i + 1], "a");  // append mode
        }
    }

    initscr();
    cbreak();
    noecho();
    keypad(stdscr, TRUE);
    curs_set(0);
    timeout(100);

    start_color();
    init_pair(PAIR_NORMAL, COLOR_WHITE, COLOR_BLACK);
    init_pair(PAIR_ACCENT_BG, COLOR_BLACK, COLOR_RED);
    init_pair(PAIR_RED_FG, COLOR_RED, COLOR_BLACK);

    load_sslkeylogfile();

    pthread_t t;
    pthread_create(&t, NULL, capture_thread, NULL);
    pthread_detach(t);

    int selected = 0;

    int max_y, max_x;
    getmaxyx(stdscr, max_y, max_x);

    int log_h = max_y * 0.5;
    int det_h = max_y * 0.4;

    WINDOW *logwin = newwin(log_h, max_x, 0, 0);
    WINDOW *detwin = newwin(det_h, max_x, log_h, 0);
    WINDOW *ctlwin = newwin(max_y - log_h - det_h, max_x, log_h + det_h, 0);

    while (1) {
        int ch = getch();

        if (ch == 'q' || ch == 'Q') break;

        // Navigation
        if (ch == KEY_UP && selected > 0) selected--;
        else if (ch == KEY_DOWN && selected < entry_count - 1) selected++;
        else if (ch == KEY_NPAGE) selected += 10;       // PageDown
        else if (ch == KEY_PPAGE) selected -= 10;       // PageUp
        else if (ch == KEY_HOME) selected = 0;
        else if (ch == KEY_END) selected = entry_count - 1;

        if (selected < 0) selected = 0;
        if (selected >= entry_count) selected = entry_count - 1;

        draw_traffic_log(logwin, selected);
        draw_details(detwin, selected);
        draw_control(ctlwin);
    }

    endwin();
    if (outfile) fclose(outfile);
    return 0;
}
