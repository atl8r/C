// crawler.c
// Features:
//  - Header Recon
//  - DNS Recon (A, AAAA, NS, TXT)
//  - API Endpoint Scanner
//  - HTML Crawler

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <curl/curl.h>
#include <gumbo.h>

#include <resolv.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#define MAX_URLS 30000
#define MAX_DEPTH 6

char base_domain[256];
char *visited[MAX_URLS];
int visited_count = 0;

FILE *out_file;
FILE *ep_file;
FILE *dns_file;

int current_depth = 0;

/*
 * CURL write callback
 */
size_t write_cb(void *data, size_t size, size_t nmemb, void *userdata) {
    size_t total = size * nmemb;
    char **html = (char**)userdata;

    if (*html == NULL) {
        *html = calloc(total + 1, 1);
        memcpy(*html, data, total);
    } else {
        size_t old_len = strlen(*html);
        *html = realloc(*html, old_len + total + 1);
        memcpy(*html + old_len, data, total);
        (*html)[old_len + total] = '\0';
    }
    return total;
}

/*
 * Logging
 */
void log_url(const char *type, const char *url) {
    char ts[64];
    time_t now = time(NULL);
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(out_file, "[%s] %s │ %s\n", ts, type, url);
    fflush(out_file);
}

/*
 * Visited list management
 */
int url_visited(const char *url) {
    for (int i = 0; i < visited_count; i++) {
        if (strcmp(visited[i], url) == 0)
            return 1;
    }
    return 0;
}

void add_visited(const char *url) {
    if (visited_count < MAX_URLS && !url_visited(url)) {
        visited[visited_count++] = strdup(url);
    }
}

int is_internal(const char *url) {
    return strstr(url, base_domain) != NULL;
}

/*
 * DNS Recon
 */
void do_dns_recon(const char *domain) {
    fprintf(dns_file, "# DNS Recon für: %s\n\n", domain);

    // A Records
    struct hostent *host = gethostbyname(domain);
    if (host) {
        fprintf(dns_file, "A Records:\n");
        for (int i = 0; host->h_addr_list[i]; i++) {
            char ipbuf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, host->h_addr_list[i], ipbuf, sizeof(ipbuf));
            fprintf(dns_file, " - %s\n", ipbuf);
        }
        fprintf(dns_file, "\n");
    }

    // AAAA Records
    struct addrinfo hints = {0}, *res;
    hints.ai_family = AF_UNSPEC;

    fprintf(dns_file, "AAAA / NS Records:\n");
    if (getaddrinfo(domain, NULL, &hints, &res) == 0) {
        struct addrinfo *p = res;
        char hostbuf[256];

        while (p) {
            getnameinfo(p->ai_addr, p->ai_addrlen,
                        hostbuf, sizeof(hostbuf),
                        NULL, 0, NI_NUMERICHOST);
            fprintf(dns_file, " - %s\n", hostbuf);
            p = p->ai_next;
        }
        freeaddrinfo(res);
        fprintf(dns_file, "\n");
    }

    // TXT Records
    fprintf(dns_file, "TXT Records:\n");
    unsigned char answer[4096];
    int len = res_query(domain, C_IN, T_TXT, answer, sizeof(answer));
    if (len > 0)
        fprintf(dns_file, " - TXT data received (%d bytes)\n", len);
    else
        fprintf(dns_file, " - no TXT\n");

    fprintf(dns_file, "\n---------------------------------\n\n");
    fflush(dns_file);
}

/*
 * HEADER Recon
 */
size_t header_cb(char *buffer, size_t size, size_t nitems, void *userdata) {
    FILE *hf = (FILE*)userdata;
    size_t len = size * nitems;
    fprintf(hf, "%.*s", (int)len, buffer);
    return len;
}

void do_header_recon(const char *url) {
    char filename[512];
    snprintf(filename, sizeof(filename), "headers_%s.txt", base_domain);

    FILE *hf = fopen(filename, "a");
    if (!hf) return;

    CURL *curl = curl_easy_init();
    if (!curl) { fclose(hf); return; }

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_cb);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, hf);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ReconCrawler/1.0");

    curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(hf);
}

/*
 * API Endpoint Scanner
 */
int is_api_endpoint(const char *url) {
    const char *pats[] = {
        "/api/", "/v1/", "/v2/", "/v3/", "/rest/",
        "/graphql", "/auth/", "/token",
        "/user/", "/admin/api", "/login",
        NULL
    };
    for (int i = 0; pats[i]; i++) {
        if (strstr(url, pats[i])) return 1;
    }
    return 0;
}

void save_endpoint(const char *ep) {
    static char *saved[10000];
    static int ep_count = 0;

    for (int i = 0; i < ep_count; i++) {
        if (strcmp(saved[i], ep) == 0) return;
    }

    saved[ep_count++] = strdup(ep);
    fprintf(ep_file, "%s\n", ep);
    fflush(ep_file);
}

/*
 * JS Scanner
 */
void scan_js_for_api(const char *js) {
    const char *p = js;
    while ((p = strstr(p, "/api/"))) {
        char buf[512];
        int i = 0;

        while (p[i] && p[i] != '"' && p[i] != '\'' && p[i] != ' ' && i < 500)
            buf[i] = p[i], i++;

        buf[i] = '\0';
        save_endpoint(buf);
        p++;
    }
}

/*
 * HTML Extractor + API Scanner
 */
void extract_links(const char *html, const char *base_url) {
    GumboOutput *output = gumbo_parse(html);
    if (!output) return;

    void recurse(GumboNode *node) {
        if (node->type == GUMBO_NODE_TEXT) {
            if (strstr(node->v.text.text, "/api/"))
                scan_js_for_api(node->v.text.text);
            return;
        }

        if (node->type != GUMBO_NODE_ELEMENT)
            return;

        GumboTag tag = node->v.element.tag;

        // <a href="">
        if (tag == GUMBO_TAG_A) {
            GumboAttribute *href = gumbo_get_attribute(&node->v.element.attributes, "href");
            if (href) {
                char url[2048];

                if (strncmp(href->value, "http", 4) != 0)
                    snprintf(url, sizeof(url), "%s%s", base_url, href->value);
                else
                    snprintf(url, sizeof(url), "%s", href->value);

                if (is_api_endpoint(url))
                    save_endpoint(url);

                if (is_internal(url) && !url_visited(url)) {
                    log_url("LINK", url);
                    add_visited(url);
                }
            }
        }

        // <form action="">
        if (tag == GUMBO_TAG_FORM) {
            GumboAttribute *act = gumbo_get_attribute(&node->v.element.attributes, "action");
            if (act) {
                char url[2048];
                if (strncmp(act->value, "http", 4) != 0)
                    snprintf(url, sizeof(url), "%s%s", base_url, act->value);
                else
                    snprintf(url, sizeof(url), "%s", act->value);

                if (is_api_endpoint(url))
                    save_endpoint(url);
            }
        }

        // <script src="">
        if (tag == GUMBO_TAG_SCRIPT) {
            GumboAttribute *src = gumbo_get_attribute(&node->v.element.attributes, "src");
            if (src) {
                char url[2048];
                if (strncmp(src->value, "http", 4) != 0)
                    snprintf(url, sizeof(url), "%s%s", base_url, src->value);
                else
                    snprintf(url, sizeof(url), "%s", src->value);

                if (is_api_endpoint(url))
                    save_endpoint(url);
            }
        }

        // Recurse
        GumboVector *children = &node->v.element.children;
        for (unsigned i = 0; i < children->length; i++)
            recurse(children->data[i]);
    }

    recurse(output->root);
    gumbo_destroy_output(&kGumboDefaultOptions, output);
}

/*
 * Crawler
 */
void crawl(const char *url) {
    if (current_depth >= MAX_DEPTH) return;
    if (visited_count >= MAX_URLS) return;

    log_url("DIR", url);
    do_header_recon(url);
    add_visited(url);

    CURL *curl = curl_easy_init();
    if (!curl) return;

    char *html = NULL;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &html);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "ReconCrawler/1.0");
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 12L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode res = curl_easy_perform(curl);
    long code;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    if (res == CURLE_OK && code == 200 && html) {
        current_depth++;
        extract_links(html, url);
        current_depth--;
    }

    free(html);
    curl_easy_cleanup(curl);

    usleep(200000); // polite delay
}

/*
 * MAIN
 */
int main(int argc, char **argv) {
    if (argc != 3) {
        printf("Usage: %s <https://example.com/> <output.txt>\n", argv[0]);
        return 1;
    }

    // domain extrahieren
    const char *p = strstr(argv[1], "//");
    p = p ? p + 2 : argv[1];

    const char *slash = strchr(p, '/');
    int len = slash ? slash - p : strlen(p);
    strncpy(base_domain, p, len);
    base_domain[len] = '\0';

    out_file = fopen(argv[2], "w");
    ep_file = fopen("endpoints.txt", "w");
    dns_file = fopen("dns.txt", "w");

    if (!out_file || !ep_file || !dns_file) {
        perror("fopen");
        return 1;
    }

    // DNS RECON
    do_dns_recon(base_domain);

    // Start Header Recon
    do_header_recon(argv[1]);

    // Crawl
    curl_global_init(CURL_GLOBAL_DEFAULT);

    add_visited(argv[1]);
    crawl(argv[1]);

    curl_global_cleanup();

    fprintf(out_file, "\n# Done — %d URLs\n", visited_count);
    fclose(out_file);
    fclose(ep_file);
    fclose(dns_file);

    for (int i = 0; i < visited_count; i++)
        free(visited[i]);

    printf("[+] Recon Done. Files: %s, endpoints.txt, dns.txt\n", argv[2]);
    return 0;
}
