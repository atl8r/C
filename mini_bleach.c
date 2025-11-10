#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <time.h>
#include <glob.h>
#include <utime.h> 
#include <libgen.h> // Für basename()

#define BUFFER_SIZE 4096

// --- Kernfunktionen ---

// Sicheres Überschreiben mit 3-Pass (DoD 5220.22-M)
int secure_overwrite(const char *path, char *buffer, size_t buf_size) {
    struct stat st;
    if (lstat(path, &st) != 0 || !S_ISREG(st.st_mode)) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_TRUNC);
    if (fd == -1) {
        perror(path);
        return -1;
    }

    off_t size = st.st_size;

    // Pass 1: 0x00
    memset(buffer, 0x00, buf_size);
    for (off_t i = 0; i < size; i += buf_size) {
        ssize_t write_size = (size - i > buf_size) ? buf_size : size - i;
        if (write(fd, buffer, write_size) != write_size) goto error;
    }

    // Pass 2: 0xFF
    memset(buffer, 0xFF, buf_size);
    lseek(fd, 0, SEEK_SET);
    for (off_t i = 0; i < size; i += buf_size) {
        ssize_t write_size = (size - i > buf_size) ? buf_size : size - i;
        if (write(fd, buffer, write_size) != write_size) goto error;
    }

    // Pass 3: Zufallsdaten
    lseek(fd, 0, SEEK_SET);
    for (off_t i = 0; i < size; i += buf_size) {
        for (int j = 0; j < buf_size; j++) buffer[j] = rand() % 256;
        ssize_t write_size = (size - i > buf_size) ? buf_size : size - i;
        if (write(fd, buffer, write_size) != write_size) goto error;
    }

    if (fsync(fd) == -1) {
        perror("fsync");
        goto error;
    }
    
    close(fd);
    return 0;

error:
    close(fd);
    return -1;
}

// --- SICHERHEITSFUNKTION 1: Symlink-Prüfung ---
int is_safe_path(const char *full_path) {
    struct stat lst;
    
    if (lstat(full_path, &lst) != 0) {
        // Kann den Pfad nicht statten (z.B. Rechteproblem), behandeln als unsicher
        return 0; 
    }

    if (S_ISLNK(lst.st_mode)) {
        fprintf(stderr, "WARNUNG: Symlink erkannt und ignoriert: %s\n", full_path);
        return 0; 
    }
    
    return 1;
}

// --- SICHERHEITSFUNKTION 2: Metadaten löschen und Datei entlinken ---
int secure_unlink_with_metadata_wipe(const char *path, char *buffer, size_t buf_size) {
    if (secure_overwrite(path, buffer, buf_size) == 0) {
        
        // 1. Zeitstempel manipulieren
        struct utimbuf new_times;
        new_times.actime = 0; // Epoch time
        new_times.modtime = 0;
        utime(path, &new_times);

        // 2. Dateinamen manipulieren (umbenennen)
        // basename() modifiziert den String, daher eine Kopie verwenden
        char path_copy[PATH_MAX];
        strncpy(path_copy, path, PATH_MAX);
        char *name = basename(path_copy);
        
        char new_path[PATH_MAX];
        // Erstelle den neuen Pfadnamen im selben Verzeichnis: /pfad/zum/geloeschten.deleted
        snprintf(new_path, sizeof(new_path), "%s.deleted_XXXXXX", path);
        // mkstemp könnte eine Option sein, aber rename reicht hier für den Zweck
        rename(path, new_path); 

        // 3. Datei entlinken (löschen)
        return unlink(new_path); 

    }
    return -1;
}


// Verzeichnis rekursiv aufräumen
void clean_directory(const char *dirpath, int delete_dir, char *buffer, size_t buf_size) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        //perror(dirpath); // Oft nur Permission Denied, daher auskommentiert
        return;
    }

    struct dirent *entry;
    char filepath[PATH_MAX];

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        snprintf(filepath, sizeof(filepath), "%s/%s", dirpath, entry->d_name);
            
        // Symlink-Prüfung für jeden Eintrag
        if (!is_safe_path(filepath)) {
            continue; 
        }

        struct stat st;
        if (lstat(filepath, &st) == -1) continue;

        if (S_ISDIR(st.st_mode)) {
            clean_directory(filepath, 1, buffer, buf_size);
        } else if (S_ISREG(st.st_mode)) {
            printf("Lösche sicher: %s\n", filepath);
            secure_unlink_with_metadata_wipe(filepath, buffer, buf_size);
        }
    }
    closedir(dir);

    // Metadaten des Verzeichnisses bereinigen, bevor es gelöscht wird
    struct utimbuf new_times = { .actime = 0, .modtime = 0 };
    utime(dirpath, &new_times);

    if (delete_dir && rmdir(dirpath) == 0) {
        printf("Verzeichnis gelöscht: %s\n", dirpath);
    }
}

int main() {
    srand(time(NULL)); 
    char *buffer = malloc(BUFFER_SIZE);
    if (!buffer) return EXIT_FAILURE;

    printf("=== Mini-BleachBit (C) mit erweiterten Sicherheitsfunktionen ===\n\n");

    const char *targets[] = {
    	// Erweiterte Liste von Pfaden
    	"/tmp/*",
    	"/var/tmp/*",
    	"/home/*/.cache/*",
    	"/home/*/.thumbnails/*",
   	    "/home/*/.local/share/Trash/*",
    	"/var/cache/apt/archives/*.deb",
    	"/home/*/.bash_history",
    	"/home/*/.zsh_history",
    	"/home/*/.local/share/recently-used.xbel",
    	"/var/crash/*",
    	NULL
	};
    
    glob_t glob_results;
    
    for (int i = 0; targets[i] != NULL; i++) {
        // Die glob() Funktion expandiert die Platzhalter (* und ?)
        if (glob(targets[i], GLOB_NOSORT, NULL, &glob_results) == 0) {
            for (size_t j = 0; j < glob_results.gl_pathc; j++) {
                const char* path = glob_results.gl_pathv[j];
                
                // Erneute Sicherheitsprüfung nach der Expansion
                if (!is_safe_path(path)) continue;

                struct stat st;
                if (lstat(path, &st) == 0) {
                    printf("\nBeginne Bereinigung von: %s\n", path);
                    if (S_ISDIR(st.st_mode)) {
                        // Löscht Inhalt, nicht das Startverzeichnis (delete_dir = 0)
                        clean_directory(path, 0, buffer, BUFFER_SIZE); 
                    } else if (S_ISREG(st.st_mode)) {
                        secure_unlink_with_metadata_wipe(path, buffer, BUFFER_SIZE);
                    }
                }
            }
            globfree(&glob_results);
        } else {
            // Fehler bei glob, z.B. wenn keine Treffer (GLOB_NOMATCH)
            // fprintf(stderr, "Keine Treffer für %s\n", targets[i]);
        }
    }

    free(buffer);
    printf("\nAufräumen abgeschlossen.\n");
    return EXIT_SUCCESS;
}
