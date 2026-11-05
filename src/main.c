#define _POSIX_C_SOURCE 200809L
#include "vault.h"

#include <ctype.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sodium.h>

// Check that service name only has normal printable characters.
static int valid_service(const char *service) {
    size_t len = strlen(service);
    if (!len || len >= STR_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        if (!isprint((unsigned char)service[i])) return 0;
    }
    return 1;
}

// Search for an existing entry matching the given service name.
static int find_service(const Credential *entries, size_t count, const char *service) {
    for (size_t i = 0; i < count; i++) {
        if (strcmp(entries[i].service, service) == 0) return (int)i;
    }
    return -1;
}

// Copy password to system clipboard without showing it on screen.
static int copy_to_clipboard(const char *password) {
    // Check if any supported clipboard tool is installed.
    if (system("command -v wl-copy >/dev/null 2>&1 || command -v xclip >/dev/null 2>&1 || command -v clip.exe >/dev/null 2>&1") != 0) {
        return -1;
    }
    // Run clipboard tool in the background so the program does not hang.
    FILE *pipe = popen("(wl-copy 2>/dev/null || xclip -selection clipboard 2>/dev/null || clip.exe 2>/dev/null) &", "w");
    if (!pipe) return -1;

    // Ignore broken pipe signal if clipboard tool closes early.
    void (*old_handler)(int) = signal(SIGPIPE, SIG_IGN);
    if (old_handler == SIG_ERR) { pclose(pipe); return -1; }

    // Send the password into the clipboard tool.
    int ok = fputs(password, pipe) >= 0;
    if (pclose(pipe) != 0) ok = 0;
    signal(SIGPIPE, old_handler);
    return ok ? 0 : -1;
}

// Print command help and how to use the program.
static void usage(const char *program) {
    printf("Usage: %s <init|add|list|get|del|help> [service]\n"
           "  init          Create the vault\n"
           "  add <service> Add or update an entry\n"
           "  list          Show saved services and usernames\n"
           "  get <service> Copy a password to the clipboard\n"
           "  del <service> Delete an entry\n"
           "  help          Show this help text\n", program);
}

int main(int argc, char **argv) {
    // Start up libsodium security library.
    if (sodium_init() < 0) {
        fputs("Secure storage is unavailable.\n", stderr);
        return 1;
    }

    // Check if user asked for help.
    if (argc < 2 || strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0) {
        usage(argv[0]);
        return argc < 2 ? 1 : 0;
    }

    // Check which command was requested.
    const char *command = argv[1];
    int is_init = strcmp(command, "init") == 0;
    int is_list = strcmp(command, "list") == 0;
    int is_add = strcmp(command, "add") == 0;
    int is_get = strcmp(command, "get") == 0;
    int is_del = strcmp(command, "del") == 0;

    // Validate command name and argument count.
    if (!is_init && !is_list && !is_add && !is_get && !is_del) {
        usage(argv[0]);
        return 1;
    }
    if ((is_init || is_list) && argc != 2) {
        usage(argv[0]);
        return 1;
    }
    if ((is_add || is_get || is_del) && (argc != 3 || !valid_service(argv[2]))) {
        usage(argv[0]);
        return 1;
    }

    // On init, stop if vault.bin already exists so we do not overwrite data.
    struct stat st;
    if (is_init && lstat(VAULT_FILE, &st) == 0) {
        fputs("A vault already exists.\n", stderr);
        return 1;
    }

    // Buffers to hold master password and loaded entries.
    char master[PASS_LEN] = {0};
    Credential entries[MAX_ENTRIES] = {0};
    size_t count = 0;
    int status = 1;

    // Ask user for master password without showing it on screen.
    if (prompt_input("Master password: ", master, sizeof(master), 1) != 0 || !master[0]) {
        fputs("Invalid password input.\n", stderr);
        goto done;
    }

    // Handle init command: save an empty vault.
    if (is_init) {
        if (vault_save(master, NULL, 0) != 0) {
            fputs("Could not create the vault.\n", stderr);
            goto done;
        }
        puts("Vault created.");
        status = 0;
        goto done;
    }

    // Load and decrypt vault with master password. Fails on wrong password or bad file.
    if (vault_load(master, entries, &count) != 0) {
        fputs("Could not unlock the vault.\n", stderr);
        goto done;
    }

    // Handle list command: show services and usernames, never passwords.
    if (is_list) {
        for (size_t i = 0; i < count; i++) {
            printf("%s (user: %s)\n", entries[i].service, entries[i].username);
        }
        if (!count) puts("Vault is empty.");
        status = 0;
    }
    // Handle add command: insert new entry or update existing one.
    else if (is_add) {
        int index = find_service(entries, count, argv[2]);
        // If entry is new, check if vault reached max limit.
        if (index < 0) {
            if (count == MAX_ENTRIES) {
                fputs("Vault is full.\n", stderr);
                goto done;
            }
            index = (int)count++;
        }
        // Ask for username in plain text, password hidden.
        if (prompt_input("Username: ", entries[index].username, STR_LEN, 0) != 0 ||
            !entries[index].username[0] ||
            prompt_input("Password: ", entries[index].password, PASS_LEN, 1) != 0 ||
            !entries[index].password[0]) {
            fputs("Invalid entry input.\n", stderr);
            goto done;
        }
        // Save service name into entry.
        snprintf(entries[index].service, STR_LEN, "%s", argv[2]);

        // Encrypt and write updated vault to disk.
        if (vault_save(master, entries, count) != 0) {
            fputs("Could not save the vault.\n", stderr);
            goto done;
        }
        puts("Entry saved.");
        status = 0;
    }
    // Handle get: copy password to clipboard.
    else if (is_get) {
        int index = find_service(entries, count, argv[2]);
        if (index < 0) {
            fputs("Entry not found.\n", stderr);
            goto done;
        }
        if (copy_to_clipboard(entries[index].password) != 0) {
            fputs("Could not copy to clipboard.\n", stderr);
            goto done;
        }
        puts("Clipboard helper started.");
        status = 0;
    }
    // Handle del: remove entry and shift remaining ones left.
    else if (is_del) {
        int index = find_service(entries, count, argv[2]);
        if (index < 0) {
            fputs("Entry not found.\n", stderr);
            goto done;
        }
        for (size_t i = (size_t)index + 1; i < count; i++) {
            entries[i - 1] = entries[i];
        }
        // Wipe the last slot that is now unused.
        wipe_buffer(&entries[--count], sizeof(entries[0]));

        // Save updated vault to disk.
        if (vault_save(master, entries, count) != 0) {
            fputs("Could not save the vault.\n", stderr);
            goto done;
        }
        puts("Entry deleted.");
        status = 0;
    }

done:
    // Wipe sensitive password and entry buffers from RAM before exiting.
    wipe_buffer(master, sizeof(master));
    wipe_buffer(entries, sizeof(entries));
    return status;
}
