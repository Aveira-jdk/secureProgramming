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
static void usage(const char *program, int interactive) {
    if (interactive) {
        puts("Commands: init | add <service> | list | get <service> | del <service> | help | exit | quit");
        return;
    }
    printf("Usage: %s [init|add|list|get|del|help] [service]\n"
           "  (no args)     Start interactive session\n"
           "  init          Create the vault\n"
           "  add <service> Add or update an entry\n"
           "  list          Show saved services and usernames\n"
           "  get <service> Copy a password to the clipboard\n"
           "  del <service> Delete an entry\n"
           "  help          Show this help text\n", program);
}

// Unlock the vault if it is not already unlocked in memory.
static int ensure_unlocked(char *master, size_t master_sz, Credential *entries,
                           size_t *count, int *unlocked) {
    if (*unlocked) return 0;

    int rc = prompt_input("Master password: ", master, master_sz, 1);
    if (rc == -2) return -2;
    if (rc != 0 || !master[0]) {
        fputs("Invalid password input.\n", stderr);
        return -1;
    }

    if (vault_load(master, entries, count) != 0) {
        wipe_buffer(master, master_sz);
        if (handle_pending_signals() != 0) return -2;
        fputs("Could not unlock the vault.\n", stderr);
        return -1;
    }
    if (handle_pending_signals() != 0) return -2;
    *unlocked = 1;
    return 0;
}

// Execute one command. Returns 0 on success, -1 on runtime error, -2 on signal abort, -3 on bad syntax.
static int run_command(const char *command, const char *arg, char *master, size_t master_sz,
                       Credential *entries, size_t *count, int *unlocked) {
    int is_init = strcmp(command, "init") == 0;
    int is_list = strcmp(command, "list") == 0;
    int is_add = strcmp(command, "add") == 0;
    int is_get = strcmp(command, "get") == 0;
    int is_del = strcmp(command, "del") == 0;

    if (!is_init && !is_list && !is_add && !is_get && !is_del) return -3;
    if ((is_init || is_list) && arg != NULL) return -3;
    if ((is_add || is_get || is_del) && (arg == NULL || !valid_service(arg))) return -3;

    // On init, stop if vault.bin already exists so we do not overwrite data.
    if (is_init) {
        struct stat st;
        if (lstat(VAULT_FILE, &st) == 0) {
            fputs("A vault already exists.\n", stderr);
            return -1;
        }
        char new_master[PASS_LEN] = {0};
        int rc = prompt_input("Master password: ", new_master, sizeof(new_master), 1);
        if (rc == -2) { wipe_buffer(new_master, sizeof(new_master)); return -2; }
        if (rc != 0 || !new_master[0]) {
            wipe_buffer(new_master, sizeof(new_master));
            fputs("Invalid password input.\n", stderr);
            return -1;
        }
        if (vault_save(new_master, NULL, 0) != 0) {
            wipe_buffer(new_master, sizeof(new_master));
            fputs("Could not create the vault.\n", stderr);
            return -1;
        }
        wipe_buffer(entries, MAX_ENTRIES * sizeof(*entries));
        memcpy(master, new_master, master_sz);
        wipe_buffer(new_master, sizeof(new_master));
        *count = 0;
        *unlocked = 1;
        puts("Vault created.");
        return handle_pending_signals() != 0 ? -2 : 0;
    }

    int unlock_rc = ensure_unlocked(master, master_sz, entries, count, unlocked);
    if (unlock_rc != 0) return unlock_rc;

    if (is_list) {
        for (size_t i = 0; i < *count; i++) {
            printf("%s (user: %s)\n", entries[i].service, entries[i].username);
        }
        if (!*count) puts("Vault is empty.");
        return 0;
    }

    if (is_add) {
        int index = find_service(entries, *count, arg);
        int is_new = index < 0;
        if (is_new && *count == MAX_ENTRIES) {
            fputs("Vault is full.\n", stderr);
            return -1;
        }

        char user_buf[STR_LEN] = {0};
        char pass_buf[PASS_LEN] = {0};
        int rc = prompt_input("Username: ", user_buf, sizeof(user_buf), 0);
        if (rc == -2) { wipe_buffer(user_buf, sizeof(user_buf)); return -2; }
        if (rc != 0 || !user_buf[0]) {
            wipe_buffer(user_buf, sizeof(user_buf));
            fputs("Invalid entry input.\n", stderr);
            return -1;
        }

        rc = prompt_input("Password: ", pass_buf, sizeof(pass_buf), 1);
        if (rc == -2) {
            wipe_buffer(user_buf, sizeof(user_buf));
            wipe_buffer(pass_buf, sizeof(pass_buf));
            return -2;
        }
        if (rc != 0 || !pass_buf[0]) {
            wipe_buffer(user_buf, sizeof(user_buf));
            wipe_buffer(pass_buf, sizeof(pass_buf));
            fputs("Invalid entry input.\n", stderr);
            return -1;
        }

        Credential backup = {0};
        size_t target = is_new ? (*count)++ : (size_t)index;
        if (!is_new) backup = entries[target];

        snprintf(entries[target].service, STR_LEN, "%s", arg);
        snprintf(entries[target].username, STR_LEN, "%s", user_buf);
        snprintf(entries[target].password, PASS_LEN, "%s", pass_buf);
        wipe_buffer(user_buf, sizeof(user_buf));
        wipe_buffer(pass_buf, sizeof(pass_buf));

        if (vault_save(master, entries, *count) != 0) {
            if (is_new) wipe_buffer(&entries[--(*count)], sizeof(entries[0]));
            else entries[target] = backup;
            wipe_buffer(&backup, sizeof(backup));
            fputs("Could not save the vault.\n", stderr);
            return -1;
        }
        wipe_buffer(&backup, sizeof(backup));
        puts("Entry saved.");
        return handle_pending_signals() != 0 ? -2 : 0;
    }

    if (is_get) {
        int index = find_service(entries, *count, arg);
        if (index < 0) {
            fputs("Entry not found.\n", stderr);
            return -1;
        }
        if (copy_to_clipboard(entries[index].password) != 0) {
            fputs("Could not copy to clipboard.\n", stderr);
            return -1;
        }
        puts("Clipboard helper started.");
        return 0;
    }

    // is_del
    int index = find_service(entries, *count, arg);
    if (index < 0) {
        fputs("Entry not found.\n", stderr);
        return -1;
    }
    Credential backup = entries[index];
    for (size_t i = (size_t)index + 1; i < *count; i++) {
        entries[i - 1] = entries[i];
    }
    wipe_buffer(&entries[--(*count)], sizeof(entries[0]));

    if (vault_save(master, entries, *count) != 0) {
        for (size_t i = *count; i > (size_t)index; i--) {
            entries[i] = entries[i - 1];
        }
        entries[index] = backup;
        (*count)++;
        wipe_buffer(&backup, sizeof(backup));
        fputs("Could not save the vault.\n", stderr);
        return -1;
    }
    wipe_buffer(&backup, sizeof(backup));
    puts("Entry deleted.");
    return handle_pending_signals() != 0 ? -2 : 0;
}

int main(int argc, char **argv) {
    // Start up libsodium security library.
    if (sodium_init() < 0) {
        fputs("Secure storage is unavailable.\n", stderr);
        return 1;
    }
    setup_signals();

    if (argc < 1) { usage("spm", 0); return 1; }
    const char *prog = argv[0] ? argv[0] : "spm";

    // Handle explicit help flag.
    if (argc >= 2 && (strcmp(argv[1], "help") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(prog, 0);
        return 0;
    }

    char master[PASS_LEN] = {0};
    Credential entries[MAX_ENTRIES] = {0};
    size_t count = 0;
    int unlocked = 0;
    int status = 1;

    // One-shot CLI mode when command-line arguments are supplied.
    if (argc >= 2) {
        if (argc > 3) {
            usage(prog, 0);
            goto done;
        }
        const char *arg = (argc == 3) ? argv[2] : NULL;
        int rc = run_command(argv[1], arg, master, sizeof(master), entries, &count, &unlocked);
        if (rc == -3) {
            usage(prog, 0);
            goto done;
        }
        if (rc == -2) {
            status = handle_pending_signals();
            if (status == 0) status = 130;
            goto done;
        }
        status = (rc == 0) ? 0 : 1;
        goto done;
    }

    // Interactive mode when started with no arguments.
    puts("Interactive mode. Type 'help' or 'exit'.");
    for (;;) {
        int sig_rc = handle_pending_signals();
        if (sig_rc != 0) { status = sig_rc; goto done; }

        char line[256] = {0};
        int rc = prompt_input("spm> ", line, sizeof(line), 0);
        if (rc == -2) {
            wipe_buffer(line, sizeof(line));
            status = handle_pending_signals();
            if (status == 0) status = 130;
            goto done;
        }
        if (rc != 0) {
            wipe_buffer(line, sizeof(line));
            if (feof(stdin) && !ferror(stdin)) {
                fputc('\n', stdout);
                status = 0;
                goto done;
            }
            fputs("Invalid command input.\n", stderr);
            continue;
        }

        // Parse up to 2 whitespace-separated tokens without allocating.
        char *p = line;
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') continue;

        char *cmd = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        if (*p) *p++ = '\0';
        while (*p == ' ' || *p == '\t') p++;

        char *arg = (*p != '\0') ? p : NULL;
        if (arg) {
            while (*p && *p != ' ' && *p != '\t') p++;
            if (*p) {
                *p++ = '\0';
                while (*p == ' ' || *p == '\t') p++;
                if (*p != '\0') {
                    wipe_buffer(line, sizeof(line));
                    usage(prog, 1);
                    continue;
                }
            }
        }

        if ((strcmp(cmd, "exit") == 0 || strcmp(cmd, "quit") == 0) && !arg) {
            wipe_buffer(line, sizeof(line));
            status = 0;
            goto done;
        }
        if ((strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0) && !arg) {
            wipe_buffer(line, sizeof(line));
            usage(prog, 1);
            continue;
        }

        int cmd_rc = run_command(cmd, arg, master, sizeof(master), entries, &count, &unlocked);
        wipe_buffer(line, sizeof(line));
        if (cmd_rc == -2) {
            status = handle_pending_signals();
            if (status == 0) status = 130;
            goto done;
        }
        if (cmd_rc == -3) usage(prog, 1);

        sig_rc = handle_pending_signals();
        if (sig_rc != 0) { status = sig_rc; goto done; }
    }

done:
    // Wipe sensitive password and entry buffers from RAM before exiting.
    wipe_buffer(master, sizeof(master));
    wipe_buffer(entries, sizeof(entries));
    return status;
}
