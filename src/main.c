#define _POSIX_C_SOURCE 200809L
#include "vault.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sodium.h>

#define MIN_MASTER_LEN 8

// Strict allowlist for service names and usernames: letters, digits, and . _ - @ + (no '..' or '.').
static int valid_ident(const char *s) {
    if (!s) return 0;
    size_t len = strlen(s);
    if (!len || len >= STR_LEN) return 0;
    if (strcmp(s, ".") == 0 || strstr(s, "..") != NULL) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        int ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                 (ch >= '0' && ch <= '9') ||
                 ch == '.' || ch == '_' || ch == '-' || ch == '@' || ch == '+';
        if (!ok) return 0;
    }
    return 1;
}

// Enforce length bounds and reject ASCII control bytes inside passwords.
static int valid_password(const char *s, size_t min_len) {
    if (!s) return 0;
    size_t len = strlen(s);
    if (len < min_len || len >= PASS_LEN) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch < 0x20 || ch == 0x7f) return 0;
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

// Check whether an executable file exists in an absolute directory listed in PATH.
static int command_in_path(const char *name) {
    const char *path_env = getenv("PATH");
    if (!path_env || !path_env[0] || !name || !name[0]) return 0;

    const char *p = path_env;
    while (*p) {
        const char *sep = strchr(p, ':');
        size_t dir_len = sep ? (size_t)(sep - p) : strlen(p);
        char full[4096];
        if (dir_len > 0 && dir_len < sizeof(full) && p[0] == '/') {
            int n = snprintf(full, sizeof(full), "%.*s/%s", (int)dir_len, p, name);
            struct stat st;
            if (n > 0 && (size_t)n < sizeof(full) &&
                stat(full, &st) == 0 && S_ISREG(st.st_mode) && access(full, X_OK) == 0) {
                return 1;
            }
        }
        if (!sep) break;
        p = sep + 1;
    }
    return 0;
}

// Copy password directly via fork/execvp without spawning a shell.
static int copy_to_clipboard(const char *password) {
    static char tool_wl[] = "wl-copy";
    static char tool_xclip[] = "xclip";
    static char arg_sel[] = "-selection";
    static char arg_clip[] = "clipboard";
    static char tool_win[] = "clip.exe";
    char *const wl_argv[] = { tool_wl, NULL };
    char *const xclip_argv[] = { tool_xclip, arg_sel, arg_clip, NULL };
    char *const win_argv[] = { tool_win, NULL };

    char *const *argv = NULL;
    if (command_in_path("wl-copy")) argv = wl_argv;
    else if (command_in_path("xclip")) argv = xclip_argv;
    else if (command_in_path("clip.exe")) argv = win_argv;
    else return -1;

    int pfd[2];
    if (pipe(pfd) != 0) return -1;

    struct sigaction ign_sa, old_pipe;
    memset(&ign_sa, 0, sizeof(ign_sa));
    ign_sa.sa_handler = SIG_IGN;
    sigemptyset(&ign_sa.sa_mask);
    if (sigaction(SIGPIPE, &ign_sa, &old_pipe) != 0) {
        close(pfd[0]);
        close(pfd[1]);
        return -1;
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pfd[0]);
        close(pfd[1]);
        sigaction(SIGPIPE, &old_pipe, NULL);
        return -1;
    }

    if (pid == 0) {
        close(pfd[1]);
        if (dup2(pfd[0], STDIN_FILENO) < 0) _exit(127);
        if (pfd[0] != STDIN_FILENO) close(pfd[0]);

        int devnull = open("/dev/null", O_WRONLY);
        if (devnull < 0) _exit(127);
        if (dup2(devnull, STDOUT_FILENO) < 0 || dup2(devnull, STDERR_FILENO) < 0) _exit(127);
        if (devnull != STDOUT_FILENO && devnull != STDERR_FILENO) close(devnull);

        signal(SIGPIPE, SIG_DFL);
        signal(SIGTSTP, SIG_DFL);
        signal(SIGINT, SIG_DFL);
        signal(SIGTERM, SIG_DFL);
        signal(SIGHUP, SIG_DFL);

        execvp(argv[0], argv);
        _exit(127);
    }

    close(pfd[0]);
    const unsigned char *buf = (const unsigned char *)password;
    size_t rem = strlen(password);
    int ok = 1;
    while (rem > 0) {
        ssize_t n = write(pfd[1], buf, rem);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = 0; break; }
        buf += (size_t)n;
        rem -= (size_t)n;
    }
    if (close(pfd[1]) != 0) ok = 0;

    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno != EINTR) { ok = 0; break; }
    }
    sigaction(SIGPIPE, &old_pipe, NULL);
    return (ok && WIFEXITED(status) && WEXITSTATUS(status) == 0) ? 0 : -1;
}

// Print command help and how to use the program.
static void usage(const char *program, int interactive) {
    if (!interactive) {
        printf("Usage: %s [command] [service]\n"
               "  (no args)      Start interactive session\n", program);
    } else {
        puts("Commands:");
    }
    puts("  init           Create a new vault\n"
         "  add <service>  Add or update an entry\n"
         "  list           Show saved services and usernames\n"
         "  get <service>  Copy password to clipboard and show username\n"
         "  del <service>  Delete an entry\n"
         "  del-vault      Delete the entire vault (requires YES)\n"
         "  help           Show this help text");
    if (interactive) {
        puts("  exit | quit    Exit interactive mode");
    }
}

// Unlock the vault if it is not already unlocked in memory.
static int ensure_unlocked(char *master, size_t master_sz, Credential *entries,
                           size_t *count, int *unlocked) {
    if (*unlocked) return 0;

    struct stat st;
    if (lstat(VAULT_FILE, &st) != 0 && errno == ENOENT) {
        log_event("UNLOCK", "FAIL", "no_vault");
        fputs("No vault found. Run 'init' first.\n", stderr);
        return -1;
    }

    int rc = prompt_input("Master password: ", master, master_sz, 1);
    if (rc == -2) return -2;
    if (rc != 0 || !valid_password(master, 1)) {
        wipe_buffer(master, master_sz);
        log_event("UNLOCK", "FAIL", "invalid_input");
        fputs("Invalid password input.\n", stderr);
        return -1;
    }

    if (vault_load(master, entries, count) != 0) {
        wipe_buffer(master, master_sz);
        if (handle_pending_signals() != 0) return -2;
        log_event("UNLOCK", "FAIL", "unlock_failed");
        fputs("Could not unlock the vault.\n", stderr);
        return -1;
    }
    if (handle_pending_signals() != 0) return -2;
    *unlocked = 1;
    log_event("UNLOCK", "OK", "vault_unlocked");
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
    int is_del_vault = strcmp(command, "del-vault") == 0;

    if (!is_init && !is_list && !is_add && !is_get && !is_del && !is_del_vault) return -3;
    if ((is_init || is_list || is_del_vault) && arg != NULL) return -3;
    if ((is_add || is_get || is_del) && (arg == NULL || !valid_ident(arg))) return -3;

    // On init, stop if vault.bin already exists so we do not overwrite data.
    if (is_init) {
        struct stat st;
        if (lstat(VAULT_FILE, &st) == 0) {
            log_event("INIT", "FAIL", "vault_exists");
            fputs("A vault already exists.\n", stderr);
            return -1;
        }
        char *new_master = secure_alloc(PASS_LEN);
        if (!new_master) {
            log_event("INIT", "FAIL", "memory_error");
            fputs("Secure memory is unavailable.\n", stderr);
            return -1;
        }
        int rc = prompt_input("Master password: ", new_master, PASS_LEN, 1);
        if (rc == -2) { secure_free(new_master); return -2; }
        if (rc != 0 || !valid_password(new_master, MIN_MASTER_LEN)) {
            secure_free(new_master);
            log_event("INIT", "FAIL", "invalid_input");
            fprintf(stderr, "Master password must be %d to %d normal characters.\n",
                    MIN_MASTER_LEN, PASS_LEN - 2);
            return -1;
        }

        char *confirm = secure_alloc(PASS_LEN);
        if (!confirm) {
            secure_free(new_master);
            log_event("INIT", "FAIL", "memory_error");
            fputs("Secure memory is unavailable.\n", stderr);
            return -1;
        }
        rc = prompt_input("Confirm master password: ", confirm, PASS_LEN, 1);
        if (rc == -2) {
            secure_free(new_master);
            secure_free(confirm);
            return -2;
        }
        size_t mlen = strlen(new_master);
        int match = (rc == 0 && strlen(confirm) == mlen && sodium_memcmp(new_master, confirm, mlen) == 0);
        secure_free(confirm);
        if (!match) {
            secure_free(new_master);
            log_event("INIT", "FAIL", "password_mismatch");
            fputs("Master passwords do not match.\n", stderr);
            return -1;
        }

        if (vault_create(new_master) != 0) {
            secure_free(new_master);
            log_event("INIT", "FAIL", "save_failed");
            fputs("Could not create the vault.\n", stderr);
            return -1;
        }
        wipe_buffer(entries, MAX_ENTRIES * sizeof(*entries));
        memcpy(master, new_master, master_sz);
        secure_free(new_master);
        *count = 0;
        *unlocked = 1;
        log_event("INIT", "OK", "vault_created");
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
        log_event("LIST", "OK", NULL);
        return 0;
    }

    if (is_add) {
        int index = find_service(entries, *count, arg);
        int is_new = index < 0;
        if (is_new && *count == MAX_ENTRIES) {
            log_event("ADD", "FAIL", "vault_full");
            fputs("Vault is full.\n", stderr);
            return -1;
        }

        char user_buf[STR_LEN] = {0};
        int rc = prompt_input("Username: ", user_buf, sizeof(user_buf), 0);
        if (rc == -2) { wipe_buffer(user_buf, sizeof(user_buf)); return -2; }
        if (rc != 0 || !valid_ident(user_buf)) {
            wipe_buffer(user_buf, sizeof(user_buf));
            log_event("ADD", "FAIL", "invalid_input");
            fputs("Invalid username (allowed: letters, digits, . _ - @ +).\n", stderr);
            return -1;
        }

        char *pass_buf = secure_alloc(PASS_LEN);
        if (!pass_buf) {
            wipe_buffer(user_buf, sizeof(user_buf));
            log_event("ADD", "FAIL", "memory_error");
            fputs("Secure memory is unavailable.\n", stderr);
            return -1;
        }
        rc = prompt_input("Password: ", pass_buf, PASS_LEN, 1);
        if (rc == -2) {
            wipe_buffer(user_buf, sizeof(user_buf));
            secure_free(pass_buf);
            return -2;
        }
        if (rc != 0 || !valid_password(pass_buf, 1)) {
            wipe_buffer(user_buf, sizeof(user_buf));
            secure_free(pass_buf);
            log_event("ADD", "FAIL", "invalid_input");
            fputs("Invalid entry password.\n", stderr);
            return -1;
        }

        Credential *backup = is_new ? NULL : secure_alloc(sizeof(Credential));
        if (!is_new && !backup) {
            wipe_buffer(user_buf, sizeof(user_buf));
            secure_free(pass_buf);
            log_event("ADD", "FAIL", "memory_error");
            fputs("Secure memory is unavailable.\n", stderr);
            return -1;
        }
        size_t target = is_new ? (*count)++ : (size_t)index;
        if (!is_new) *backup = entries[target];

        int n1 = snprintf(entries[target].service, STR_LEN, "%s", arg);
        int n2 = snprintf(entries[target].username, STR_LEN, "%s", user_buf);
        int n3 = snprintf(entries[target].password, PASS_LEN, "%s", pass_buf);
        wipe_buffer(user_buf, sizeof(user_buf));
        secure_free(pass_buf);
        if (n1 <= 0 || n1 >= STR_LEN || n2 <= 0 || n2 >= STR_LEN || n3 <= 0 || n3 >= PASS_LEN) {
            if (is_new) wipe_buffer(&entries[--(*count)], sizeof(entries[0]));
            else entries[target] = *backup;
            secure_free(backup);
            log_event("ADD", "FAIL", "invalid_input");
            fputs("Invalid entry input.\n", stderr);
            return -1;
        }

        if (vault_save(master, entries, *count) != 0) {
            if (is_new) wipe_buffer(&entries[--(*count)], sizeof(entries[0]));
            else entries[target] = *backup;
            secure_free(backup);
            log_event("ADD", "FAIL", "save_failed");
            fputs("Could not save the vault.\n", stderr);
            return -1;
        }
        secure_free(backup);
        log_event("ADD", "OK", is_new ? "entry_added" : "entry_updated");
        puts("Entry saved.");
        return handle_pending_signals() != 0 ? -2 : 0;
    }

    if (is_get) {
        int index = find_service(entries, *count, arg);
        if (index < 0) {
            log_event("GET", "FAIL", "not_found");
            fputs("Entry not found.\n", stderr);
            return -1;
        }
        if (copy_to_clipboard(entries[index].password) != 0) {
            log_event("GET", "FAIL", "clipboard_failed");
            fputs("Could not copy to clipboard.\n", stderr);
            return -1;
        }
        log_event("GET", "OK", "clipboard_started");
        printf("%s (user: %s)\n%s (pass: in clipboard)\n",
               entries[index].service, entries[index].username, entries[index].service);
        return handle_pending_signals() != 0 ? -2 : 0;
    }

    if (is_del_vault) {
        char confirm[16] = {0};
        int rc = prompt_input("Delete vault.bin permanently? Type YES to confirm: ",
                              confirm, sizeof(confirm), 0);
        if (rc == -2) { wipe_buffer(confirm, sizeof(confirm)); return -2; }
        int confirmed = (rc == 0 && strcmp(confirm, "YES") == 0);
        wipe_buffer(confirm, sizeof(confirm));
        if (!confirmed) {
            log_event("DEL_VAULT", "FAIL", "cancelled");
            puts("Vault deletion cancelled.");
            return -1;
        }
        if (vault_delete() != 0) {
            log_event("DEL_VAULT", "FAIL", "delete_failed");
            fputs("Could not delete the vault.\n", stderr);
            return -1;
        }
        wipe_buffer(master, master_sz);
        wipe_buffer(entries, MAX_ENTRIES * sizeof(*entries));
        *count = 0;
        *unlocked = 0;
        log_event("DEL_VAULT", "OK", "vault_deleted");
        puts("Vault deleted.");
        return handle_pending_signals() != 0 ? -2 : 0;
    }

    // is_del
    int index = find_service(entries, *count, arg);
    if (index < 0) {
        log_event("DEL", "FAIL", "not_found");
        fputs("Entry not found.\n", stderr);
        return -1;
    }
    Credential *backup = secure_alloc(sizeof(Credential));
    if (!backup) {
        log_event("DEL", "FAIL", "memory_error");
        fputs("Secure memory is unavailable.\n", stderr);
        return -1;
    }
    *backup = entries[index];
    for (size_t i = (size_t)index + 1; i < *count; i++) {
        entries[i - 1] = entries[i];
    }
    wipe_buffer(&entries[--(*count)], sizeof(entries[0]));

    if (vault_save(master, entries, *count) != 0) {
        for (size_t i = *count; i > (size_t)index; i--) {
            entries[i] = entries[i - 1];
        }
        entries[index] = *backup;
        (*count)++;
        secure_free(backup);
        log_event("DEL", "FAIL", "save_failed");
        fputs("Could not save the vault.\n", stderr);
        return -1;
    }
    secure_free(backup);
    log_event("DEL", "OK", "entry_deleted");
    puts("Entry deleted.");
    return handle_pending_signals() != 0 ? -2 : 0;
}

// Log signal-triggered termination and return its shell exit status.
static int finish_signal_exit(void) {
    int sig_rc = handle_pending_signals();
    if (sig_rc == 0) sig_rc = 130;
    const char *reason = (sig_rc == 128 + SIGINT) ? "sigint" :
                         (sig_rc == 128 + SIGTERM) ? "sigterm" :
                         (sig_rc == 128 + SIGHUP) ? "sighup" : "signal";
    log_event("SIGNAL_EXIT", "OK", reason);
    return sig_rc;
}

int main(int argc, char **argv) {
    // Start up libsodium security library.
    if (sodium_init() < 0 || disable_core_dumps() != 0) {
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

    char *master = secure_alloc(PASS_LEN);
    Credential *entries = secure_alloc(MAX_ENTRIES * sizeof(Credential));
    if (!master || !entries) {
        secure_free(master);
        secure_free(entries);
        fputs("Secure memory is unavailable.\n", stderr);
        return 1;
    }
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
        int rc = run_command(argv[1], arg, master, PASS_LEN, entries, &count, &unlocked);
        if (rc == -3) {
            usage(prog, 0);
            goto done;
        }
        if (rc == -2) {
            status = finish_signal_exit();
            goto done;
        }
        status = (rc == 0) ? 0 : 1;
        goto done;
    }

    // Interactive mode when started with no arguments.
    puts("Interactive mode. Type 'help' or 'exit'.");
    for (;;) {
        if (handle_pending_signals() != 0) {
            status = finish_signal_exit();
            goto done;
        }

        char line[256] = {0};
        int rc = prompt_input("spm> ", line, sizeof(line), 0);
        if (rc == -2) {
            wipe_buffer(line, sizeof(line));
            status = finish_signal_exit();
            goto done;
        }
        if (rc != 0) {
            wipe_buffer(line, sizeof(line));
            if (feof(stdin) && !ferror(stdin)) {
                fputc('\n', stdout);
                log_event("SESSION", "OK", "clean_exit");
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
            log_event("SESSION", "OK", "clean_exit");
            status = 0;
            goto done;
        }
        if ((strcmp(cmd, "help") == 0 || strcmp(cmd, "--help") == 0) && !arg) {
            wipe_buffer(line, sizeof(line));
            usage(prog, 1);
            continue;
        }

        int cmd_rc = run_command(cmd, arg, master, PASS_LEN, entries, &count, &unlocked);
        wipe_buffer(line, sizeof(line));
        if (cmd_rc == -2) {
            status = finish_signal_exit();
            goto done;
        }
        if (cmd_rc == -3) usage(prog, 1);

        if (handle_pending_signals() != 0) {
            status = finish_signal_exit();
            goto done;
        }
    }

done:
    // Wipe, munlock, and release locked secret buffers before exiting.
    secure_free(master);
    secure_free(entries);
    return status;
}
