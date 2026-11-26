#define _POSIX_C_SOURCE 200809L
#include "vault.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sodium.h>

// Authenticated header: 4-byte magic ("SPM1"), version (1), reserved (3 bytes), salt, nonce.
#define VAULT_MAGIC_LEN 4
#define VAULT_VERSION   1
#define HEADER_META_LEN 8
#define HEADER_SIZE (HEADER_META_LEN + crypto_pwhash_SALTBYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)
static const unsigned char VAULT_MAGIC[VAULT_MAGIC_LEN] = { 'S', 'P', 'M', '1' };

// Maximum encrypted size: 50 entries plus 16-byte authentication tag.
#define MAX_CIPHER_SIZE (MAX_ENTRIES * sizeof(Credential) + crypto_aead_xchacha20poly1305_ietf_ABYTES)

static volatile sig_atomic_t g_got_sigint = 0;
static volatile sig_atomic_t g_term_sig = 0;
static volatile sig_atomic_t g_in_confirm = 0;
static volatile sig_atomic_t g_term_active = 0;
static struct termios g_saved_term;

static void signal_handler(int sig) {
    int saved_errno = errno;
    if (g_term_active) {
        tcsetattr(STDIN_FILENO, TCSANOW, &g_saved_term);
    }
    if (sig == SIGINT) {
        if (g_in_confirm) g_term_sig = SIGINT;
        else g_got_sigint = 1;
    } else {
        g_term_sig = sig;
    }
    errno = saved_errno;
}

void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = signal_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);

    // Ignore Ctrl+Z so unlocked secrets cannot be suspended in RAM or leave ECHO off.
    sa.sa_handler = SIG_IGN;
    sigaction(SIGTSTP, &sa, NULL);
}

static int confirm_sigint_exit(void) {
    g_in_confirm = 1;
    for (;;) {
        g_got_sigint = 0;
        clearerr(stdin);
        fputs("\nExit cleanly? [y/N]: ", stdout);
        fflush(stdout);

        char ans[16] = {0};
        if (!fgets(ans, (int)sizeof(ans), stdin)) {
            g_in_confirm = 0;
            fputc('\n', stdout);
            if (!g_term_sig) g_term_sig = SIGINT;
            return 1;
        }

        size_t len = strlen(ans);
        if (len && ans[len - 1] == '\n') {
            ans[--len] = '\0';
        } else if (!feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {}
            clearerr(stdin);
            continue;
        }

        if ((ans[0] == 'y' || ans[0] == 'Y') && len == 1) {
            g_in_confirm = 0;
            g_term_sig = SIGINT;
            return 1;
        }
        if (len == 0 || ((ans[0] == 'n' || ans[0] == 'N') && len == 1)) {
            g_in_confirm = 0;
            clearerr(stdin);
            return 0;
        }
    }
}

int handle_pending_signals(void) {
    if (g_term_sig) return 128 + (int)g_term_sig;
    if (g_got_sigint && confirm_sigint_exit()) return 128 + (int)g_term_sig;
    return 0;
}

// Overwrite memory with zeros so secrets do not stay in RAM.
void wipe_buffer(void *ptr, size_t size) {
    if (ptr && size) sodium_memzero(ptr, size);
}

// Read one line of text from the keyboard.
int prompt_input(const char *prompt, char *buffer, size_t size, int hidden) {
    // Check that buffer pointer and size are valid.
    if (!buffer || size < 2 || size > INT_MAX) return -1;
    if (handle_pending_signals() != 0) return -2;

    struct termios old_term;
    int term_tty = hidden && isatty(STDIN_FILENO);

    for (;;) {
        int changed = 0;
        // Turn off echo before printing prompt so fast typing neither echoes nor gets flushed.
        if (term_tty) {
            if (tcgetattr(STDIN_FILENO, &old_term) != 0) return -1;
            g_saved_term = old_term;
            g_term_active = 1;
            struct termios quiet_term = old_term;
            quiet_term.c_lflag &= (tcflag_t)~ECHO;
            if (tcsetattr(STDIN_FILENO, TCSANOW, &quiet_term) != 0) {
                g_term_active = 0;
                return -1;
            }
            changed = 1;
        }

        // Show prompt to the user.
        if (prompt) { fputs(prompt, stdout); fflush(stdout); }

        // Read the line from stdin unless a signal already interrupted before fgets.
        clearerr(stdin);
        char *result = NULL;
        if (!g_term_sig && !g_got_sigint) {
            result = fgets(buffer, (int)size, stdin);
        }

        // Restore terminal settings immediately so typing works normally again.
        if (changed) {
            g_term_active = 0;
            tcsetattr(STDIN_FILENO, TCSANOW, &old_term);
        }

        // Return error or ask confirmation on signal interrupt.
        if (!result) {
            wipe_buffer(buffer, size);
            if (g_term_sig) return -2;
            if (g_got_sigint) {
                if (confirm_sigint_exit()) return -2;
                continue;
            }
            if (changed) fputc('\n', stdout);
            return -1;
        }

        if (changed) fputc('\n', stdout);
        if (g_term_sig) { wipe_buffer(buffer, size); return -2; }
        if (g_got_sigint) {
            wipe_buffer(buffer, size);
            if (confirm_sigint_exit()) return -2;
            continue;
        }

        // Strip trailing newline character.
        size_t len = strlen(buffer);
        if (len && buffer[len - 1] == '\n') {
            buffer[--len] = '\0';
        }
        // If input exceeded buffer size, clear extra characters to keep stdin clean.
        else if (!feof(stdin)) {
            int ch;
            while ((ch = getchar()) != '\n' && ch != EOF) {}
            wipe_buffer(buffer, size);
            return -1;
        }
        return 0;
    }
}

// Keep reading until all requested bytes are read from the file.
static int read_all(int fd, void *buffer, size_t size) {
    unsigned char *p = buffer;
    while (size) {
        ssize_t n = read(fd, p, size);
        // If interrupted by a signal, try reading again.
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

// Keep writing until all bytes are saved to the file.
static int write_all(int fd, const void *buffer, size_t size) {
    const unsigned char *p = buffer;
    while (size) {
        ssize_t n = write(fd, p, size);
        // If interrupted by a signal, try writing again.
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        p += n;
        size -= (size_t)n;
    }
    return 0;
}

// Turn the master password into a 32-byte encryption key using Argon2id.
static int derive_key(const char *password, const unsigned char *salt, unsigned char *key) {
    return crypto_pwhash(key, crypto_aead_xchacha20poly1305_ietf_KEYBYTES,
                         password, strlen(password), salt,
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13);
}

// Reject control characters inside stored strings.
static int has_no_ctrl(const char *s) {
    for (size_t i = 0; s[i] != '\0'; i++) {
        unsigned char ch = (unsigned char)s[i];
        if (ch < 0x20 || ch == 0x7f) return 0;
    }
    return 1;
}

// Check that record strings are non-empty, NUL-terminated, and free of control bytes.
static int valid_record(const Credential *entry) {
    return memchr(entry->service, '\0', sizeof(entry->service)) &&
           memchr(entry->username, '\0', sizeof(entry->username)) &&
           memchr(entry->password, '\0', sizeof(entry->password)) &&
           entry->service[0] && entry->username[0] && entry->password[0] &&
           has_no_ctrl(entry->service) &&
           has_no_ctrl(entry->username) &&
           has_no_ctrl(entry->password);
}

// Enforce per-user ownership (UID + GID) and strict 0600 permissions on a regular vault file.
static int valid_vault_stat(const struct stat *st) {
    return S_ISREG(st->st_mode) &&
           st->st_uid == getuid() &&
           st->st_gid == getgid() &&
           (st->st_mode & 0777) == 0600;
}

// Encrypt and write vault.bin either atomically as new (create_only=1) or via temp rename (create_only=0).
static int vault_write_file(const char *master_password, const Credential *entries, size_t count, int create_only) {
    if (!master_password || !master_password[0] || count > MAX_ENTRIES || (count && !entries)) return -1;
    for (size_t i = 0; i < count; i++) {
        if (!valid_record(&entries[i])) return -1;
    }

    unsigned char header[HEADER_SIZE];
    unsigned char *salt = header + HEADER_META_LEN;
    unsigned char *nonce = salt + crypto_pwhash_SALTBYTES;
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char cipher[MAX_CIPHER_SIZE];
    unsigned long long cipher_len = 0;

    memcpy(header, VAULT_MAGIC, VAULT_MAGIC_LEN);
    header[4] = VAULT_VERSION;
    header[5] = 0;
    header[6] = 0;
    header[7] = 0;
    randombytes_buf(salt, crypto_pwhash_SALTBYTES);
    randombytes_buf(nonce, crypto_aead_xchacha20poly1305_ietf_NPUBBYTES);

    if (derive_key(master_password, salt, key) != 0) {
        wipe_buffer(key, sizeof(key));
        return -1;
    }

    // Bind the full unencrypted header as AAD so header tampering fails Poly1305 verification.
    size_t plain_len = count * sizeof(Credential);
    static const unsigned char empty = 0;
    const unsigned char *plain = count ? (const unsigned char *)entries : &empty;
    int encrypted = crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipher, &cipher_len, plain, plain_len, header, sizeof(header), NULL, nonce, key);
    wipe_buffer(key, sizeof(key));

    if (encrypted != 0 || cipher_len != plain_len + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        wipe_buffer(cipher, sizeof(cipher));
        return -1;
    }

    char temp[] = VAULT_FILE ".XXXXXX";
    int fd = -1;
    int opened_exclusive = 0;

    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);
    int blocked = sigprocmask(SIG_BLOCK, &block_set, &old_set) == 0;
    int ok = blocked;

    if (ok && create_only) {
        // O_CREAT | O_EXCL prevents TOCTOU overwrite if another process creates vault.bin mid-init.
        fd = open(VAULT_FILE, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK, 0600);
        if (fd >= 0) opened_exclusive = 1;
        else ok = 0;
    } else if (ok) {
        struct stat cur_st;
        if (lstat(VAULT_FILE, &cur_st) != 0 || !valid_vault_stat(&cur_st)) {
            ok = 0;
        } else {
            fd = mkstemp(temp);
            if (fd < 0) ok = 0;
        }
    }

    struct stat fd_st;
    if (ok) {
        ok = fchmod(fd, 0600) == 0 &&
             fstat(fd, &fd_st) == 0 &&
             valid_vault_stat(&fd_st) &&
             write_all(fd, header, sizeof(header)) == 0 &&
             write_all(fd, cipher, (size_t)cipher_len) == 0 &&
             fsync(fd) == 0;
    }

    if (fd >= 0 && close(fd) != 0) ok = 0;

    if (!create_only) {
        if (ok && rename(temp, VAULT_FILE) != 0) ok = 0;
        if (!ok && fd >= 0) unlink(temp);
    } else if (!ok && opened_exclusive) {
        unlink(VAULT_FILE);
    }

    if (blocked) sigprocmask(SIG_SETMASK, &old_set, NULL);
    wipe_buffer(cipher, sizeof(cipher));
    return ok ? 0 : -1;
}

// Atomically create an empty vault (fails if vault.bin already exists).
int vault_create(const char *master_password) {
    return vault_write_file(master_password, NULL, 0, 1);
}

// Encrypt and save all entries into the existing owned vault file.
int vault_save(const char *master_password, const Credential *entries, size_t count) {
    return vault_write_file(master_password, entries, count, 0);
}

// Open the vault file, verify ownership and header AAD, and decrypt all entries.
int vault_load(const char *master_password, Credential *entries, size_t *count_out) {
    if (!master_password || !master_password[0] || !entries || !count_out) return -1;
    *count_out = 0;

    // O_NOFOLLOW blocks symlinks; O_NONBLOCK avoids hanging on FIFOs.
    int fd = open(VAULT_FILE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !valid_vault_stat(&st) ||
        st.st_size < (off_t)(HEADER_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES) ||
        st.st_size > (off_t)(HEADER_SIZE + MAX_CIPHER_SIZE)) {
        close(fd);
        return -1;
    }

    unsigned char header[HEADER_SIZE];
    unsigned char cipher[MAX_CIPHER_SIZE];
    size_t cipher_len = (size_t)st.st_size - HEADER_SIZE;
    size_t plain_len = cipher_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;

    if (plain_len % sizeof(Credential) != 0 ||
        read_all(fd, header, sizeof(header)) != 0 ||
        read_all(fd, cipher, cipher_len) != 0) {
        close(fd);
        wipe_buffer(cipher, sizeof(cipher));
        return -1;
    }
    if (close(fd) != 0) {
        wipe_buffer(cipher, sizeof(cipher));
        return -1;
    }

    if (memcmp(header, VAULT_MAGIC, VAULT_MAGIC_LEN) != 0 ||
        header[4] != VAULT_VERSION || header[5] != 0 || header[6] != 0 || header[7] != 0) {
        wipe_buffer(cipher, sizeof(cipher));
        return -1;
    }

    const unsigned char *salt = header + HEADER_META_LEN;
    const unsigned char *nonce = salt + crypto_pwhash_SALTBYTES;
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (derive_key(master_password, salt, key) != 0) {
        wipe_buffer(key, sizeof(key));
        wipe_buffer(cipher, sizeof(cipher));
        return -1;
    }

    unsigned long long opened_len = 0;
    int opened = crypto_aead_xchacha20poly1305_ietf_decrypt(
        (unsigned char *)entries, &opened_len, NULL, cipher, cipher_len, header, sizeof(header), nonce, key);
    wipe_buffer(key, sizeof(key));
    wipe_buffer(cipher, sizeof(cipher));

    if (opened != 0 || opened_len != plain_len) {
        wipe_buffer(entries, MAX_ENTRIES * sizeof(*entries));
        return -1;
    }

    *count_out = plain_len / sizeof(Credential);
    for (size_t i = 0; i < *count_out; i++) {
        if (!valid_record(&entries[i])) {
            wipe_buffer(entries, MAX_ENTRIES * sizeof(*entries));
            *count_out = 0;
            return -1;
        }
    }
    return 0;
}

// Securely overwrite and unlink an owned regular vault file.
int vault_delete(void) {
    int fd = open(VAULT_FILE, O_RDWR | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return -1;

    struct stat st;
    if (fstat(fd, &st) != 0 || !valid_vault_stat(&st) ||
        st.st_size < 0 || st.st_size > (off_t)(HEADER_SIZE + MAX_CIPHER_SIZE)) {
        close(fd);
        return -1;
    }

    sigset_t block_set, old_set;
    sigemptyset(&block_set);
    sigaddset(&block_set, SIGINT);
    sigaddset(&block_set, SIGTERM);
    int blocked = sigprocmask(SIG_BLOCK, &block_set, &old_set) == 0;
    int ok = blocked;

    if (ok && st.st_size > 0) {
        unsigned char junk[512];
        off_t rem = st.st_size;
        while (rem > 0) {
            size_t chunk = (rem > (off_t)sizeof(junk)) ? sizeof(junk) : (size_t)rem;
            randombytes_buf(junk, chunk);
            if (write_all(fd, junk, chunk) != 0) { ok = 0; break; }
            rem -= (off_t)chunk;
        }
        wipe_buffer(junk, sizeof(junk));
        if (ok && fsync(fd) != 0) ok = 0;
    }

    if (close(fd) != 0) ok = 0;
    if (ok && unlink(VAULT_FILE) != 0) ok = 0;
    if (blocked) sigprocmask(SIG_SETMASK, &old_set, NULL);
    return ok ? 0 : -1;
}

// Accept only safe identifier characters in log fields to prevent log injection.
static int valid_log_token(const char *s) {
    if (!s || !s[0]) return 0;
    size_t len = strlen(s);
    if (len > 48) return 0;
    for (size_t i = 0; i < len; i++) {
        unsigned char ch = (unsigned char)s[i];
        int ok = (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
                 (ch >= '0' && ch <= '9') || ch == '_' || ch == '-';
        if (!ok) return 0;
    }
    return 1;
}

// Append one structured event line to spm.log with symlink, type, owner, and permission checks.
void log_event(const char *event, const char *outcome, const char *detail) {
    const char *safe_detail = (detail && detail[0]) ? detail : "none";
    if (!valid_log_token(event) || !valid_log_token(outcome) || !valid_log_token(safe_detail)) return;

    char ts[32] = "unknown";
    time_t now = time(NULL);
    struct tm utc_tm;
    memset(&utc_tm, 0, sizeof(utc_tm));
    if (now != (time_t)-1 && gmtime_r(&now, &utc_tm) != NULL) {
        if (strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%SZ", &utc_tm) == 0) {
            snprintf(ts, sizeof(ts), "%s", "unknown");
        }
    }

    char line[256];
    int n = snprintf(line, sizeof(line), "ts=%s uid=%lu pid=%ld event=%s outcome=%s detail=%s\n",
                     ts, (unsigned long)getuid(), (long)getpid(), event, outcome, safe_detail);
    if (n <= 0 || (size_t)n >= sizeof(line)) return;

    // O_NOFOLLOW blocks symlinks; O_NONBLOCK avoids hanging if an attacker placed a FIFO.
    int fd = open(LOG_FILE, O_WRONLY | O_CREAT | O_APPEND | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (fd < 0) {
        fputs("Warning: could not update log file.\n", stderr);
        return;
    }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_uid != getuid() ||
        fchmod(fd, 0600) != 0 || write_all(fd, line, (size_t)n) != 0) {
        close(fd);
        fputs("Warning: could not update log file.\n", stderr);
        return;
    }
    if (close(fd) != 0) {
        fputs("Warning: could not update log file.\n", stderr);
    }
}
