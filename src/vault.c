#define _POSIX_C_SOURCE 200809L
#include "vault.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <sodium.h>

// File header size: 16-byte salt plus 24-byte nonce.
#define HEADER_SIZE (crypto_pwhash_SALTBYTES + crypto_aead_xchacha20poly1305_ietf_NPUBBYTES)

// Maximum encrypted size: 50 entries plus 16-byte authentication tag.
#define MAX_CIPHER_SIZE (MAX_ENTRIES * sizeof(Credential) + crypto_aead_xchacha20poly1305_ietf_ABYTES)

// Overwrite memory with zeros so secrets do not stay in RAM.
void wipe_buffer(void *ptr, size_t size) {
    if (ptr && size) sodium_memzero(ptr, size);
}

// Read one line of text from the keyboard.
int prompt_input(const char *prompt, char *buffer, size_t size, int hidden) {
    // Check that buffer pointer and size are valid.
    if (!buffer || size < 2 || size > INT_MAX) return -1;

    // Show prompt to the user.
    if (prompt) { fputs(prompt, stdout); fflush(stdout); }

    struct termios old_term;
    int changed = 0;

    // Turn off terminal echo if input is a secret password.
    if (hidden && isatty(STDIN_FILENO)) {
        if (tcgetattr(STDIN_FILENO, &old_term) != 0) return -1;
        struct termios quiet_term = old_term;
        quiet_term.c_lflag &= (tcflag_t)~ECHO;
        if (tcsetattr(STDIN_FILENO, TCSAFLUSH, &quiet_term) != 0) return -1;
        changed = 1;
    }

    // Read the line from stdin.
    char *result = fgets(buffer, (int)size, stdin);

    // Restore terminal settings so typing works normally again.
    if (changed) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
        fputc('\n', stdout);
    }

    // Return error if reading failed.
    if (!result) { wipe_buffer(buffer, size); return -1; }

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

// Check that strings are non-empty and end with a null character.
static int valid_record(const Credential *entry) {
    return memchr(entry->service, '\0', sizeof(entry->service)) &&
           memchr(entry->username, '\0', sizeof(entry->username)) &&
           memchr(entry->password, '\0', sizeof(entry->password)) &&
           entry->service[0] && entry->username[0] && entry->password[0];
}

// Encrypt and save all entries into the vault file.
int vault_save(const char *master_password, const Credential *entries, size_t count) {
    // Validate arguments before doing any work.
    if (!master_password || !master_password[0] || count > MAX_ENTRIES || (count && !entries)) return -1;
    for (size_t i = 0; i < count; i++) {
        if (!valid_record(&entries[i])) return -1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    unsigned char cipher[MAX_CIPHER_SIZE];
    unsigned long long cipher_len = 0;

    // Pick a new random salt and a new random nonce for each save.
    randombytes_buf(salt, sizeof(salt));
    randombytes_buf(nonce, sizeof(nonce));

    // Derive key from password and wipe key buffer on failure.
    if (derive_key(master_password, salt, key) != 0) {
        wipe_buffer(key, sizeof(key));
        return -1;
    }

    // Encrypt all entries with XChaCha20-Poly1305.
    size_t plain_len = count * sizeof(Credential);
    static const unsigned char empty = 0;
    const unsigned char *plain = count ? (const unsigned char *)entries : &empty;
    int encrypted = crypto_aead_xchacha20poly1305_ietf_encrypt(
        cipher, &cipher_len, plain, plain_len, NULL, 0, NULL, nonce, key);

    // Erase the encryption key from RAM immediately after encryption.
    wipe_buffer(key, sizeof(key));

    // Check if encryption succeeded.
    if (encrypted != 0 || cipher_len != plain_len + crypto_aead_xchacha20poly1305_ietf_ABYTES) {
        wipe_buffer(cipher, sizeof(cipher));
        return -1;
    }

    // Write to a temporary file first, so old data is safe if writing is interrupted.
    char temp[] = VAULT_FILE ".XXXXXX";
    int fd = mkstemp(temp);
    if (fd < 0) { wipe_buffer(cipher, sizeof(cipher)); return -1; }

    // Set file permissions to 0600 so only the file owner can read or write it.
    fchmod(fd, 0600);

    // Write header (salt + nonce) and encrypted data, then force to disk with fsync.
    int ok = write_all(fd, salt, sizeof(salt)) == 0 &&
             write_all(fd, nonce, sizeof(nonce)) == 0 &&
             write_all(fd, cipher, (size_t)cipher_len) == 0 &&
             fsync(fd) == 0;

    if (close(fd) != 0) ok = 0;

    // Safely replace the old vault file with the new temporary file.
    if (ok && rename(temp, VAULT_FILE) != 0) ok = 0;

    // If writing failed, delete the temporary file.
    if (!ok) unlink(temp);

    // Clear encrypted buffer from RAM.
    wipe_buffer(cipher, sizeof(cipher));
    return ok ? 0 : -1;
}

// Open the vault file, authenticate the data, and decrypt all entries.
int vault_load(const char *master_password, Credential *entries, size_t *count_out) {
    // Validate input arguments.
    if (!master_password || !master_password[0] || !entries || !count_out) return -1;
    *count_out = 0;

    // Open file. O_NOFOLLOW stops attackers from using symlinks to steal other files.
    int fd = open(VAULT_FILE, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    // Check file stats: must be a regular file, and size must be within valid bounds.
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) ||
        st.st_size < (off_t)(HEADER_SIZE + crypto_aead_xchacha20poly1305_ietf_ABYTES) ||
        st.st_size > (off_t)(HEADER_SIZE + MAX_CIPHER_SIZE)) {
        close(fd);
        return -1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_aead_xchacha20poly1305_ietf_NPUBBYTES];
    unsigned char cipher[MAX_CIPHER_SIZE];

    // Compute expected lengths for encrypted data and plaintext.
    size_t cipher_len = (size_t)st.st_size - HEADER_SIZE;
    size_t plain_len = cipher_len - crypto_aead_xchacha20poly1305_ietf_ABYTES;

    // Read salt, nonce, and ciphertext from the file.
    if (plain_len % sizeof(Credential) != 0 ||
        read_all(fd, salt, sizeof(salt)) != 0 ||
        read_all(fd, nonce, sizeof(nonce)) != 0 ||
        read_all(fd, cipher, cipher_len) != 0) {
        close(fd);
        return -1;
    }
    close(fd);

    // Derive key using the password and the salt read from the file.
    unsigned char key[crypto_aead_xchacha20poly1305_ietf_KEYBYTES];
    if (derive_key(master_password, salt, key) != 0) {
        wipe_buffer(key, sizeof(key));
        wipe_buffer(cipher, sizeof(cipher));
        return -1;
    }

    // Decrypt data and verify authentication tag. Fails if password is wrong or file was changed.
    unsigned long long opened_len = 0;
    int opened = crypto_aead_xchacha20poly1305_ietf_decrypt(
        (unsigned char *)entries, &opened_len, NULL, cipher, cipher_len, NULL, 0, nonce, key);

    // Wipe decryption key and ciphertext buffer from RAM immediately.
    wipe_buffer(key, sizeof(key));
    wipe_buffer(cipher, sizeof(cipher));

    // Check if decryption succeeded.
    if (opened != 0 || opened_len != plain_len) {
        wipe_buffer(entries, MAX_ENTRIES * sizeof(*entries));
        return -1;
    }

    // Calculate number of loaded entries and validate all record strings.
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
