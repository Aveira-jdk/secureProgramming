#include "vault.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <termios.h>
#include <sys/stat.h>
#include <sodium.h>

// Worst-case capacity: 50 entries * (64 + 64 + 128 + 3 delimiters) = 12950 bytes
#define TEXT_BUF_SIZE 16384

// sodium_memzero is used instead of memset because compilers may optimise
// away standard memset calls when buffers are no longer referenced, leaving
// sensitive material in RAM.
void wipe_buffer(void *ptr, size_t size) {
    if (ptr && size > 0) {
        sodium_memzero(ptr, size);
    }
}

int prompt_password(const char *prompt, char *buffer, size_t max_size) {
    if (!buffer || max_size == 0) return -1;

    if (prompt) {
        printf("%s", prompt);
        fflush(stdout);
    }

    struct termios old_term, new_term;
    int is_term = isatty(STDIN_FILENO);

    // tcgetattr returns ENOTTY when standard input is a pipe (e.g. echo pw | ./spm).
    // Terminal attributes are modified only when input is an interactive terminal.
    if (is_term) {
        if (tcgetattr(STDIN_FILENO, &old_term) == 0) {
            new_term = old_term;
            new_term.c_lflag &= ~ECHO;
            tcsetattr(STDIN_FILENO, TCSAFLUSH, &new_term);
        }
    }

    char *res = fgets(buffer, (int)max_size, stdin);

    // Restore terminal attributes to avoid leaving terminal echo disabled.
    if (is_term) {
        tcsetattr(STDIN_FILENO, TCSAFLUSH, &old_term);
        printf("\n");
    }

    if (!res) return -1;

    size_t len = strlen(buffer);
    if (len > 0 && buffer[len - 1] == '\n') {
        buffer[len - 1] = '\0';
    }

    return 0;
}

// Argon2id key derivation: converts master password and salt into a 32-byte key.
// Memory-hard design resists GPU and ASIC offline dictionary attacks.
static int make_key(const char *password, const unsigned char *salt,
                    unsigned char *key_out) {
    return crypto_pwhash(key_out, crypto_secretbox_KEYBYTES,
                         password, strlen(password), salt,
                         crypto_pwhash_OPSLIMIT_INTERACTIVE,
                         crypto_pwhash_MEMLIMIT_INTERACTIVE,
                         crypto_pwhash_ALG_ARGON2ID13);
}

int vault_save(const char *master_password, const Credential *entries,
               size_t count) {
    if (!master_password || master_password[0] == '\0') return -1;

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    unsigned char key[crypto_secretbox_KEYBYTES];

    // Preserve existing salt across updates to ensure consistent key derivation.
    // A fresh salt is generated only when creating a new vault file.
    int fd = open(VAULT_FILE, O_RDONLY | O_NOFOLLOW);
    if (fd < 0 || read(fd, salt, sizeof(salt)) != sizeof(salt)) {
        randombytes_buf(salt, sizeof(salt));
    }
    if (fd >= 0) close(fd);

    // Nonce must be unique for each encryption operation.
    // Reusing nonces under the same key compromises stream cipher confidentiality.
    randombytes_buf(nonce, sizeof(nonce));

    if (make_key(master_password, salt, key) != 0) {
        return -1;
    }

    // Serialise entries as "service:username:password\n" records.
    // Colons in service and username fields are restricted at input boundaries.
    char text[TEXT_BUF_SIZE] = {0};
    size_t text_len = 0;
    if (entries && count > 0) {
        for (size_t i = 0; i < count; i++) {
            int written = snprintf(text + text_len, sizeof(text) - text_len,
                                   "%s:%s:%s\n",
                                   entries[i].service,
                                   entries[i].username,
                                   entries[i].password);
            if (written > 0 && (size_t)written < sizeof(text) - text_len) {
                text_len += (size_t)written;
            }
        }
    }

    // Authenticated encryption (AEAD): provides confidentiality via XChaCha20
    // and integrity/authenticity verification via a 16-byte Poly1305 MAC tag.
    size_t cipher_len = text_len + crypto_secretbox_MACBYTES;
    unsigned char *ciphertext = malloc(cipher_len);
    if (!ciphertext) {
        wipe_buffer(text, sizeof(text));
        wipe_buffer(key, sizeof(key));
        return -1;
    }

    crypto_secretbox_easy(ciphertext, (unsigned char *)text, text_len, nonce, key);
    wipe_buffer(text, sizeof(text));
    wipe_buffer(key, sizeof(key));

    // O_NOFOLLOW prevents symlink traversal attacks targeting arbitrary files.
    // File mode 0600 restricts read and write permissions to the file owner only.
    fd = open(VAULT_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, 0600);
    if (fd < 0) {
        free(ciphertext);
        return -1;
    }
    fchmod(fd, 0600);

    // On-disk layout: [salt 16B] [nonce 24B] [ciphertext + MAC tag]
    if (write(fd, salt, sizeof(salt)) != sizeof(salt) ||
        write(fd, nonce, sizeof(nonce)) != sizeof(nonce) ||
        write(fd, ciphertext, cipher_len) != (ssize_t)cipher_len) {
        free(ciphertext);
        close(fd);
        return -1;
    }

    free(ciphertext);
    close(fd);
    return 0;
}

int vault_load(const char *master_password, Credential *entries,
               size_t *count_out) {
    if (!master_password || master_password[0] == '\0') return -1;
    if (!entries || !count_out) return -1;
    *count_out = 0;

    int fd = open(VAULT_FILE, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;

    // Validate minimum file size: file must contain salt, nonce, and Poly1305 MAC tag.
    struct stat st;
    size_t header_size = crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES;
    if (fstat(fd, &st) != 0 ||
        st.st_size < (off_t)(header_size + crypto_secretbox_MACBYTES)) {
        close(fd);
        return -1;
    }

    unsigned char salt[crypto_pwhash_SALTBYTES];
    unsigned char nonce[crypto_secretbox_NONCEBYTES];
    if (read(fd, salt, sizeof(salt)) != sizeof(salt) ||
        read(fd, nonce, sizeof(nonce)) != sizeof(nonce)) {
        close(fd);
        return -1;
    }

    size_t cipher_len = (size_t)st.st_size - header_size;
    unsigned char *ciphertext = malloc(cipher_len);
    if (!ciphertext) {
        close(fd);
        return -1;
    }

    if (read(fd, ciphertext, cipher_len) != (ssize_t)cipher_len) {
        free(ciphertext);
        close(fd);
        return -1;
    }
    close(fd);

    unsigned char key[crypto_secretbox_KEYBYTES];
    if (make_key(master_password, salt, key) != 0) {
        free(ciphertext);
        return -1;
    }

    // Authentication check: Poly1305 MAC verification occurs during decryption.
    // Incorrect keys or modified ciphertexts cause immediate rejection without output.
    size_t plain_len = cipher_len - crypto_secretbox_MACBYTES;
    char *text = malloc(plain_len + 1);
    if (!text) {
        wipe_buffer(key, sizeof(key));
        free(ciphertext);
        return -1;
    }

    if (crypto_secretbox_open_easy((unsigned char *)text, ciphertext,
                                   cipher_len, nonce, key) != 0) {
        wipe_buffer(key, sizeof(key));
        free(ciphertext);
        free(text);
        return -1;
    }

    wipe_buffer(key, sizeof(key));
    free(ciphertext);
    text[plain_len] = '\0';

    // Parse records into credential structures
    const char *line_start = text;
    while (*line_start != '\0' && *count_out < MAX_ENTRIES) {
        const char *line_end = strchr(line_start, '\n');
        size_t line_len = line_end ? (size_t)(line_end - line_start)
                                   : strlen(line_start);

        char line[STR_LEN * 2 + PASS_LEN + 10];
        if (line_len < sizeof(line)) {
            memcpy(line, line_start, line_len);
            line[line_len] = '\0';

            char *c1 = strchr(line, ':');
            if (c1) {
                *c1 = '\0';
                char *c2 = strchr(c1 + 1, ':');
                if (c2) {
                    *c2 = '\0';

                    strncpy(entries[*count_out].service, line, STR_LEN - 1);
                    entries[*count_out].service[STR_LEN - 1] = '\0';

                    strncpy(entries[*count_out].username, c1 + 1, STR_LEN - 1);
                    entries[*count_out].username[STR_LEN - 1] = '\0';

                    strncpy(entries[*count_out].password, c2 + 1, PASS_LEN - 1);
                    entries[*count_out].password[PASS_LEN - 1] = '\0';

                    (*count_out)++;
                }
            }
            wipe_buffer(line, sizeof(line));
        }

        if (!line_end) break;
        line_start = line_end + 1;
    }

    wipe_buffer(text, plain_len);
    free(text);
    return 0;
}
