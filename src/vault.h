#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>

#define VAULT_FILE  "vault.bin"
#define MAX_ENTRIES 50
#define STR_LEN     64
#define PASS_LEN    128

// One saved entry. Fixed size keeps it simple and safe.
typedef struct {
    char service[STR_LEN];
    char username[STR_LEN];
    char password[PASS_LEN];
} Credential;

// Read user input. Hides typing if hidden is 1.
int prompt_input(const char *prompt, char *buffer, size_t size, int hidden);

// Clear sensitive data from memory.
void wipe_buffer(void *ptr, size_t size);

// Encrypt and save all entries to the vault file.
int vault_save(const char *master_password, const Credential *entries, size_t count);

// Decrypt and load all entries from the vault file.
int vault_load(const char *master_password, Credential *entries, size_t *count_out);

#endif
