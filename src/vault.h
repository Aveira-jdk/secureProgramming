#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>

#define VAULT_FILE  "vault.bin"
#define MAX_ENTRIES 50
#define STR_LEN     64
#define PASS_LEN    128

// Fixed-size structure to allow memory clearing without dynamic pointer tracking
typedef struct {
    char service[STR_LEN];
    char username[STR_LEN];
    char password[PASS_LEN];
} Credential;

int prompt_password(const char *prompt, char *buffer, size_t max_size);
void wipe_buffer(void *ptr, size_t size);
int vault_save(const char *master_password, const Credential *entries, size_t count);
int vault_load(const char *master_password, Credential *entries, size_t *count_out);

#endif
