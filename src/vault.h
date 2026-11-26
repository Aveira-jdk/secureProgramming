#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>

#define VAULT_FILE  "vault.bin"
#define LOG_FILE    "spm.log"
#define MAX_ENTRIES 50
#define STR_LEN     64
#define PASS_LEN    128

// One saved entry. Fixed size keeps it simple and safe.
typedef struct {
    char service[STR_LEN];
    char username[STR_LEN];
    char password[PASS_LEN];
} Credential;

// Install handlers for SIGINT, SIGTERM, and SIGHUP, and ignore SIGTSTP.
void setup_signals(void);

// Prompt or report pending signal exit. Returns 0 to continue or exit code (e.g. 130).
int handle_pending_signals(void);

// Read user input. Hides typing if hidden is 1. Returns 0, -1 (error/EOF), or -2 (signal).
int prompt_input(const char *prompt, char *buffer, size_t size, int hidden);

// Clear sensitive data from memory.
void wipe_buffer(void *ptr, size_t size);

// Append a structured audit event without secrets to spm.log.
void log_event(const char *event, const char *outcome, const char *detail);

// Atomically create a new vault file (fails if vault.bin already exists).
int vault_create(const char *master_password);

// Encrypt and save all entries to an existing owned vault file.
int vault_save(const char *master_password, const Credential *entries, size_t count);

// Decrypt and load all entries from the vault file.
int vault_load(const char *master_password, Credential *entries, size_t *count_out);

// Overwrite and delete an existing owned vault file.
int vault_delete(void);

#endif
