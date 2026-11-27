#ifndef VAULT_H
#define VAULT_H

#include <stddef.h>

#define VAULT_FILE  "vault.bin"
#define LOG_FILE    "spm.log"
#define MAX_ENTRIES       50
#define STR_LEN           64
#define PASS_LEN          128
#define MAX_FAIL_ATTEMPTS 10
#define CLIPBOARD_TTL_SEC 30

// One saved entry. Fixed size keeps it simple and safe.
typedef struct {
    char service[STR_LEN];
    char username[STR_LEN];
    char password[PASS_LEN];
} Credential;

// Install handlers for SIGINT, SIGTERM, and SIGHUP, and ignore SIGTSTP. Returns 0 or -1.
int setup_signals(void);

// Prompt or report pending signal exit. Returns 0 to continue or exit code (e.g. 130).
int handle_pending_signals(void);

// Read user input. Hides typing if hidden is 1. Returns 0, -1 (error/EOF), or -2 (signal).
int prompt_input(const char *prompt, char *buffer, size_t size, int hidden);

// Disable core dumps and non-root process memory inspection.
int disable_core_dumps(void);

// Allocate a guarded, swap-locked zero-initialized secret buffer.
void *secure_alloc(size_t size);

// Wipe, unlock, and release a buffer created by secure_alloc().
void secure_free(void *ptr);

// Clear sensitive data from memory.
void wipe_buffer(void *ptr, size_t size);

// Append a structured audit event without secrets to spm.log.
void log_event(const char *event, const char *outcome, const char *detail);

// Atomically create a new vault file (fails if vault.bin already exists).
int vault_create(const char *master_password);

// Encrypt and save all entries to an existing owned vault file.
int vault_save(const char *master_password, const Credential *entries, size_t count);

// Decrypt and load entries. Returns 0 on success, -1 on error, or -2 if wiped after max failed attempts.
int vault_load(const char *master_password, Credential *entries, size_t *count_out, int *attempts_left_out);

// Verify that vault.bin is an owned 0600 regular file without following symlinks.
int vault_check_access(void);

// Overwrite and delete an existing owned vault file.
int vault_delete(void);

#endif
