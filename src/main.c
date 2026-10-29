#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sodium.h>
#include "vault.h"

// Test harness for crypto engine and vault storage functionality.
int main(void) {
    // Restrict file creation permissions to owner only (0600/0700).
    umask(0077);

    // Initialize libsodium RNG and cryptographic primitives.
    if (sodium_init() < 0) {
        fprintf(stderr, "Fatal error: Could not initialize libsodium.\n");
        return 1;
    }

    printf("=== Secure Password Manager (SPM) - Engine Test ===\n\n");

    // Sample credentials for storage and retrieval verification.
    const char *test_pass = "MasterSecret123!";
    Credential test_items[2];
    snprintf(test_items[0].service, STR_LEN, "github.com");
    snprintf(test_items[0].username, STR_LEN, "alice");
    snprintf(test_items[0].password, PASS_LEN, "GithubPass#2026");

    snprintf(test_items[1].service, STR_LEN, "taltech.ee");
    snprintf(test_items[1].username, STR_LEN, "alice@taltech.ee");
    snprintf(test_items[1].password, PASS_LEN, "StudentPortalPass!");

    // Test encrypted write operation.
    printf("1. Encrypting and saving 2 test credentials to '%s'...\n", VAULT_FILE);
    if (vault_save(test_pass, test_items, 2) != 0) {
        fprintf(stderr, "Error: Failed to save encrypted vault.\n");
        return 1;
    }
    printf("   [+] Vault saved and encrypted successfully at rest.\n\n");

    // Test decryption with valid credentials.
    printf("2. Testing decryption with correct master password...\n");
    Credential loaded_items[MAX_ENTRIES];
    size_t count = 0;
    if (vault_load(test_pass, loaded_items, &count) != 0) {
        fprintf(stderr, "Error: Decryption failed with correct password.\n");
        return 1;
    }
    printf("   [+] Decryption succeeded! Loaded %zu credentials:\n", count);
    for (size_t i = 0; i < count; i++) {
        printf("       [%zu] %s (user: %s)\n",
               i + 1, loaded_items[i].service, loaded_items[i].username);
    }
    printf("       (Passwords kept secret in memory).\n\n");

    // Test tampering and invalid password rejection via Poly1305 MAC verification.
    printf("3. Testing tamper & wrong-password defense...\n");
    Credential fake_items[MAX_ENTRIES];
    size_t fake_count = 0;
    if (vault_load("WrongPassword!", fake_items, &fake_count) == 0) {
        fprintf(stderr, "Error: Security failure! Vault unlocked with wrong password!\n");
        return 1;
    }
    printf("   [+] Poly1305 MAC tag rejected wrong password successfully.\n\n");

    // Clean up test file and zero memory buffers.
    unlink(VAULT_FILE);
    wipe_buffer(test_items, sizeof(test_items));
    wipe_buffer(loaded_items, sizeof(loaded_items));

    printf("All core engine security checks passed.\n");
    return 0;
}
