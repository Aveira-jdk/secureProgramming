#include <stdio.h>
#include <sodium.h>

int main(void) {
    if (sodium_init() < 0) {
        fprintf(stderr, "Error: Could not initialize libsodium.\n");
        return 1;
    }

    printf("=== Secure Password Manager (SPM) ===\n");
    printf("Libsodium initialized successfully.\n");
    return 0;
}
