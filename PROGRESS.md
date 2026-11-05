# Checkpoint 2 Progress Note

## What works right now

The password manager runs from the command line and handles the core workflow:

- `./spm init`: creates a new vault file (`vault.bin`) with owner-only permissions (`0600`) and asks for a master password.
- `./spm add <service>`: asks for a username and password, then saves the entry into the vault.
- `./spm list`: prints all saved service names and usernames. It never prints passwords.
- `./spm get <service>`: copies the saved password directly to the system clipboard using `wl-copy`, `xclip`, or `clip.exe`. It does not print the password in the terminal.
- `./spm del <service>`: removes a service from the vault and cleans up the stored records.

### Security and crypto

- The vault file is encrypted using libsodium's `crypto_aead_xchacha20poly1305_ietf`. The master password itself is never saved to disk.
- When opening the vault, `Argon2id` (`crypto_pwhash`) turns the master password and a 16-byte random salt into the encryption key.
- If an incorrect master password is entered, or if someone alters the bytes in `vault.bin`, decryption fails and the program stops immediately.
- Terminal echo is turned off while typing passwords (using `<termios.h>`), so characters are not visible on screen.
- Buffers holding passwords, keys, and credentials are wiped with `sodium_memzero()` before the program exits.
- When saving, data is written to a temporary file first. It is synced with `fsync()` and moved into place with `rename()`. This stops the file from getting corrupted if the program stops midway.

### Error handling

- Error messages are kept short and generic (for example, `"Could not unlock the vault"` or `"Invalid password input"`) so they do not leak information about what went wrong.
- Service names are checked so only normal printable characters are accepted.
- Return codes from file operations and library calls are checked. If anything fails, buffers are cleared and the program exits with code `1`.

## How to build and run on a clean machine

Install the required tools on Ubuntu or WSL:

```bash
sudo apt update
sudo apt install -y build-essential libsodium-dev wl-clipboard xclip
```

Compile the program:

```bash
make
```

Run commands:

```bash
./spm init
./spm add github
./spm list
./spm get github
./spm del github
```

## Plans for Checkpoint 3

Here is what is left for the next checkpoint:

- **Automated test suite:** Add a test script to test all commands, wrong password handling, and corrupted files automatically.
- **Event logging:** Add a log file to record events like opening the vault or failed attempts with timestamps. Passwords and keys must never be logged.
- **User access checks:** Add user ID checks with `getuid()` so users cannot touch each other's vaults on a shared system.
- **Memory checks:** Run tests with `valgrind` to make sure there are no memory leaks.
- **Hardware key support (optional idea):** Look into using a hardware key (like a Flipper Zero with FIDO2, or a YubiKey) for physical unlocking, if it can be added simply.
