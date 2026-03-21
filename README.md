# Encrypted Cloud Storage

Final project for the Cryptography Engineering course (WS 2025/26).

The goal was to build a system where a client can store and retrieve files from an untrusted server — meaning the server should learn nothing useful even if it reads everything it stores. The report (`report_final.pdf`) goes into more detail on the design choices.

## What it does

- **register** — creates a user profile with an Argon2id password hash and a random HKDF salt
- **upload** — encrypts a file with AES-256-GCM and stores it under a random UUID on the server
- **download** — decrypts a file and writes it locally
- **list** — decrypts the manifest and shows all stored filenames with their sizes
- **delete** — removes the encrypted blob and its entry from the manifest

The server (simulated as a local directory) only ever sees random UUIDs and encrypted blobs. Filenames are hidden inside an encrypted manifest (`manifest.enc`).

## Crypto stack

| Primitive | Purpose |
| Argon2id | Password hashing — memory-hard, resistant to GPU brute-force |
| HKDF-SHA256 | Derives two independent keys from the Argon2 output |
| AES-256-GCM | Authenticated encryption for file contents and the manifest |

Two separate keys are derived via HKDF: `file_key` for file contents and `meta_key` for the manifest. They use different info labels so compromising one tells you nothing about the other.

## Build & run

bash
cargo build --release
cargo test

# Register
./target/release/ecs register --username alice --password MyPassword

# Upload a file
./target/release/ecs upload secret.pdf --password MyPassword

# List vault contents
./target/release/ecs list --password MyPassword

# Download a file
./target/release/ecs download secret.pdf --dest ./out --password MyPassword

# Delete a file
./target/release/ecs delete secret.pdf --password MyPassword

# End-to-end demo (no setup needed)
./target/release/ecs demo

On Windows use `ecs.exe` instead of `ecs`.

## Project structure

src/
├── main.rs              CLI (clap)
├── crypto/
│   ├── password.rs      Argon2id
│   ├── keys.rs          HKDF-SHA256
│   └── aead.rs          AES-256-GCM
├── storage/
│   ├── manifest.rs      Encrypted file index
│   └── vault.rs         Server abstraction
└── client/
    ├── profile.rs       User profile (persisted)
    └── session.rs       register / login / upload / download / delete

## Report

`report_final.pdf` covers the design in more depth: threat model, explanation of the 5 most important functions (what they do, how they work, why they're secure), and known limitations.

## Tests

bash
cargo test

26 tests across all modules. The most interesting one is `vault_contains_no_plaintext` — it uploads a file and then scans every raw byte in the vault directory to assert that neither the file content nor the filename appear anywhere in cleartext.
