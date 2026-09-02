# bip39-scanner

A BIP39 mnemonic scanner for Bitcoin bech32 addresses. All crypto primitives
(SHA-256, SHA-512, HMAC, RIPEMD-160, PBKDF2, secp256k1, Bech32) are
implemented from scratch — no external crypto crates are used. The only
dependencies are `clap`, `serde`, `serde_json`, and `toml`.

## Features

- Walks the full 12-word BIP39 mnemonic space (`2^132` combinations).
- Match modes: exact address, vanity prefix, or batch list from a file.
- Checkpoint + resume: progress is persisted to a JSON file every N mnemonics.
- Ticket manager: pre-computed contiguous work ranges for distributed workers.
- Validate a single mnemonic and print its derived bech32 address.
- Generate 12 / 15 / 18 / 21 / 24-word mnemonics from any of the five
  standard entropy sizes (128 / 160 / 192 / 224 / 256 bits).
- Export a hit record (`timestamp\tindex\tmnemonic\taddress`) to a file.
- TOML config file with sensible defaults; CLI flags always override config.

## Build

```
# CI verifies all Rust projects on this machine — do not run cargo locally.
cd bip39-scanner
cargo build --release      # CI only
cargo test                 # CI only
```

The release binary lands at `target/release/bip39-scanner`.

## Usage

### Scan for an exact address

```
bip39-scanner scan -t bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 \
                   --checkpoint cp.json --verbose
```

The full space is `2048^11 ≈ 2.56 × 10^39`. Even at high rates, brute-force
search is only realistic against vanity prefixes.

### Vanity prefix scan

```
bip39-scanner scan --prefix bc1qw --checkpoint cp.json --save-every 50000
```

The scanner stops at the first hit and writes the matching mnemonic to the
checkpoint file as `state: Found`.

### Resume an interrupted scan

```
bip39-scanner scan --prefix bc1qw --checkpoint cp.json --resume
```

The checkpoint stores `current_index`, `scanned_count`, and `state`. Resuming
picks up at `current_index`.

### Batch target file

```
# targets.txt — one address per line, '#' starts a comment
bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4
bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq

bip39-scanner scan --targets targets.txt --export-match found.txt
```

### Validate a mnemonic

```
bip39-scanner validate \
    --mnemonic "abandon abandon abandon abandon abandon abandon \
                abandon abandon abandon abandon abandon about"
bip39-scanner validate -m "..." -p "TREZOR" --path "m/44'/0'/0'/0/0"
```

### Check a mnemonic against a target address

Verify that a user-supplied 12-word mnemonic (or a file of them) derives to a
specific bech32 address, a vanity prefix, or any address from a target file.

```
bip39-scanner check -m "abandon abandon abandon abandon abandon abandon \
                       abandon abandon abandon abandon abandon about" \
                  -t bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4

bip39-scanner check -t bc1q... --mnemonics-file candidates.txt

bip39-scanner check -t bc1q... --targets-file targets.txt --stop-on-first-match
```

Exit codes: `0` = match found, `3` = no match, `2` = bad arguments.

### Generate mnemonics

```
bip39-scanner generate --count 5
bip39-scanner generate -c 1 --entropy 32       # 24 words (256-bit entropy)
bip39-scanner generate -c 3 --entropy 24       # 18 words (192-bit entropy)
```

### Config file

```
bip39-scanner config -o config.toml
bip39-scanner scan --config config.toml --prefix bc1q
```

`config.toml` lets you set `target_address`, `derivation_path`, `passphrase`,
`threads`, `batch_size`, `checkpoint_interval`, `save_progress_every`, and
`log_file`. CLI flags override config-file values.

### Checkpoint inspection

```
bip39-scanner checkpoint -f cp.json show
bip39-scanner checkpoint -f cp.json resume
bip39-scanner checkpoint -f cp.json reset
```

### Ticket manager

Splits the full range into fixed-size tickets that can be distributed across
multiple workers. The output is `<file>.tickets`:

```
bip39-scanner ticket --checkpoint cp.json --ticket-size 1000000
```

## Architecture

```
src/
├── lib.rs           # public module re-exports
├── main.rs          # CLI (clap derive) + scan loop
├── sha256.rs        # SHA-256
├── sha512.rs        # SHA-512
├── hmac.rs          # HMAC-SHA512
├── ripemd160.rs     # RIPEMD-160 + HASH160
├── pbkdf2.rs        # PBKDF2-HMAC-SHA512
├── secp256k1.rs     # secp256k1 field + point ops + ECDSA-secp256k1 pubkey
├── bech32.rs        # Bech32 + Bech32m (segwit address encoding)
├── bip39.rs         # wordlist (2048 words), entropy ↔ mnemonic, checksum
├── bip32.rs         # master-from-seed + CKDpriv + path parsing
├── config.rs        # TOML config types + load/save/default
├── checkpoint.rs    # resumable scan state (JSON)
└── ticket.rs        # fixed-size work tickets (JSON)
```

## Test vectors

The crate ships unit tests for:

- The 12-word "abandon × 11, about" vector with empty entropy and passphrase
  `"TREZOR"` (verified against the canonical BIP39 seed
  `c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e5349553…`).
- Round-trip `entropy → mnemonic → entropy` for 12, 15, 18, 21, and 24-word
  mnemonics.
- Word index round-trips for all 2048 wordlist entries.
- BIP32 master-from-seed, child derivation, depth, and address format.

## License

MIT.