# fernet-cracker

Authors: Hamid Kashfi (X: @hkashfi), Codex

Generic Fernet cracker with wordlist, mask, and bruteforce modes. Includes pause/resume, progress, and hashcat-style masks.

## Build
```
cargo build --release
```

## Usage
```
./target/release/fernet_bruteforce --token <TOKEN_OR_FILE> wordlist <WORDLIST>
./target/release/fernet_bruteforce --token <TOKEN_OR_FILE> mask "?d?d?d?d"
./target/release/fernet_bruteforce --token <TOKEN_OR_FILE> bruteforce "?h" 6 8
```

### Common Options
- `--token`: Fernet token string or path to a file containing the token
- `--threads`: number of worker threads (defaults to CPU count)
- `--out`: write decrypted plaintext to a file
- `--state`: save progress to a state file (for pause/resume)
- `--resume`: resume from the state file
- `--no-input`: disable interactive controls

Interactive controls:
- `p`: pause/resume
- `q`: quit

## Mask Tokens
Hashcat-style sets:
- `?l` / `?L`: lowercase letters
- `?u` / `?U`: uppercase letters
- `?d` / `?D`: digits
- `?m` / `?M`: mixed case (lower + upper)
- `?h` / `?H`: alnum (lower + upper + digits)
- `?s`: symbols
- `?a` / `?A`: all (lower + upper + digits + symbols)
- `??`: literal `?`

Examples:
```
# 4-digit PIN
./target/release/fernet_bruteforce --token token.txt mask "?d?d?d?d"

# 6 lowercase letters
./target/release/fernet_bruteforce --token token.txt mask "?l?l?l?l?l?l"

# 8 alnum brute-force
./target/release/fernet_bruteforce --token token.txt bruteforce "?h" 8 8
```

## Extracting Fernet Tokens

### From PNG LSB (Stegano-style)
If a PNG hides a Stegano-style payload, the extracted stream begins with:
```
<length>:<token>
```

You can detect using zsteg:
```
zsteg -a image.png
```
Look for:
```
b1,rgb,lsb,xy .. text: "120:gAAAAA...$"
```

### From MP4 Trailer (STEG markers)
Some files append a payload between markers:
```
<<--STEG_START-->> ... <<--STEG_END-->>
```

You can detect with:
```
exiftool -a -u -g1 video.mp4
rg -a -n "STEG_START|STEG_END" video.mp4
```

## End-to-End Python Extractor
Script is included at `scripts/extract_fernet_token.py`. It supports PNG LSB (Stegano-style), STEG markers in trailers, and raw scanning for Fernet-like tokens in any file. It also lists multiple hits and lets you select an index.
PNG extraction requires Pillow: `pip install pillow`.

Examples:
```
# Extract first token found
python3 scripts/extract_fernet_token.py sample.bin -o fernet_token.txt

# List all tokens with offsets
python3 scripts/extract_fernet_token.py sample.bin --list

# Select a specific token
python3 scripts/extract_fernet_token.py sample.bin --list --index 2 -o token2.txt
```

Then crack:
```
./target/release/fernet_bruteforce --token fernet_token.txt wordlist /path/to/wordlist.txt
```
