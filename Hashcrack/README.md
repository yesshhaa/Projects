# HashCrack

A lean, dependency-free (stdlib only) tool that combines:
1. **OSINT-based wordlist generation** — builds targeted password guesses from
   personal details (name, pet, birth year, company, etc.), applying
   leetspeak, case, and suffix/year mutations.
2. **Hash cracking** — dictionary attack first, with an optional capped
   brute-force fallback for short passwords.

## Why this project exists
Most successful password attacks don't rely on raw brute force — they rely on
predictable human behavior (birthdays, pet names, "123" at the end). This tool
demonstrates that attack pattern to make the defensive case: **use random
passphrases, not personalized passwords.**

## Project structure
```
hashcrack/
├── main.py          # CLI entry point
├── wordlist.py       # wordlist generation logic
├── cracker.py         # hashing + cracking logic
├── data/
│   └── common_passwords.txt
└── output/
    └── generated_wordlist.txt   # created on first run
```

## Usage

Crack a hash using a personal-info wordlist:
```bash
python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99 --inputs john fluffy acme 1990
```

Crack a hash using only the common password list:
```bash
python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
```

Use an existing wordlist file:
```bash
python main.py --hash <hash> --wordlist output/generated_wordlist.txt
```

Skip the brute-force fallback:
```bash
python main.py --hash <hash> --inputs john --no-brute-force
```

Force a hash algorithm if auto-detection is ambiguous:
```bash
python main.py --hash <hash> --algo sha256
```

## How hash type is detected
Detection is based on hex string length only (a simple, transparent
heuristic — not a guarantee):
| Length | Algorithm |
|--------|-----------|
| 32     | MD5       |
| 40     | SHA1      |
| 64     | SHA256    |

## Sample output
```
[+] Hash type: md5
[+] Generated 842 candidate passwords -> output/generated_wordlist.txt
[+] Starting attack...

----- RESULT -----
Password found: password1
Method:   dictionary
Attempts: 214
Time:     0.0021 sec
Rate:     101,904 attempts/sec
```

## Defensive takeaway
This project is for educational and authorized-testing use only (e.g.
cracking your own hashes, or testing systems you have explicit permission
to test). It illustrates why:
- Personalized passwords (names, pets, birthdates) are trivially guessable.
- Adding a static suffix like `!` or `123` provides almost no real protection.
- Longer, random passphrases resist both dictionary and brute-force attacks
  far better than "clever" substitutions.

## Possible next steps
- Plug in your hash identifier tool for smarter auto-detection.
- Add bcrypt/sha512crypt support for a "modern hash" comparison.
- Feed timing results into your hash-cracking-speed comparison tool.
