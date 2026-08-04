# Async Directory Brute-Forcer

A Python tool that discovers hidden directories, files, and backup artifacts on a web server by requesting paths from a wordlist and analyzing the responses — the same recon technique behind tools like `gobuster`, `dirb`, and `ffuf`.

**MITRE ATT&CK:** T1595.003 — Active Scanning: Wordlist Scanning (Reconnaissance)

---

## Why this project

Directory brute-forcing is one of the first things a pentester or attacker does during recon: find the `/admin` panel, the forgotten `.env` file, the `backup.zip` someone left in web root. Building the tool yourself (instead of just running `gobuster`) forces you to understand *why* it works — and to solve the problems real scanners have to solve, like servers that return `200 OK` for every URL (soft 404s), which would otherwise flood your results with garbage.

## How it works

1. **Load wordlist** — reads paths from a `.txt` file, one per line
2. **Extension fuzzing** — optionally appends extensions (`.bak`, `.env`, `.zip`, `.php`) to every word, since backup/config leaks are usually found this way, not by guessing the base name alone
3. **Baseline probe** — before scanning, requests a random path that's guaranteed not to exist (e.g. `/this-path-should-not-exist-8x7z2q1`) and records its status code + response length. This baseline is what makes soft-404 detection possible
4. **Async requests** — uses `asyncio` + `aiohttp` to fire many requests concurrently instead of one at a time, controlled by a semaphore so you don't overwhelm the target or your own network
5. **Response classification** — compares every real response against the baseline:
   - Status not in the "interesting" set (200, 201, 204, 301, 302, 307, 308, 401, 403, 405) → discarded as ordinary 404
   - Status *and* response length both match the baseline within a small tolerance → discarded as a soft 404, even if the status code was 200
   - Otherwise → reported as a finding
6. **Output** — live progress bar + colorless terminal findings, exportable to JSON or CSV

## Project structure

```
dir-bruteforcer/
├── dir_bruteforcer.py     # main script
├── wordlist_common.txt    # sample wordlist (~55 common paths)
└── README.md
```

## Requirements

```bash
pip install aiohttp
```

## Usage

Basic scan:
```bash
python dir_bruteforcer.py -u http://target.com -w wordlist_common.txt
```

With extension fuzzing and higher concurrency:
```bash
python dir_bruteforcer.py -u http://target.com -w wordlist_common.txt -e php,bak,env,zip -c 25
```

Export results:
```bash
python dir_bruteforcer.py -u http://target.com -w wordlist_common.txt -o results.json
python dir_bruteforcer.py -u http://target.com -w wordlist_common.txt -o results.csv
```

### Flags

| Flag | Description | Default |
|---|---|---|
| `-u`, `--url` | Target base URL (required) | — |
| `-w`, `--wordlist` | Path to wordlist file (required) | — |
| `-e`, `--extensions` | Comma-separated extensions to fuzz | none |
| `-c`, `--concurrency` | Max concurrent requests | 15 |
| `-t`, `--timeout` | Per-request timeout (seconds) | 6 |
| `-m`, `--method` | HTTP method: GET or HEAD | GET |
| `-o`, `--output` | Output file (`.json` or `.csv`) | none (terminal only) |

## Sample output

```
[*] Target: http://target.com
[*] Wordlist: wordlist_common.txt
[*] Extensions: ['php', 'bak', 'env']
[*] Concurrency: 15
[*] MITRE ATT&CK: T1595.003 (Reconnaissance)

[+] 200 http://target.com/admin (len=1204)
[+] 403 http://target.com/private (len=9) forbidden but exists
[+] 200 http://target.com/config.php.bak (len=48)
    [##############################] 159/159 (100.0%)
[*] Done in 4.31s — 3 findings out of 159 requests

[*] Results saved to results.json
```

## Testing it yourself (safely)

Never point this at a target you don't own or have written permission to test. For practice:

- **Local Flask target** — spin up a tiny Flask app with a couple of hidden routes and scan `http://127.0.0.1:5000`. This is how I validated the tool during development: I stood up routes for `/admin`, `/private` (403), and `/config.php.bak`, and confirmed the scanner found all three while correctly ignoring dozens of real 404s.
- **testphp.vulnweb.com** — a legally scrapeable practice site (Acunetix's intentionally vulnerable test app) if you want a live target instead of localhost.

## Design decisions worth calling out (interview talking points)

- **Async over threading** — `asyncio` + `aiohttp` gives high request concurrency with far less overhead than spinning up threads per request, and it's the same pattern used across the rest of this portfolio (e.g. the TCP port scanner), so the codebase stays consistent.
- **Soft-404 baseline comparison** — a naive brute-forcer treats every 200 as a hit. Real-world servers (especially ones running frameworks with catch-all routes) return 200 for *everything*, which would make results useless without this check.
- **Extension fuzzing as expansion, not a separate pass** — appending extensions to the same wordlist keeps one request loop and one progress bar instead of juggling multiple scan phases.
- **Deduplication** — if a wordlist already contains `config.php.bak` and extension fuzzing would also generate it from `config.php` + `.bak`, the tool dedupes before sending requests, so you don't scan the same path twice.
- **403 ≠ noise** — a forbidden response still confirms the path *exists*, which is valuable recon information, so it's flagged separately rather than dropped like a 404.

## Possible extensions (if you want to push this further)

- Recursive scanning: if a directory returns 200, re-scan inside it
- `robots.txt` parsing: auto-seed the wordlist with disallowed paths
- Response hashing instead of length-only comparison, for tighter soft-404 detection
- `rich`-based colored terminal output
