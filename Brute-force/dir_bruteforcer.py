#!/usr/bin/env python3
"""
Async Directory Brute-Forcer
-----------------------------
Discovers hidden directories, files, and backup artifacts on a web server
by requesting paths from a wordlist and analyzing the responses.

MITRE ATT&CK Mapping: T1595.003 (Active Scanning: Wordlist Scanning)

Author: Yesha
Usage:
    python dir_bruteforcer.py -u http://target.com -w wordlist_common.txt
    python dir_bruteforcer.py -u http://target.com -w wordlist_common.txt -e php,bak,env -c 20 -o results.json
"""

import argparse
import asyncio
import csv
import json
import sys
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urljoin

import aiohttp

MITRE_TECHNIQUE = "T1595.003"
MITRE_TACTIC = "Reconnaissance"

# Status codes we care about. 404 is noise; everything else is signal.
INTERESTING_CODES = {200, 201, 204, 301, 302, 307, 308, 401, 403, 405}


@dataclass
class Finding:
    url: str
    status: int
    length: int
    redirect_to: str | None = None
    note: str = ""


@dataclass
class ScanResult:
    target: str
    started_at: str
    finished_at: str = ""
    total_requests: int = 0
    findings: list[Finding] = field(default_factory=list)
    mitre_technique: str = MITRE_TECHNIQUE
    mitre_tactic: str = MITRE_TACTIC


class DirBruteForcer:
    def __init__(
        self,
        target: str,
        wordlist_path: str,
        extensions: list[str] | None = None,
        concurrency: int = 15,
        timeout: float = 6.0,
        method: str = "GET",
        user_agent: str = "dir-bruteforcer/1.0",
    ):
        self.target = target.rstrip("/") + "/"
        self.wordlist_path = wordlist_path
        self.extensions = extensions or []
        self.concurrency = concurrency
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.method = method
        self.headers = {"User-Agent": user_agent}
        self.semaphore = asyncio.Semaphore(concurrency)
        self.baseline_length: int | None = None
        self.baseline_status: int | None = None

    def _load_words(self) -> list[str]:
        with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip() and not line.startswith("#")]

        # Expand wordlist with extension variants: admin -> admin.php, admin.bak, etc.
        # dict.fromkeys preserves order while dropping duplicates (e.g. a wordlist
        # that already contains "config.php.bak" plus fuzzed "config.php" + ".bak").
        expanded = []
        for w in words:
            expanded.append(w)
            for ext in self.extensions:
                expanded.append(f"{w}.{ext.lstrip('.')}")
        return list(dict.fromkeys(expanded))

    async def _establish_baseline(self, session: aiohttp.ClientSession):
        """
        Requests a random, near-certainly-nonexistent path to see how the
        server responds to a real 404. Some servers return HTTP 200 for
        everything ('soft 404'), which would otherwise flood results with
        false positives.
        """
        probe_path = "this-path-should-not-exist-8x7z2q1"
        url = urljoin(self.target, probe_path)
        try:
            async with session.request(self.method, url, headers=self.headers, allow_redirects=False) as resp:
                body = await resp.read()
                self.baseline_status = resp.status
                self.baseline_length = len(body)
        except aiohttp.ClientError:
            self.baseline_status = None
            self.baseline_length = None

    def _is_soft_404(self, status: int, length: int) -> bool:
        if self.baseline_status is None:
            return False
        # Same status AND very similar body length as the known-fake path = soft 404
        return status == self.baseline_status and abs(length - (self.baseline_length or 0)) < 15

    async def _check_path(self, session: aiohttp.ClientSession, word: str) -> Finding | None:
        url = urljoin(self.target, word.lstrip("/"))
        async with self.semaphore:
            try:
                async with session.request(
                    self.method, url, headers=self.headers, allow_redirects=False
                ) as resp:
                    body = await resp.read()
                    length = len(body)

                    if resp.status not in INTERESTING_CODES:
                        return None
                    if self._is_soft_404(resp.status, length):
                        return None

                    redirect_to = resp.headers.get("Location") if resp.status in (301, 302, 307, 308) else None
                    note = "forbidden but exists" if resp.status == 403 else ""

                    return Finding(url=url, status=resp.status, length=length, redirect_to=redirect_to, note=note)
            except asyncio.TimeoutError:
                return None
            except aiohttp.ClientError:
                return None

    async def run(self) -> ScanResult:
        words = self._load_words()
        started_at = datetime.now(timezone.utc).isoformat()

        connector = aiohttp.TCPConnector(limit=self.concurrency, ssl=False)
        async with aiohttp.ClientSession(connector=connector, timeout=self.timeout) as session:
            await self._establish_baseline(session)

            tasks = [self._check_path(session, word) for word in words]
            results = []
            completed = 0
            total = len(tasks)

            for coro in asyncio.as_completed(tasks):
                res = await coro
                completed += 1
                if res:
                    results.append(res)
                    # Clear progress bar before printing findings to avoid trailing character pollution
                    sys.stdout.write("\r" + " " * 60 + "\r")
                    print(f"[+] {res.status} {res.url} (len={res.length}) {res.note}")
                self._print_progress(completed, total)

        print()  # newline after progress bar
        return ScanResult(
            target=self.target,
            started_at=started_at,
            finished_at=datetime.now(timezone.utc).isoformat(),
            total_requests=total,
            findings=sorted(results, key=lambda f: f.status),
        )

    @staticmethod
    def _print_progress(done: int, total: int):
        pct = (done / total) * 100 if total else 100
        bar_len = 30
        filled = int(bar_len * done // total) if total else bar_len
        bar = "#" * filled + "-" * (bar_len - filled)
        sys.stdout.write(f"\r    [{bar}] {done}/{total} ({pct:.1f}%)")
        sys.stdout.flush()


def export_json(result: ScanResult, path: str):
    payload = {
        "target": result.target,
        "started_at": result.started_at,
        "finished_at": result.finished_at,
        "total_requests": result.total_requests,
        "mitre_technique": result.mitre_technique,
        "mitre_tactic": result.mitre_tactic,
        "findings_count": len(result.findings),
        "findings": [
            {
                "url": f.url,
                "status": f.status,
                "length": f.length,
                "redirect_to": f.redirect_to,
                "note": f.note,
            }
            for f in result.findings
        ],
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)


def export_csv(result: ScanResult, path: str):
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "status", "length", "redirect_to", "note"])
        for finding in result.findings:
            writer.writerow([finding.url, finding.status, finding.length, finding.redirect_to or "", finding.note])


def parse_args():
    parser = argparse.ArgumentParser(description="Async directory/file brute-forcer for web recon.")
    parser.add_argument("-u", "--url", required=True, help="Target base URL, e.g. http://target.com")
    parser.add_argument("-w", "--wordlist", required=True, help="Path to wordlist file")
    parser.add_argument("-e", "--extensions", default="", help="Comma-separated extensions to fuzz, e.g. php,bak,env")
    parser.add_argument("-c", "--concurrency", type=int, default=15, help="Max concurrent requests (default: 15)")
    parser.add_argument("-t", "--timeout", type=float, default=6.0, help="Per-request timeout in seconds (default: 6)")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "HEAD"], help="HTTP method (default: GET)")
    parser.add_argument("-o", "--output", help="Output file path (.json or .csv)")
    return parser.parse_args()


async def main():
    args = parse_args()
    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]

    print(f"[*] Target: {args.url}")
    print(f"[*] Wordlist: {args.wordlist}")
    print(f"[*] Extensions: {extensions if extensions else 'none'}")
    print(f"[*] Concurrency: {args.concurrency}")
    print(f"[*] MITRE ATT&CK: {MITRE_TECHNIQUE} ({MITRE_TACTIC})\n")

    scanner = DirBruteForcer(
        target=args.url,
        wordlist_path=args.wordlist,
        extensions=extensions,
        concurrency=args.concurrency,
        timeout=args.timeout,
        method=args.method,
    )

    start = time.time()
    result = await scanner.run()
    elapsed = time.time() - start

    print(f"[*] Done in {elapsed:.2f}s — {len(result.findings)} findings out of {result.total_requests} requests\n")

    if args.output:
        if args.output.endswith(".csv"):
            export_csv(result, args.output)
        else:
            export_json(result, args.output)
        print(f"[*] Results saved to {args.output}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user")
        sys.exit(1)
