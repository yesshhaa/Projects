"""
main.py
HashCrack CLI - generate a targeted wordlist and use it (plus optional
brute force) to attempt to crack a given hash.

Usage examples:
    python main.py --hash 5f4dcc3b5aa765d61d8327deb882cf99
    python main.py --hash <hash> --inputs john fluffy acme 1990
    python main.py --hash <hash> --wordlist output/generated_wordlist.txt
    python main.py --hash <hash> --no-brute-force
"""

import argparse
import os

from wordlist import generate_wordlist, save_wordlist, load_common_passwords
from cracker import identify_hash_type, crack_hash

COMMON_PASSWORDS_PATH = os.path.join("data", "common_passwords.txt")
DEFAULT_WORDLIST_OUTPUT = os.path.join("output", "generated_wordlist.txt")


def build_wordlist(inputs: list) -> list:
    """Generate a wordlist from OSINT inputs + common password seed list."""
    words = generate_wordlist(inputs, common_list_path=COMMON_PASSWORDS_PATH)
    save_wordlist(words, DEFAULT_WORDLIST_OUTPUT)
    print(f"[+] Generated {len(words)} candidate passwords -> {DEFAULT_WORDLIST_OUTPUT}")
    return words


def main():
    parser = argparse.ArgumentParser(
        description="HashCrack: OSINT-based wordlist generator + hash cracker"
    )
    parser.add_argument("--hash", required=True, help="Target hash to crack")
    parser.add_argument(
        "--algo",
        help="Force a hash algorithm (md5, sha1, sha256). Auto-detected if omitted.",
    )
    parser.add_argument(
        "--inputs",
        nargs="*",
        default=[],
        help="Personal/OSINT words to build a targeted wordlist from (name, pet, etc.)",
    )
    parser.add_argument(
        "--wordlist",
        help="Path to an existing wordlist file. If omitted, one is generated.",
    )
    parser.add_argument(
        "--no-brute-force",
        action="store_true",
        help="Skip brute-force fallback if dictionary attack fails",
    )

    args = parser.parse_args()

    # Step 1: figure out the algorithm
    algo = args.algo or identify_hash_type(args.hash)
    if algo == "unknown":
        print("[!] Could not auto-detect hash type from length. Use --algo to specify.")
        return
    print(f"[+] Hash type: {algo}")

    # Step 2: get the wordlist
    if args.wordlist:
        with open(args.wordlist, "r", encoding="utf-8", errors="ignore") as f:
            words = [line.strip() for line in f if line.strip()]
        print(f"[+] Loaded {len(words)} words from {args.wordlist}")
    elif args.inputs:
        words = build_wordlist(args.inputs)
    else:
        print("[+] No inputs or wordlist given, using common password list only.")
        words = load_common_passwords(COMMON_PASSWORDS_PATH)

    # Step 3: crack
    print("[+] Starting attack...")
    result = crack_hash(
        args.hash, algo, words, try_brute_force=not args.no_brute_force
    )

    # Step 4: report
    print("\n----- RESULT -----")
    if result["found"]:
        print(f"Password found: {result['password']}")
    else:
        print("Password NOT found.")
    print(f"Method:   {result['method']}")
    print(f"Attempts: {result['attempts']}")
    print(f"Time:     {result['elapsed']:.4f} sec")
    if result["elapsed"] > 0:
        rate = result["attempts"] / result["elapsed"]
        print(f"Rate:     {rate:,.0f} attempts/sec")


if __name__ == "__main__":
    main()
