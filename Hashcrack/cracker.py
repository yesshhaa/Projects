"""
cracker.py
Identifies hash type by length, then attempts to crack it via
dictionary attack, falling back to a capped brute-force attack
for short passwords.
"""

import hashlib
import itertools
import time

HASH_LENGTHS = {
    32: "md5",
    40: "sha1",
    64: "sha256",
}

DEFAULT_BRUTE_CHARSET = "abcdefghijklmnopqrstuvwxyz0123456789"
DEFAULT_BRUTE_MAX_LEN = 5          # keep this small, brute force grows fast
DEFAULT_BRUTE_TIME_CAP = 30        # seconds, safety valve


def identify_hash_type(hash_str: str) -> str:
    """Guess hash algorithm from hex length. Returns 'unknown' if no match."""
    length = len(hash_str.strip())
    return HASH_LENGTHS.get(length, "unknown")


def hash_word(word: str, algo: str) -> str:
    """Hash a single word with the given algorithm."""
    h = hashlib.new(algo)
    h.update(word.encode("utf-8"))
    return h.hexdigest()


def dictionary_attack(target_hash: str, algo: str, wordlist: list) -> dict:
    """
    Try every word in wordlist against the target hash.
    Returns a result dict with match info and stats.
    """
    target_hash = target_hash.strip().lower()
    start = time.time()
    attempts = 0

    for word in wordlist:
        attempts += 1
        if hash_word(word, algo) == target_hash:
            elapsed = time.time() - start
            return {
                "found": True,
                "password": word,
                "method": "dictionary",
                "attempts": attempts,
                "elapsed": elapsed,
            }

    elapsed = time.time() - start
    return {
        "found": False,
        "password": None,
        "method": "dictionary",
        "attempts": attempts,
        "elapsed": elapsed,
    }


def brute_force_attack(
    target_hash: str,
    algo: str,
    charset: str = DEFAULT_BRUTE_CHARSET,
    max_len: int = DEFAULT_BRUTE_MAX_LEN,
    time_cap: int = DEFAULT_BRUTE_TIME_CAP,
) -> dict:
    """
    Try all combinations up to max_len characters.
    Stops early if time_cap (seconds) is exceeded, so it never hangs forever.
    """
    target_hash = target_hash.strip().lower()
    start = time.time()
    attempts = 0

    for length in range(1, max_len + 1):
        for combo in itertools.product(charset, repeat=length):
            attempts += 1
            candidate = "".join(combo)

            if hash_word(candidate, algo) == target_hash:
                elapsed = time.time() - start
                return {
                    "found": True,
                    "password": candidate,
                    "method": "brute_force",
                    "attempts": attempts,
                    "elapsed": elapsed,
                }

            if time.time() - start > time_cap:
                elapsed = time.time() - start
                return {
                    "found": False,
                    "password": None,
                    "method": "brute_force (time cap reached)",
                    "attempts": attempts,
                    "elapsed": elapsed,
                }

    elapsed = time.time() - start
    return {
        "found": False,
        "password": None,
        "method": "brute_force",
        "attempts": attempts,
        "elapsed": elapsed,
    }


def crack_hash(target_hash: str, algo: str, wordlist: list, try_brute_force: bool = True) -> dict:
    """
    Runs dictionary attack first, then optionally falls back to
    brute force if nothing was found.
    """
    result = dictionary_attack(target_hash, algo, wordlist)

    if not result["found"] and try_brute_force:
        brute_result = brute_force_attack(target_hash, algo)
        # combine attempt counts/time for an honest total, but keep the
        # method label from whichever attack actually succeeded (or the last one tried)
        brute_result["attempts"] += result["attempts"]
        brute_result["elapsed"] += result["elapsed"]
        return brute_result

    return result
