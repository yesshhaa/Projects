"""
wordlist.py
Generates a targeted wordlist from personal/OSINT-style inputs,
plus mutations (leetspeak, case, years, symbols), merged with a
common password seed list.
"""

import os

LEET_MAP = {
    "a": "@",
    "o": "0",
    "s": "$",
    "i": "1",
    "e": "3",
}

COMMON_SUFFIXES = ["", "!", "123", "1", "2024", "2025", "2026", "#", "@"]

YEARS = [str(y) for y in range(2015, 2027)]


def leetspeak(word: str) -> str:
    """Return a leetspeak version of the word."""
    result = ""
    for char in word.lower():
        result += LEET_MAP.get(char, char)
    return result


def case_variations(word: str) -> list:
    """Return a few common case variants."""
    return list({
        word.lower(),
        word.upper(),
        word.capitalize(),
    })


def mutate(word: str) -> set:
    """Apply leetspeak, case, and suffix mutations to a single word."""
    variants = set()
    base_forms = set(case_variations(word))
    base_forms.add(leetspeak(word))

    for form in base_forms:
        for suffix in COMMON_SUFFIXES:
            variants.add(f"{form}{suffix}")
        for year in YEARS:
            variants.add(f"{form}{year}")

    return variants


def load_common_passwords(path: str) -> list:
    """Load a seed list of common passwords from file."""
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip()]


def generate_wordlist(inputs: list, common_list_path: str = None) -> list:
    """
    inputs: list of personal strings (name, pet, birth year, company, etc.)
    common_list_path: optional path to a seed common-password file
    Returns a deduped list of candidate passwords.
    """
    all_words = set()

    for word in inputs:
        all_words.update(mutate(word))

    if common_list_path:
        all_words.update(load_common_passwords(common_list_path))

    return sorted(all_words)


def save_wordlist(words: list, output_path: str) -> None:
    """Write the wordlist to a file, one entry per line."""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        for word in words:
            f.write(word + "\n")
