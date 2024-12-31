#!/usr/bin/env python3
"""
password.py - Password Strength Analysis
Offline credential strength evaluation using only stdlib.
"""

import math
import re
import hashlib
import os
from typing import Dict, Any, List


# common passwords for pattern matching (source: published breach lists)
COMMON_PASSWORDS = {
    '123456', 'password', '123456789', '12345678', '12345', '1234567',
    '1234567890', 'qwerty', 'abc123', 'million', 'myspace1',
    'password1', 'iloveyou', 'sunshine', 'princess', 'football',
    'charlie', 'shadow', 'master', 'dragon', 'monkey', 'letmein',
    'login', 'welcome', 'admin', 'passw0rd', 'hello', 'trustno1',
    'whatever', 'freedom', 'batman', 'baseball', 'soccer', 'hockey',
    'michael', 'jennifer', 'hunter', 'thomas', 'summer', 'winter',
    'ashley', 'jessica', 'mustang', 'access', 'flower', 'hottie',
    'loveme', 'cheese', 'matrix', 'starwars', 'buster', 'jordan',
    'pepper', 'ginger', 'ranger', 'tucker', 'maverick', 'cookie',
    'maggie', 'bailey', 'harley', 'sparky', 'yankees', 'joshua',
    'test', 'pass', 'secret', 'killer', 'george', 'computer',
    'internet', 'pokemon', 'corvette', 'diamond', 'silver', 'golfer',
    'orange', 'banana', 'hammer', 'falcon', 'knight', 'wizard',
    'junior', 'thunder', 'tigger', 'samantha', 'dakota', 'jackson',
    'angel', 'devil', 'nicole', 'purple', 'andrea', 'phoenix',
    'amanda', 'peanut', 'qwerty123', '111111', '000000', 'pussy',
}

# keyboard walk patterns
KEYBOARD_WALKS = [
    'qwerty', 'qwertz', 'asdf', 'zxcv', 'qazwsx', 'wsxedc',
    '1qaz', '2wsx', '3edc', 'rfvtgb', 'tgbyhn', 'yhnujm',
]

# common leet substitutions
LEET_MAP = {'@': 'a', '3': 'e', '1': 'i', '0': 'o', '$': 's', '5': 's', '7': 't'}


def analyze_strength(password: str) -> Dict[str, Any]:
    """
    Evaluate password strength across multiple dimensions.

    Args:
        password: Password to analyze.

    Returns:
        Dict with score (0-100), rating, and suggestions.
    """
    try:
        if not password:
            return {
                'status': 'success',
                'score': 0,
                'rating': 'very_weak',
                'suggestions': ['password cannot be empty']
            }

        length = len(password)
        has_upper = bool(re.search(r'[A-Z]', password))
        has_lower = bool(re.search(r'[a-z]', password))
        has_digits = bool(re.search(r'\d', password))
        has_special = bool(re.search(r'[^A-Za-z0-9]', password))

        # unique character ratio
        unique_ratio = len(set(password)) / length if length > 0 else 0

        # detect sequential characters (abc, 123, etc.)
        sequential = 0
        for i in range(len(password) - 2):
            a, b, c = ord(password[i]), ord(password[i + 1]), ord(password[i + 2])
            if b - a == 1 and c - b == 1:
                sequential += 1

        # detect repeated characters (aaa, 111, etc.)
        repeated = 0
        for i in range(len(password) - 2):
            if password[i] == password[i + 1] == password[i + 2]:
                repeated += 1

        # detect common patterns
        common_patterns = []
        lower_pw = password.lower()

        for walk in KEYBOARD_WALKS:
            if walk in lower_pw:
                common_patterns.append(f'keyboard walk: {walk}')

        if re.search(r'(19|20)\d{2}', password):
            common_patterns.append('year pattern detected')

        if re.search(r'\d{2}[/-]\d{2}[/-]\d{2,4}', password):
            common_patterns.append('date pattern detected')

        # scoring
        score = 0

        # length: up to 30 points
        score += min(length * 3, 30)

        # character diversity: up to 25 points
        diversity_count = sum([has_upper, has_lower, has_digits, has_special])
        score += diversity_count * 6.25

        # unique character ratio: up to 15 points
        score += unique_ratio * 15

        # penalties
        score -= sequential * 5
        score -= repeated * 5
        score -= len(common_patterns) * 10

        # bonus for length > 12
        if length > 12:
            score += min((length - 12) * 2, 10)

        score = max(0, min(100, round(score)))

        # rating
        if score >= 80:
            rating = 'very_strong'
        elif score >= 60:
            rating = 'strong'
        elif score >= 40:
            rating = 'fair'
        elif score >= 20:
            rating = 'weak'
        else:
            rating = 'very_weak'

        # suggestions
        suggestions = []
        if length < 8:
            suggestions.append('use at least 8 characters')
        if length < 12:
            suggestions.append('consider 12+ characters for better security')
        if not has_upper:
            suggestions.append('add uppercase letters')
        if not has_lower:
            suggestions.append('add lowercase letters')
        if not has_digits:
            suggestions.append('add numbers')
        if not has_special:
            suggestions.append('add special characters')
        if sequential > 0:
            suggestions.append('avoid sequential characters (abc, 123)')
        if repeated > 0:
            suggestions.append('avoid repeated characters (aaa, 111)')
        if common_patterns:
            suggestions.append('avoid common patterns')

        return {
            'status': 'success',
            'length': length,
            'has_uppercase': has_upper,
            'has_lowercase': has_lower,
            'has_digits': has_digits,
            'has_special': has_special,
            'char_diversity': diversity_count,
            'unique_ratio': round(unique_ratio, 2),
            'sequential_chars': sequential,
            'repeated_chars': repeated,
            'common_patterns': common_patterns,
            'score': score,
            'rating': rating,
            'suggestions': suggestions
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def estimate_crack_time(password: str) -> Dict[str, Any]:
    """
    Estimate brute-force crack time at various attack speeds.

    Args:
        password: Password to evaluate.

    Returns:
        Dict with entropy and time estimates for online/offline attacks.
    """
    try:
        if not password:
            return {
                'status': 'success',
                'entropy_bits': 0,
                'online_attack': 'instant',
                'offline_slow': 'instant',
                'offline_fast': 'instant'
            }

        # calculate character space
        charset_size = 0
        if re.search(r'[a-z]', password):
            charset_size += 26
        if re.search(r'[A-Z]', password):
            charset_size += 26
        if re.search(r'\d', password):
            charset_size += 10
        if re.search(r'[^A-Za-z0-9]', password):
            charset_size += 33

        charset_size = max(charset_size, 1)
        keyspace = charset_size ** len(password)
        entropy_bits = round(math.log2(keyspace), 2)

        # attack speeds (attempts per second)
        speeds = {
            'online_attack': 1_000,            # rate-limited online
            'offline_slow': 1_000_000,         # cpu-based
            'offline_fast': 10_000_000_000,    # gpu cluster
        }

        estimates = {}
        for attack, speed in speeds.items():
            seconds = keyspace / speed / 2  # average case
            estimates[attack] = _format_duration(seconds)

        return {
            'status': 'success',
            'charset_size': charset_size,
            'keyspace_size': f'{keyspace:.2e}',
            'entropy_bits': entropy_bits,
            **estimates
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def _format_duration(seconds: float) -> str:
    """convert seconds to human-readable duration."""
    if seconds < 1:
        return 'instant'
    if seconds < 60:
        return f'{seconds:.0f} seconds'
    if seconds < 3600:
        return f'{seconds / 60:.0f} minutes'
    if seconds < 86400:
        return f'{seconds / 3600:.0f} hours'
    if seconds < 86400 * 365:
        return f'{seconds / 86400:.0f} days'
    years = seconds / (86400 * 365)
    if years > 1e12:
        return f'{years:.2e} years'
    if years > 1e6:
        return f'{years / 1e6:.0f} million years'
    if years > 1000:
        return f'{years / 1000:.0f} thousand years'
    return f'{years:.0f} years'


def check_known_patterns(password: str) -> Dict[str, Any]:
    """
    Check password against common passwords and patterns.

    Args:
        password: Password to check.

    Returns:
        Dict with pattern matches and risk level.
    """
    try:
        patterns_found = []
        lower_pw = password.lower()

        # direct match
        if lower_pw in COMMON_PASSWORDS:
            patterns_found.append('exact match in common passwords')

        # leet substitution check
        normalized = lower_pw
        for leet, char in LEET_MAP.items():
            normalized = normalized.replace(leet, char)
        if normalized != lower_pw and normalized in COMMON_PASSWORDS:
            patterns_found.append('common password with leet substitutions')

        # keyboard walks
        for walk in KEYBOARD_WALKS:
            if walk in lower_pw:
                patterns_found.append(f'keyboard walk: {walk}')

        # date patterns
        if re.search(r'(19[5-9]\d|20[0-2]\d)', password):
            patterns_found.append('year pattern')

        if re.search(r'\d{2}[/-]\d{2}[/-]\d{2,4}', password):
            patterns_found.append('date format')

        # phone number pattern
        if re.search(r'\d{10,11}', password):
            patterns_found.append('possible phone number')

        # all same character
        if len(set(password)) == 1:
            patterns_found.append('single repeated character')

        # risk level
        if 'exact match in common passwords' in patterns_found:
            risk = 'critical'
        elif 'common password with leet substitutions' in patterns_found:
            risk = 'high'
        elif len(patterns_found) >= 2:
            risk = 'high'
        elif len(patterns_found) == 1:
            risk = 'medium'
        else:
            risk = 'none'

        return {
            'status': 'success',
            'is_common': len(patterns_found) > 0,
            'patterns_found': patterns_found,
            'risk_level': risk
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


# word list for passphrase generation
WORD_LIST = [
    'able', 'acid', 'aged', 'also', 'area', 'army', 'away', 'baby', 'back',
    'ball', 'band', 'bank', 'base', 'bath', 'bean', 'bear', 'beat', 'been',
    'beer', 'bell', 'belt', 'best', 'bill', 'bird', 'bite', 'blow', 'blue',
    'boat', 'body', 'bomb', 'bond', 'bone', 'book', 'boom', 'born', 'boss',
    'both', 'bowl', 'burn', 'bush', 'busy', 'cafe', 'cage', 'cake', 'calm',
    'came', 'camp', 'card', 'care', 'case', 'cash', 'cast', 'cave', 'chat',
    'chip', 'city', 'club', 'coal', 'coat', 'code', 'cold', 'come', 'cook',
    'cool', 'copy', 'core', 'cost', 'crew', 'crop', 'dark', 'data', 'date',
    'dawn', 'dead', 'deal', 'dear', 'debt', 'deep', 'desk', 'diet', 'dirt',
    'dish', 'disk', 'dock', 'does', 'done', 'door', 'dose', 'down', 'draw',
    'drew', 'drop', 'drug', 'drum', 'dual', 'dust', 'duty', 'each', 'earn',
    'ease', 'east', 'easy', 'edge', 'else', 'even', 'ever', 'evil', 'exam',
    'exit', 'face', 'fact', 'fail', 'fair', 'fall', 'fame', 'farm', 'fast',
    'fate', 'fear', 'feed', 'feel', 'feet', 'fell', 'felt', 'file', 'fill',
    'film', 'find', 'fine', 'fire', 'firm', 'fish', 'five', 'flat', 'flew',
    'flow', 'folk', 'food', 'foot', 'ford', 'form', 'fort', 'four', 'free',
    'from', 'fuel', 'full', 'fund', 'gain', 'game', 'gang', 'gate', 'gave',
    'gear', 'gene', 'gift', 'girl', 'give', 'glad', 'goal', 'goes', 'gold',
    'golf', 'gone', 'good', 'grab', 'gray', 'grew', 'grip', 'grow', 'gulf',
    'hair', 'half', 'hall', 'hand', 'hang', 'hard', 'harm', 'hate', 'have',
    'head', 'hear', 'heat', 'held', 'hell', 'help', 'here', 'hero', 'high',
    'hill', 'hire', 'hold', 'hole', 'holy', 'home', 'hope', 'host', 'hour',
    'huge', 'hung', 'hunt', 'hurt', 'idea', 'iron', 'item', 'jack', 'jail',
    'jane', 'jean', 'jobs', 'join', 'joke', 'jump', 'jury', 'just', 'keen',
    'keep', 'kent', 'kept', 'kick', 'kill', 'kind', 'king', 'knee', 'knew',
    'knot', 'know', 'lack', 'lady', 'laid', 'lake', 'lamp', 'land', 'lane',
    'last', 'late', 'lead', 'left', 'lend', 'less', 'life', 'lift', 'like',
    'lime', 'line', 'link', 'lion', 'list', 'live', 'load', 'loan', 'lock',
    'lone', 'long', 'look', 'lord', 'lose', 'loss', 'lost', 'love', 'luck',
]


def generate_passphrase(word_count: int = 4, separator: str = '-') -> Dict[str, Any]:
    """
    Generate a cryptographically secure random passphrase.

    Args:
        word_count: Number of words (default 4).
        separator: Word separator character.

    Returns:
        Dict with passphrase and entropy estimate.
    """
    try:
        words = []
        for _ in range(word_count):
            # cryptographically secure random index
            index = int.from_bytes(os.urandom(4), 'big') % len(WORD_LIST)
            words.append(WORD_LIST[index])

        passphrase = separator.join(words)
        entropy_bits = round(math.log2(len(WORD_LIST) ** word_count), 2)

        # estimate crack time at gpu speed
        keyspace = len(WORD_LIST) ** word_count
        crack_seconds = keyspace / 10_000_000_000 / 2
        crack_time = _format_duration(crack_seconds)

        return {
            'status': 'success',
            'passphrase': passphrase,
            'word_count': word_count,
            'entropy_bits': entropy_bits,
            'estimated_crack_time': crack_time
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


def hash_check(password: str, known_hash: str, algorithm: str = 'sha256') -> Dict[str, Any]:
    """
    Check if a password matches a known hash.

    Args:
        password: Password to hash and compare.
        known_hash: Hash value to compare against.
        algorithm: Hash algorithm (md5, sha1, sha256, sha512).

    Returns:
        Dict with match result and computed hash.
    """
    try:
        valid_algorithms = ['md5', 'sha1', 'sha256', 'sha512']
        if algorithm not in valid_algorithms:
            return {
                'status': 'error',
                'error': f'Unsupported algorithm. Use: {", ".join(valid_algorithms)}'
            }

        h = hashlib.new(algorithm)
        h.update(password.encode('utf-8'))
        computed = h.hexdigest()

        return {
            'status': 'success',
            'algorithm': algorithm,
            'matches': computed == known_hash.lower(),
            'hash_value': computed
        }
    except Exception as e:
        return {
            'status': 'error',
            'error': str(e)
        }


if __name__ == '__main__':
    print("Password Strength Analysis Tests:")
    print("-" * 40)

    test_passwords = ['password', 'P@ssw0rd!', 'correct-horse-battery-staple', '123456']
    for pw in test_passwords:
        result = analyze_strength(pw)
        crack = estimate_crack_time(pw)
        print(f"  '{pw}': score={result.get('score')}, rating={result.get('rating')}")
        print(f"    crack time (gpu): {crack.get('offline_fast')}")

    print("\nPassphrase generation:")
    result = generate_passphrase()
    print(f"  {result.get('passphrase')} (entropy: {result.get('entropy_bits')} bits)")
